use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    pin::Pin,
    sync::atomic::Ordering,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordVerifier},
};
use async_trait::async_trait;
use axum::extract::ws::{Message, WebSocket};
use bytes::{Buf, Bytes, BytesMut};
use futures_util::{
    Sink, Stream, StreamExt,
    stream::{SplitSink, SplitStream},
};
use tokio::sync::Semaphore;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use wisp_mux::{
    ServerMux, WispError, WispV2Handshake,
    extensions::{
        AnyProtocolExtension, AnyProtocolExtensionBuilder, ProtocolExtension,
        ProtocolExtensionBuilder,
    },
    packet::{CloseReason, StreamType},
};

use crate::{
    core::state::AppState,
    protocol::{BackendInfo, ProtocolBackend},
    proxy,
};

const PASSWORD_EXTENSION_ID: u8 = 0x02;

pub struct WispMuxBackend;

#[async_trait]
impl ProtocolBackend for WispMuxBackend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            name: "wisp-mux 6.0.0 (pinned 9cde724)",
            protocol: "Wisp v2.0",
            limitations: "TCP only; v2.1 stream-open confirmation (0x05) is not implemented",
        }
    }

    async fn serve(&self, socket: WebSocket, peer: SocketAddr, state: Arc<AppState>) {
        if let Err(error) = serve_socket(socket, peer, Arc::clone(&state)).await {
            state
                .record_error(format!("Wisp session from {peer} ended: {error}"))
                .await;
            tracing::debug!(%peer, error = %error, "Wisp session ended");
        }
    }
}

async fn serve_socket(
    socket: WebSocket,
    peer: SocketAddr,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    let _client_slot = state
        .client_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow::anyhow!("client limit reached"))?;
    let config = state.config.read().await.clone();
    let hashes = state.wisp_users.enabled_password_hashes().await;
    let authenticated_user = Arc::new(Mutex::new(None));
    let builder = PasswordBuilder {
        hashes,
        authenticated_user: Arc::clone(&authenticated_user),
    };

    let (write, read) = socket.split();
    let read = AxumWsRead(read);
    let write = AxumWsWrite(write);

    let result = ServerMux::new(
        read,
        write,
        config.limits.stream_buffer_messages,
        Some(WispV2Handshake::new(vec![
            AnyProtocolExtensionBuilder::new(builder),
        ])),
    )
    .await?;
    let (mux, actor) = result
        .with_required_extensions(&[PASSWORD_EXTENSION_ID])
        .await?;
    if mux.was_downgraded() {
        let _ = mux
            .close_with_reason(CloseReason::ExtensionsAuthRequired)
            .await;
        anyhow::bail!("Wisp v1 downgrade rejected because authentication is required");
    }
    let user = authenticated_user
        .lock()
        .map_err(|_| anyhow::anyhow!("authentication state poisoned"))?
        .clone()
        .ok_or_else(|| anyhow::anyhow!("authenticated username missing"))?;
    let mux = Arc::new(mux);
    let actor_task = tokio::spawn(actor);
    let (guard, cancel) = state
        .sessions
        .register(user.clone(), peer.to_string())
        .await;
    state.metrics.total_sessions.fetch_add(1, Ordering::Relaxed);
    let stream_slots = Arc::new(Semaphore::new(config.limits.streams_per_client));

    loop {
        tokio::select! {
            () = cancel.cancelled() => { let _ = mux.close_with_reason(CloseReason::Voluntary).await; break; }
            request = mux.wait_for_stream() => {
                let Some((connect, stream)) = request else { break; };
                if connect.stream_type != StreamType::Tcp {
                    state.metrics.rejected_streams.fetch_add(1, Ordering::Relaxed);
                    let _ = stream.close(CloseReason::ServerStreamInvalidInfo).await;
                    continue;
                }
                let Ok(stream_slot) = stream_slots.clone().try_acquire_owned() else {
                    state.metrics.rejected_streams.fetch_add(1, Ordering::Relaxed);
                    let _ = stream.close(CloseReason::ServerStreamThrottled).await;
                    continue;
                };
                let Ok(dial_slot) = state.dial_slots.clone().try_acquire_owned() else {
                    state.metrics.rejected_streams.fetch_add(1, Ordering::Relaxed);
                    let _ = stream.close(CloseReason::ServerStreamThrottled).await;
                    continue;
                };
                state.metrics.total_streams.fetch_add(1, Ordering::Relaxed);
                state.sessions.stream_opened(guard.id()).await;
                let session_id = guard.id().to_owned();
                let state = Arc::clone(&state);
                let host = connect.host;
                let port = connect.port;
                tokio::spawn(async move {
                    let config = state.config.read().await.clone();
                    let close = stream.get_close_handle();
                    let io = stream.into_async_rw().compat();
                    let remote = proxy::dns::connect_validated(&config, &host, port).await;
                    drop(dial_slot);
                    let result = match remote {
                        Ok(remote) => proxy::tcp::forward(io, remote, &config, Arc::clone(&state.metrics)).await,
                        Err(error) => Err(anyhow::Error::new(error)),
                    };
                    drop(stream_slot);
                    state.sessions.stream_closed(&session_id).await;
                    if let Err(error) = result {
                        state.record_error(format!("TCP stream to {host}:{port} failed: {error}")).await;
                        let reason = if error.downcast_ref::<proxy::dns::ConnectError>().is_some_and(|error| matches!(error, proxy::dns::ConnectError::Blocked(_))) {
                            CloseReason::ServerStreamBlockedAddress
                        } else {
                            CloseReason::ServerStreamUnreachable
                        };
                        let _ = close.close(reason).await;
                    } else {
                        let _ = close.close(CloseReason::Voluntary).await;
                    }
                });
            }
        }
    }
    actor_task.abort();
    drop(guard);
    Ok(())
}

struct PasswordBuilder {
    hashes: HashMap<String, String>,
    authenticated_user: Arc<Mutex<Option<String>>>,
}

struct AxumWsRead(SplitStream<WebSocket>);
struct AxumWsWrite(SplitSink<WebSocket, Message>);

impl Stream for AxumWsRead {
    type Item = Result<Bytes, WispError>;
    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match Pin::new(&mut self.0).poll_next(context) {
                Poll::Ready(Some(Ok(Message::Binary(bytes)))) => {
                    return Poll::Ready(Some(Ok(bytes)));
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Some(Err(WispError::WsImplError(Box::new(error)))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Sink<Bytes> for AxumWsWrite {
    type Error = WispError;
    fn poll_ready(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_ready(context).map_err(ws_error)
    }
    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        Pin::new(&mut self.0)
            .start_send(Message::Binary(item))
            .map_err(ws_error)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_flush(context).map_err(ws_error)
    }
    fn poll_close(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_close(context).map_err(ws_error)
    }
}

fn ws_error(error: axum::Error) -> WispError {
    WispError::WsImplError(Box::new(error))
}

impl ProtocolExtensionBuilder for PasswordBuilder {
    fn get_id(&self) -> u8 {
        PASSWORD_EXTENSION_ID
    }

    fn build_from_bytes(
        &mut self,
        mut bytes: Bytes,
        _role: wisp_mux::Role,
    ) -> Result<AnyProtocolExtension, WispError> {
        if bytes.remaining() < 1 {
            return Err(WispError::PacketTooSmall);
        }
        let username_length = bytes.get_u8() as usize;
        if bytes.remaining() < username_length {
            return Err(WispError::PacketTooSmall);
        }
        let username = std::str::from_utf8(&bytes[..username_length])?.to_owned();
        bytes.advance(username_length);
        let password = std::str::from_utf8(&bytes)?;
        let valid = self
            .hashes
            .get(&username)
            .and_then(|encoded| PasswordHash::new(encoded).ok())
            .is_some_and(|hash| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &hash)
                    .is_ok()
            });
        if !valid {
            return Err(WispError::PasswordExtensionCredsInvalid);
        }
        *self
            .authenticated_user
            .lock()
            .map_err(|_| WispError::ExtensionImplNotSupported)? = Some(username);
        Ok(PasswordExtension.into())
    }

    fn build_to_extension(
        &mut self,
        _role: wisp_mux::Role,
    ) -> Result<AnyProtocolExtension, WispError> {
        Ok(PasswordExtension.into())
    }
}

#[derive(Clone)]
struct PasswordExtension;

impl fmt::Debug for PasswordExtension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordExtension")
    }
}

#[async_trait]
impl ProtocolExtension for PasswordExtension {
    fn get_id(&self) -> u8 {
        PASSWORD_EXTENSION_ID
    }
    fn encode(&self) -> Bytes {
        BytesMut::from(&[1_u8][..]).freeze()
    }
    fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::{PasswordHasher, SaltString};
    use tokio::sync::mpsc;
    use wisp_mux::{ClientMux, extensions::password::PasswordProtocolExtensionBuilder};

    struct MemoryRead(mpsc::UnboundedReceiver<Bytes>);
    struct MemoryWrite(Option<mpsc::UnboundedSender<Bytes>>);

    impl Stream for MemoryRead {
        type Item = Result<Bytes, WispError>;
        fn poll_next(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Pin::new(&mut self.0)
                .poll_recv(context)
                .map(|item| item.map(Ok))
        }
    }

    impl Sink<Bytes> for MemoryWrite {
        type Error = WispError;
        fn poll_ready(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.get_mut()
                .0
                .as_ref()
                .ok_or(WispError::WsImplSocketClosed)?
                .send(item)
                .map_err(|_| WispError::WsImplSocketClosed)
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.get_mut().0.take();
            Poll::Ready(Ok(()))
        }
    }

    fn transport_pair() -> ((MemoryRead, MemoryWrite), (MemoryRead, MemoryWrite)) {
        let (client_to_server_tx, client_to_server_rx) = mpsc::unbounded_channel();
        let (server_to_client_tx, server_to_client_rx) = mpsc::unbounded_channel();
        (
            (
                MemoryRead(client_to_server_rx),
                MemoryWrite(Some(server_to_client_tx)),
            ),
            (
                MemoryRead(server_to_client_rx),
                MemoryWrite(Some(client_to_server_tx)),
            ),
        )
    }

    fn builder(password: &str) -> PasswordBuilder {
        let salt = SaltString::encode_b64(&[7_u8; 16]).unwrap();
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();
        PasswordBuilder {
            hashes: HashMap::from([("alice".into(), hash)]),
            authenticated_user: Arc::new(Mutex::new(None)),
        }
    }

    #[test]
    fn password_extension_accepts_valid_argon2_credential() {
        let mut builder = builder("correct horse battery");
        let mut metadata = vec![5];
        metadata.extend_from_slice(b"alicecorrect horse battery");
        builder
            .build_from_bytes(Bytes::from(metadata), wisp_mux::Role::Server)
            .unwrap();
        assert_eq!(
            builder.authenticated_user.lock().unwrap().as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn password_extension_rejects_invalid_and_truncated_metadata() {
        let mut builder = builder("correct horse battery");
        let invalid = builder.build_from_bytes(
            Bytes::from_static(b"\x05alicewrong"),
            wisp_mux::Role::Server,
        );
        assert!(matches!(
            invalid,
            Err(WispError::PasswordExtensionCredsInvalid)
        ));
        let truncated =
            builder.build_from_bytes(Bytes::from_static(b"\x08tiny"), wisp_mux::Role::Server);
        assert!(matches!(truncated, Err(WispError::PacketTooSmall)));
    }

    #[tokio::test]
    async fn pinned_client_completes_authenticated_v2_handshake() {
        let ((server_read, server_write), (client_read, client_write)) = transport_pair();
        let authenticated_user = Arc::new(Mutex::new(None));
        let mut server_builder = builder("correct horse battery");
        server_builder.authenticated_user = Arc::clone(&authenticated_user);
        let server = async move {
            let result = ServerMux::new(
                server_read,
                server_write,
                8,
                Some(WispV2Handshake::new(vec![
                    AnyProtocolExtensionBuilder::new(server_builder),
                ])),
            )
            .await?;
            result
                .with_required_extensions(&[PASSWORD_EXTENSION_ID])
                .await
        };
        let client = async move {
            let handshake = WispV2Handshake::new(vec![AnyProtocolExtensionBuilder::new(
                PasswordProtocolExtensionBuilder::new_client(Some((
                    "alice".into(),
                    "correct horse battery".into(),
                ))),
            )]);
            let result = ClientMux::new(client_read, client_write, Some(handshake)).await?;
            result
                .with_required_extensions(&[PASSWORD_EXTENSION_ID])
                .await
        };
        let (server_result, client_result) = tokio::join!(server, client);
        let (server_mux, server_actor) = server_result.unwrap();
        let (client_mux, client_actor) = client_result.unwrap();
        assert!(!server_mux.was_downgraded());
        assert!(!client_mux.was_downgraded());
        assert_eq!(authenticated_user.lock().unwrap().as_deref(), Some("alice"));
        drop(server_actor);
        drop(client_actor);
    }

    #[tokio::test]
    async fn pinned_client_rejects_incorrect_password() {
        let ((server_read, server_write), (client_read, client_write)) = transport_pair();
        let server = async move {
            ServerMux::new(
                server_read,
                server_write,
                8,
                Some(WispV2Handshake::new(vec![
                    AnyProtocolExtensionBuilder::new(builder("correct horse battery")),
                ])),
            )
            .await
        };
        let client = async move {
            ClientMux::new(
                client_read,
                client_write,
                Some(WispV2Handshake::new(vec![
                    AnyProtocolExtensionBuilder::new(PasswordProtocolExtensionBuilder::new_client(
                        Some(("alice".into(), "incorrect password".into())),
                    )),
                ])),
            )
            .await
        };
        let (server_result, client_result) = tokio::join!(
            server,
            tokio::time::timeout(std::time::Duration::from_secs(2), client)
        );
        assert!(server_result.is_err());
        assert!(client_result.is_err() || client_result.is_ok_and(|result| result.is_err()));
    }
}
