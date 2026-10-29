use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use axum::extract::ws::WebSocket;

use crate::core::state::AppState;

#[derive(Clone)]
pub struct BackendInfo {
    pub name: &'static str,
    pub protocol: &'static str,
    pub limitations: &'static str,
}

#[async_trait]
pub trait ProtocolBackend: Send + Sync + 'static {
    fn info(&self) -> BackendInfo;
    async fn serve(&self, socket: WebSocket, peer: SocketAddr, state: Arc<AppState>);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBackend;
    #[async_trait]
    impl ProtocolBackend for MockBackend {
        fn info(&self) -> BackendInfo {
            BackendInfo {
                name: "mock",
                protocol: "test",
                limitations: "none",
            }
        }
        async fn serve(&self, _socket: WebSocket, _peer: SocketAddr, _state: Arc<AppState>) {}
    }

    #[test]
    fn backend_is_replaceable_without_concrete_protocol_types() {
        let backend: Arc<dyn ProtocolBackend> = Arc::new(MockBackend);
        assert_eq!(backend.info().name, "mock");
    }
}
