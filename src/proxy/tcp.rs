use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use tokio::net::TcpStream;

use crate::{config::Config, core::metrics::Metrics};

pub async fn forward<S>(
    stream: S,
    mut remote: TcpStream,
    config: &Config,
    metrics: Arc<Metrics>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(stream);
    let (mut remote_read, mut remote_write) = remote.split();
    let idle = Duration::from_secs(config.timeouts.idle_seconds);
    let mut client_open = true;
    let mut remote_open = true;
    let mut upstream = [0_u8; 16_384];
    let mut downstream = [0_u8; 16_384];

    while client_open || remote_open {
        tokio::select! {
            result = client_read.read(&mut upstream), if client_open => {
                let count = result?;
                if count == 0 {
                    client_open = false;
                    remote_write.shutdown().await?;
                } else {
                    tokio::time::timeout(idle, remote_write.write_all(&upstream[..count])).await.context("stream idle timeout")??;
                    metrics.bytes_upstream.fetch_add(count as u64, Ordering::Relaxed);
                }
            }
            result = remote_read.read(&mut downstream), if remote_open => {
                let count = result?;
                if count == 0 {
                    remote_open = false;
                    client_write.shutdown().await?;
                } else {
                    tokio::time::timeout(idle, client_write.write_all(&downstream[..count])).await.context("stream idle timeout")??;
                    metrics.bytes_downstream.fetch_add(count as u64, Ordering::Relaxed);
                }
            }
            () = tokio::time::sleep(idle) => anyhow::bail!("stream idle timeout"),
        }
    }
    Ok(())
}
