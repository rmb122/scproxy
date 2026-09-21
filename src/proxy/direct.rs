//! Direct connector — opens a TCP connection straight to the target
//! from the unfiltered supervisor without going through any
//! upstream proxy.
//!
//! Used whenever the selected default or rule route is `direct`.

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::net::TcpStream;

use super::{ProxyConnector, ProxyStream, ProxyTarget};

/// Connector that simply does `TcpStream::connect` to the target.
///
/// For domain targets the host's resolver is used, so selecting this route
/// explicitly opts in to host-side DNS resolution.
pub struct DirectConnector;

#[async_trait]
impl ProxyConnector for DirectConnector {
    async fn connect(&self, target: &ProxyTarget) -> Result<ProxyStream> {
        let stream = match target {
            ProxyTarget::Ip { addr, port } => TcpStream::connect((*addr, *port))
                .await
                .with_context(|| format!("direct TCP connect to {addr}:{port}"))?,
            ProxyTarget::Domain { host, port } => TcpStream::connect((host.as_str(), *port))
                .await
                .with_context(|| format!("direct TCP connect to {host}:{port}"))?,
        };

        tracing::debug!("direct: connected to {}", target);
        Ok(ProxyStream::new(stream, Vec::new()))
    }
}
