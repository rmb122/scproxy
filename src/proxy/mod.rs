pub mod direct;
pub mod http;
pub mod socks5;

use anyhow::{Context as _, Result, bail};
use async_trait::async_trait;
use std::io::{self, Cursor, Read};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(32);

/// A fully parsed outbound route.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProxyConfig {
    Direct,
    Socks5 {
        addr: String,
        auth: Option<(String, String)>,
    },
    Http {
        addr: String,
        auth: Option<(String, String)>,
    },
}

impl ProxyConfig {
    /// Parse `direct` or a supported proxy URL.
    pub fn parse(value: &str) -> Result<Self> {
        if value == "direct" {
            return Ok(Self::Direct);
        }

        enum Kind {
            Socks5,
            Http,
        }

        let (kind, rest) = if let Some(rest) = value.strip_prefix("socks5://") {
            (Kind::Socks5, rest)
        } else if let Some(rest) = value.strip_prefix("socks://") {
            (Kind::Socks5, rest)
        } else if let Some(rest) = value.strip_prefix("http://") {
            (Kind::Http, rest)
        } else {
            bail!(
                "unsupported proxy '{}'; use direct, socks5://, socks://, or http://",
                value
            );
        };

        let (auth, host_port) = if let Some(at_pos) = rest.rfind('@') {
            let auth_str = &rest[..at_pos];
            let host_port = &rest[at_pos + 1..];
            let mut parts = auth_str.splitn(2, ':');
            let user = parts.next().unwrap_or("").to_string();
            let pass = parts.next().unwrap_or("").to_string();
            if user.is_empty() {
                bail!("empty username in proxy URL");
            }
            (Some((user, pass)), host_port)
        } else {
            (None, rest)
        };

        if host_port.parse::<SocketAddr>().is_err() {
            let (host, port) = host_port
                .rsplit_once(':')
                .with_context(|| format!("invalid proxy address: '{host_port}'"))?;
            if host.is_empty()
                || host.contains([':', '/', '?', '#', '[', ']'])
                || host.chars().any(char::is_whitespace)
            {
                bail!("invalid proxy hostname: '{host}'");
            }
            port.parse::<u16>()
                .with_context(|| format!("invalid proxy port: '{port}'"))?;
        }
        // Resolve proxy hostnames asynchronously on the host when connecting.
        let addr = host_port.to_owned();

        Ok(match kind {
            Kind::Socks5 => Self::Socks5 { addr, auth },
            Kind::Http => Self::Http { addr, auth },
        })
    }

    pub async fn connect(&self, target: &ProxyTarget) -> Result<ProxyStream> {
        tokio::time::timeout(CONNECT_TIMEOUT, self.connect_inner(target))
            .await
            .context("upstream connection timed out after 32 seconds")?
    }

    async fn connect_inner(&self, target: &ProxyTarget) -> Result<ProxyStream> {
        match self {
            Self::Direct => bail!("domain direct routes require the shared direct connector"),
            Self::Socks5 { addr, auth } => {
                socks5::Socks5Connector::new(addr.clone(), auth.clone())
                    .connect(target)
                    .await
            }
            Self::Http { addr, auth } => {
                http::HttpConnector::new(addr.clone(), auth.clone())
                    .connect(target)
                    .await
            }
        }
    }
}

impl std::fmt::Display for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => f.write_str("direct"),
            Self::Socks5 { addr, .. } => write!(f, "socks5://{addr}"),
            Self::Http { addr, .. } => write!(f, "http://{addr}"),
        }
    }
}

/// Target for proxy connection.
#[derive(Debug, Clone)]
pub enum ProxyTarget {
    /// Domain recovered from FakeIP, resolved by the selected route.
    Domain { host: String, port: u16 },
    /// IP address.
    Ip { addr: IpAddr, port: u16 },
}

impl std::fmt::Display for ProxyTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyTarget::Domain { host, port } => write!(f, "{}:{}", host, port),
            ProxyTarget::Ip { addr, port } => write!(f, "{}:{}", addr, port),
        }
    }
}

/// Trait for proxy connectors.
#[async_trait]
pub trait ProxyConnector: Send + Sync {
    async fn connect(&self, target: &ProxyTarget) -> Result<ProxyStream>;
}

/// Bidirectional stream after proxy handshake completes.
pub struct ProxyStream {
    pub inner: TcpStream,
    buffered: Cursor<Vec<u8>>,
}

impl ProxyStream {
    pub(crate) fn new(inner: TcpStream, buffered: Vec<u8>) -> Self {
        Self {
            inner,
            buffered: Cursor::new(buffered),
        }
    }

    fn has_buffered_data(&self) -> bool {
        self.buffered.position() < self.buffered.get_ref().len() as u64
    }

    pub fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.has_buffered_data() {
            self.buffered.read(buf)
        } else {
            self.inner.try_read(buf)
        }
    }

    pub fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.has_buffered_data() {
            Poll::Ready(Ok(()))
        } else {
            self.inner.poll_read_ready(cx)
        }
    }
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.has_buffered_data() {
            let read = self.buffered.read(buf.initialize_unfilled())?;
            buf.advance(read);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_urls_validate_routes_and_addresses() {
        assert_eq!(ProxyConfig::parse("direct").unwrap(), ProxyConfig::Direct);
        assert!(matches!(
            ProxyConfig::parse("http://user:pass@127.0.0.1:8080").unwrap(),
            ProxyConfig::Http { auth: Some(_), .. }
        ));
        for url in [
            "socks5://localhost:1080",
            "http://user:pass@proxy:8080",
            "http://[::1]:8080",
        ] {
            assert!(ProxyConfig::parse(url).is_ok(), "{url}");
        }
        for url in [
            "",
            "ftp://127.0.0.1:21",
            "socks5://not-an-address",
            "http://:80",
            "http://host:invalid",
            "http://host:65536",
            "http://::1:80",
        ] {
            assert!(ProxyConfig::parse(url).is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn stalled_proxy_handshakes_time_out_and_close_the_stream() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        for scheme in ["socks5", "http"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let config =
                ProxyConfig::parse(&format!("{scheme}://{}", listener.local_addr().unwrap()))
                    .unwrap();
            let target = ProxyTarget::Domain {
                host: "example.test".into(),
                port: 80,
            };
            let connect = tokio::spawn(async move { config.connect(&target).await });
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(peer.read(&mut request).await.unwrap() > 0);

            tokio::time::pause();
            tokio::time::advance(CONNECT_TIMEOUT).await;
            let error = connect
                .await
                .unwrap()
                .err()
                .expect("handshake must time out");
            tokio::time::resume();
            assert!(error.to_string().contains("timed out"));
            let read = tokio::time::timeout(Duration::from_secs(2), peer.read(&mut request))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(read, 0, "timed-out handshake must release its TCP stream");
        }
    }
}
