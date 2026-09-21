/// SOCKS5 proxy connector (RFC 1928 + RFC 1929).
///
/// Supports:
///   - NO_AUTH (0x00) and USERNAME/PASSWORD (0x02) negotiation
///   - CONNECT command with ATYP 0x01 (IPv4), 0x03 (domain), 0x04 (IPv6)
///   - Domain names are forwarded verbatim to prevent DNS leaks
use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{ProxyConnector, ProxyStream, ProxyTarget};

// ── Constants ──────────────────────────────────────────────────────────────────

const SOCKS5_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const RSV: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const AUTH_VERSION: u8 = 0x01;
const AUTH_SUCCESS: u8 = 0x00;

// ── Connector ─────────────────────────────────────────────────────────────────

/// SOCKS5 connector.
pub struct Socks5Connector {
    server: String,
    auth: Option<(String, String)>,
}

impl Socks5Connector {
    /// Create a new SOCKS5 connector.
    ///
    /// `auth` is an optional `(username, password)` pair.  When provided,
    /// the connector advertises USERNAME/PASSWORD as a supported auth method.
    pub fn new(server: String, auth: Option<(String, String)>) -> Self {
        Self { server, auth }
    }
}

#[async_trait]
impl ProxyConnector for Socks5Connector {
    async fn connect(&self, target: &ProxyTarget) -> Result<ProxyStream> {
        let mut stream = TcpStream::connect(self.server.as_str())
            .await
            .with_context(|| format!("TCP connect to SOCKS5 server {}", self.server))?;

        // ── Step 1: Method negotiation ────────────────────────────────────────
        let method = negotiate_method(&mut stream, self.auth.is_some()).await?;

        // ── Step 2: Authentication (if required) ──────────────────────────────
        if method == METHOD_USER_PASS {
            let (user, pass) = self.auth.as_ref().context("SOCKS5: missing credentials")?;
            authenticate(&mut stream, user, pass).await?;
        }

        // ── Step 3: CONNECT request ───────────────────────────────────────────
        send_connect_request(&mut stream, target).await?;

        Ok(ProxyStream::new(stream, Vec::new()))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Exchange greeting / method selection messages.
///
/// Client → Server: `VER NMETHODS METHODS…`
/// Server → Client: `VER METHOD`
async fn negotiate_method(stream: &mut TcpStream, has_auth: bool) -> Result<u8> {
    // Build client greeting.
    let methods: &[u8] = if has_auth {
        &[METHOD_NO_AUTH, METHOD_USER_PASS]
    } else {
        &[METHOD_NO_AUTH]
    };

    let mut greeting = vec![SOCKS5_VERSION, methods.len() as u8];
    greeting.extend_from_slice(methods);

    stream
        .write_all(&greeting)
        .await
        .context("SOCKS5: write greeting")?;

    // Read server method selection.
    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .await
        .context("SOCKS5: read method response")?;

    if resp[0] != SOCKS5_VERSION {
        bail!(
            "SOCKS5: server replied with unexpected version 0x{:02X}",
            resp[0]
        );
    }

    match resp[1] {
        METHOD_NO_AUTH => {
            // Server chose no-auth — proceed.
            if has_auth {
                tracing::debug!("SOCKS5: server chose NO_AUTH despite credentials being available");
            }
        }
        METHOD_USER_PASS => {
            if !has_auth {
                bail!("SOCKS5: server requires authentication but no credentials were provided");
            }
            // Handled by the caller (authenticate() called after this fn).
        }
        METHOD_NO_ACCEPTABLE => {
            bail!("SOCKS5: server found no acceptable authentication method");
        }
        other => {
            bail!("SOCKS5: server chose unknown auth method 0x{:02X}", other);
        }
    }

    Ok(resp[1])
}

/// Perform RFC 1929 username/password authentication.
///
/// Client → Server: `VER ULEN USER PLEN PASS`
/// Server → Client: `VER STATUS`   (STATUS == 0x00 means success)
async fn authenticate(stream: &mut TcpStream, user: &str, pass: &str) -> Result<()> {
    let user_bytes = user.as_bytes();
    let pass_bytes = pass.as_bytes();

    if user_bytes.len() > 255 {
        bail!("SOCKS5 auth: username too long (max 255 bytes)");
    }
    if pass_bytes.len() > 255 {
        bail!("SOCKS5 auth: password too long (max 255 bytes)");
    }

    let mut req = Vec::with_capacity(3 + user_bytes.len() + pass_bytes.len());
    req.push(AUTH_VERSION);
    req.push(user_bytes.len() as u8);
    req.extend_from_slice(user_bytes);
    req.push(pass_bytes.len() as u8);
    req.extend_from_slice(pass_bytes);

    stream
        .write_all(&req)
        .await
        .context("SOCKS5 auth: write request")?;

    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .await
        .context("SOCKS5 auth: read response")?;

    if resp[1] != AUTH_SUCCESS {
        bail!(
            "SOCKS5 auth: authentication failed (status 0x{:02X})",
            resp[1]
        );
    }

    Ok(())
}

/// Send a SOCKS5 CONNECT request and read the server reply.
///
/// Client → Server:
///   `VER CMD RSV ATYP DST.ADDR DST.PORT`
///
/// Server → Client:
///   `VER REP RSV ATYP BND.ADDR BND.PORT`
async fn send_connect_request(stream: &mut TcpStream, target: &ProxyTarget) -> Result<()> {
    // Build the request.
    let mut req = vec![SOCKS5_VERSION, CMD_CONNECT, RSV];

    match target {
        ProxyTarget::Ip {
            addr: IpAddr::V4(v4),
            port,
        } => {
            req.push(ATYP_IPV4);
            req.extend_from_slice(&v4.octets());
            req.extend_from_slice(&port.to_be_bytes());
        }
        ProxyTarget::Ip {
            addr: IpAddr::V6(v6),
            port,
        } => {
            req.push(ATYP_IPV6);
            req.extend_from_slice(&v6.octets());
            req.extend_from_slice(&port.to_be_bytes());
        }
        ProxyTarget::Domain { host, port } => {
            let host_bytes = host.as_bytes();
            if host_bytes.len() > 255 {
                bail!("SOCKS5: target hostname too long (max 255 bytes)");
            }
            req.push(ATYP_DOMAIN);
            req.push(host_bytes.len() as u8);
            req.extend_from_slice(host_bytes);
            req.extend_from_slice(&port.to_be_bytes());
        }
    }

    stream
        .write_all(&req)
        .await
        .context("SOCKS5: write CONNECT request")?;

    // Read the fixed 4-byte header of the reply.
    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .await
        .context("SOCKS5: read CONNECT reply header")?;

    if hdr[0] != SOCKS5_VERSION {
        bail!("SOCKS5: unexpected version in reply 0x{:02X}", hdr[0]);
    }
    if hdr[1] != REP_SUCCESS {
        let msg = socks5_reply_message(hdr[1]);
        bail!(
            "SOCKS5: CONNECT to {} failed: {} (0x{:02X})",
            target,
            msg,
            hdr[1]
        );
    }

    // Skip BND.ADDR + BND.PORT (we don't need them).
    skip_addr(stream, hdr[3])
        .await
        .context("SOCKS5: skip BND address")?;

    tracing::debug!("SOCKS5: tunnel established to {}", target);
    Ok(())
}

/// Drain BND.ADDR and BND.PORT from the stream.
async fn skip_addr(stream: &mut TcpStream, atyp: u8) -> Result<()> {
    match atyp {
        ATYP_IPV4 => {
            // 4 bytes addr + 2 bytes port
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
        }
        ATYP_IPV6 => {
            // 16 bytes addr + 2 bytes port
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
        }
        ATYP_DOMAIN => {
            // 1 byte length, <length> bytes addr, 2 bytes port
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let total = len_buf[0] as usize + 2;
            let mut buf = vec![0u8; total];
            stream.read_exact(&mut buf).await?;
        }
        other => {
            bail!("SOCKS5: unknown ATYP in reply 0x{:02X}", other);
        }
    }
    Ok(())
}

/// Human-readable description of a SOCKS5 reply code.
fn socks5_reply_message(rep: u8) -> &'static str {
    match rep {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::ProxyConfig;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn credentials_with_no_auth_selection_send_connect_immediately() {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            // Exercise host-side hostname resolution, including address fallback.
            let config = ProxyConfig::parse(&format!(
                "socks5://user:pass@localhost:{}",
                listener.local_addr().unwrap().port()
            ))
            .unwrap();
            let target = ProxyTarget::Ip {
                addr: "1.2.3.4".parse().unwrap(),
                port: 80,
            };
            let server = async {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 4];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 2, 0, 2]);
                stream.write_all(&[5, METHOD_NO_AUTH]).await.unwrap();
                let mut connect = [0; 10];
                stream.read_exact(&mut connect).await.unwrap();
                assert_eq!(connect, [5, 1, 0, 1, 1, 2, 3, 4, 0, 80]);
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
            };
            let (connected, ()) = tokio::join!(config.connect(&target), server);
            connected.unwrap();
        })
        .await
        .expect("SOCKS5 handshake must complete");
    }
}
