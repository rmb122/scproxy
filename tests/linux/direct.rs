//! DNS-time route selection and native direct TCP behavior.
use super::support::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn mixed_dns_returns_real_direct_addresses_and_proxy_fake_addresses() {
    for default_direct in [true, false] {
        let direct = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = direct.local_addr().unwrap().port();
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let route = format!("http://{}", proxy.local_addr().unwrap());
        let direct_worker = std::thread::spawn(move || {
            for _ in 0..2 {
                let mut connection = accept_with_timeout(direct.try_clone().unwrap());
                connection.write_all(b"DIRECT").unwrap();
                let mut ack = [0];
                connection.read_exact(&mut ack).unwrap();
                assert_eq!(&ack, b"!");
            }
        });
        let proxy_worker = std::thread::spawn(move || {
            for _ in 0..2 {
                let mut connection = accept_with_timeout(proxy.try_clone().unwrap());
                let mut reader = BufReader::new(&mut connection);
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                assert_eq!(first, format!("CONNECT localhost:{port} HTTP/1.1\r\n"));
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                connection
                    .write_all(b"HTTP/1.1 200 OK\r\n\r\nPROXY")
                    .unwrap();
                let mut ack = [0];
                connection.read_exact(&mut ack).unwrap();
                assert_eq!(&ack, b"!");
            }
        });
        let mut command = scproxy(if default_direct { "direct" } else { &route });
        if default_direct {
            command.args(["-r", &format!("domain:localhost={route}")]);
        } else {
            command.args(["-r", "domain:127.0.0.1=direct"]);
        }
        let script = format!(
            "{DNS_API}\n{}",
            r#"
import os
port=int(os.environ['PORT'])
# Both names identify the same host address, but receive different DNS answers.
# Numeric host NSS input keeps this test independent of external DNS.
for tcp in [False, True]:
    direct=dns_lookup('127.0.0.1',tcp)
    proxy=dns_lookup('localhost',tcp)
    assert direct==[('127.0.0.1',60)],direct
    assert len(proxy)==1 and proxy[0][0].startswith(('198.18.','198.19.')),proxy
    assert dns_lookup('localhost',tcp,28)==[]
    for ip,expected in [(direct[0][0],b'DIRECT'),(proxy[0][0],b'PROXY')]:
        with socket.create_connection((ip,port),timeout=3) as connection:
            assert dns_exact(connection,len(expected))==expected
            connection.sendall(b'!')
"#
        );
        let output = command
            .env("PORT", port.to_string())
            .args(["python3", "-c", &script])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "default_direct={default_direct}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        direct_worker.join().unwrap();
        proxy_worker.join().unwrap();
    }
}

#[test]
#[ignore = "requires Linux seccomp, Python 3, and a non-loopback default route"]
fn direct_connect_preserves_native_socket_errors_readiness_and_half_close() {
    // UDP connect only selects a local route; it sends no packet.
    let route_probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    route_probe
        .connect((Ipv4Addr::new(192, 0, 2, 1), 9))
        .unwrap();
    let ip = route_probe.local_addr().unwrap().ip();
    assert!(!ip.is_loopback());
    for mode in ["default", "ip", "dns"] {
        let mut command = scproxy(if mode == "default" {
            "direct"
        } else {
            "http://127.0.0.1:1"
        });
        if mode == "ip" {
            command.args(["-r", &format!("cidr:{ip}/32=direct")]);
        } else if mode == "dns" {
            command.args([
                "-r",
                &format!("domain:{ip}=direct"),
                "-r",
                &format!("ip:{ip}=http://127.0.0.1:1"),
            ]);
        }
        let script = format!(
            "{DNS_API}\n{SOCKET_API}\n{}",
            r#"
import fcntl,os,select
ip=os.environ['IP']
if os.environ['MODE']=='dns': assert dns_lookup(ip)==[(ip,60)]
server=socket.socket();server.bind((ip,0));server.listen();server.settimeout(3)
target=server.getsockname()
for blocking in [True,False]:
    client=socket.socket();client.bind((ip,0));client.setblocking(blocking)
    duplicate=socket.socket(fileno=os.dup(client.fileno()))
    identity=os.readlink('/proc/self/fd/%d'%client.fileno())
    flags=fcntl.fcntl(client,fcntl.F_GETFL)
    client.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
    if blocking: client.connect(target)
    else:
        assert client.connect_ex(target) in (0,errno.EINPROGRESS)
        assert select.select([], [duplicate], [], 3)[1]
        assert duplicate.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)==0
    assert os.readlink('/proc/self/fd/%d'%client.fileno())==identity
    assert fcntl.fcntl(duplicate,fcntl.F_GETFL)==flags
    assert duplicate.getsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE)==1
    assert client.getpeername()==peer_name(duplicate)==target
    accepted,source=server.accept();accepted.settimeout(3)
    assert source==client.getsockname(),(source,client.getsockname())
    assert accepted.getsockname()==client.getpeername()
    client.close();duplicate.settimeout(3)
    duplicate.sendall(b'NATIVE');assert dns_exact(accepted,6)==b'NATIVE'
    duplicate.shutdown(socket.SHUT_WR);assert accepted.recv(1)==b''
    accepted.sendall(b'AFTER_FIN');assert dns_exact(duplicate,9)==b'AFTER_FIN'
    accepted.close();duplicate.close()
# A bound, non-listening port deterministically refuses native TCP connects.
refused=socket.socket();refused.bind((ip,0))
for blocking in [True,False]:
    with socket.socket() as client:
        client.setblocking(blocking)
        error=client.connect_ex(refused.getsockname())
        if error==errno.EINPROGRESS:
            assert not blocking
            assert select.select([], [client], [], 3)[1]
            error=client.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
        assert error==errno.ECONNREFUSED,error
refused.close();server.close()
"#
        );
        let output = command
            .env("IP", ip.to_string())
            .env("MODE", mode)
            .args(["python3", "-c", &script])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
