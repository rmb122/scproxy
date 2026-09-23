//! Native host networking and rejection of unsupported network paths.
use super::support::*;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::time::Duration;

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn localhost_and_listeners_use_the_host_network() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = server.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let mut connection = accept_with_timeout(server);
        let mut bytes = [0; 4];
        connection.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"HOST");
        connection.write_all(b"OK").unwrap();
    });
    let mut command = scproxy("socks5://127.0.0.1:1");
    command.env("HOST_PORT", address.port().to_string()).env(
        "HOST_NETNS",
        std::fs::read_link("/proc/self/ns/net").unwrap(),
    );
    let mut managed = ManagedChild::spawn_with_command(
        command,
        r#"
import errno, os, socket
assert os.readlink('/proc/self/ns/net') == os.environ['HOST_NETNS']
s = socket.create_connection(('127.0.0.1',int(os.environ['HOST_PORT'])),timeout=3)
s.sendall(b'HOST'); assert s.recv(2) == b'OK'; s.close()
s = socket.socket(); s.bind(('0.0.0.0',0)); s.listen()
print(os.getppid(),os.getpid(),flush=True)
print(s.getsockname()[1],flush=True)
s.settimeout(5)
c,_=s.accept(); assert c.recv(1)==b'x'; c.sendall(b'y')
assert c.recv(1)==b'!'
other=socket.socket()
try: other.bind(s.getsockname()); raise AssertionError('port conflict ignored')
except OSError as e: assert e.errno==errno.EADDRINUSE
"#,
    );
    managed.read_process_ids();
    let port: u16 = managed.read_line().parse().unwrap();
    let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"x").unwrap();
    let mut byte = [0];
    c.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"y");
    c.write_all(b"!").unwrap();
    assert!(managed.wait().success());
    managed.descendants.clear();
    worker.join().unwrap();
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn native_peer_options_and_oob_remain_available() {
    let script = format!(
        "{SOCKET_API}\n{}",
        r#"
import select
for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
    with socket.socket(socket.AF_INET, kind) as unconnected:
        try:
            peer_name(unconnected)
            raise AssertionError('unconnected socket has a peer')
        except OSError as error:
            assert error.errno == errno.ENOTCONN, error
server = socket.socket()
server.bind(('127.0.0.1', 0)); server.listen()
client = socket.create_connection(server.getsockname(), timeout=3)
accepted, _ = server.accept()
accepted.settimeout(3)
for sender, receiver in ((client, accepted), (accepted, client)):
    assert peer_name(sender) == sender.getpeername()
    assert sender.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    assert sender.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
    sender.sendall(b'A')
    assert sender.send(b'!', socket.MSG_OOB) == 1
    sender.sendall(b'B')
    assert select.select([], [], [receiver], 3)[2]
    assert receiver.recv(1, socket.MSG_OOB | socket.MSG_DONTWAIT) == b'!'
    data = b''
    while len(data) < 2:
        part = receiver.recv(2 - len(data)); assert part; data += part
    assert data == b'AB'
accepted.close(); client.close(); server.close()
"#
    );
    let output = scproxy("http://127.0.0.1:1")
        .args(["python3", "-c", &script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn local_defaults_preserve_zero_destination_and_source_binding() {
    let script = format!(
        "{SOCKET_API}\n{}",
        r#"
for destination,source,expected in [
    ('0.0.0.0',None,'127.0.0.1'),
    ('0.0.0.0','127.0.0.2','127.0.0.2'),
    ('127.42.1.2',None,'127.42.1.2'),
]:
    with socket.socket() as server,socket.socket() as client:
        server.bind(('0.0.0.0',0));server.listen();server.settimeout(3);client.settimeout(3)
        if source:client.bind((source,0))
        client.connect((destination,server.getsockname()[1]))
        accepted,peer=server.accept()
        with accepted:
            assert peer==client.getsockname()
            assert client.getpeername()==peer_name(client)==(expected,server.getsockname()[1])
            assert accepted.getsockname()==client.getpeername()
            client.sendall(b'LOCAL');assert accepted.recv(5)==b'LOCAL'
"#
    );
    let output = scproxy("http://127.0.0.1:1")
        .args(["python3", "-c", &script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn explicit_local_proxy_rules_preserve_destinations_but_do_not_override_dns() {
    for scheme in ["http", "socks5"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let route = format!("{scheme}://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            for ip in ["127.0.0.1", "127.42.1.2", "0.0.0.0"] {
                let mut connection = if scheme == "http" {
                    tunnel(listener.try_clone().unwrap(), &format!("{ip}:8443"))
                } else {
                    let mut connection = accept_with_timeout(listener.try_clone().unwrap());
                    let mut hello = [0; 3];
                    connection.read_exact(&mut hello).unwrap();
                    assert_eq!(hello, [5, 1, 0]);
                    connection.write_all(&[5, 0]).unwrap();
                    let mut request = [0; 10];
                    connection.read_exact(&mut request).unwrap();
                    assert_eq!(&request[..4], &[5, 1, 0, 1]);
                    assert_eq!(
                        &request[4..8],
                        &ip.parse::<std::net::Ipv4Addr>().unwrap().octets()
                    );
                    assert_eq!(&request[8..], &8443u16.to_be_bytes());
                    connection
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                        .unwrap();
                    connection
                };
                connection.write_all(b"PROXY").unwrap();
                let mut ack = [0];
                connection.read_exact(&mut ack).unwrap();
                assert_eq!(&ack, b"!");
            }
            listener.set_nonblocking(true).unwrap();
            assert!(listener.accept().is_err());
        });
        let script = format!(
            "{DNS_API}\n{SOCKET_API}\n{}",
            r#"
for ip in ['198.18.0.1','0.0.0.0','127.0.0.1','198.18.200.1']:
    for tcp in [False,True]:
        answer=dns_lookup('dns.invalid',tcp,server=(ip,53))
        assert answer[0][0]=='198.18.0.2',answer
with socket.socket() as reserved:
    reserved.settimeout(1)
    try: reserved.connect(('198.18.0.1',8443)); raise AssertionError('DNS address was routed')
    except OSError as error: assert error.errno==errno.ENETUNREACH,error
for ip in ['127.0.0.1','127.42.1.2','0.0.0.0']:
    with socket.create_connection((ip,8443),timeout=3) as connection:
        assert connection.getpeername()==peer_name(connection)==(ip,8443)
        assert dns_exact(connection,5)==b'PROXY'
        connection.sendall(b'!')
"#
        );
        let output = scproxy("direct")
            .args([
                "-r",
                &format!("cidr:127.0.0.0/8={route}"),
                "-r",
                &format!("ip:0.0.0.0={route}"),
                "-r",
                &format!("ip:198.18.0.1={route}"),
                "python3",
                "-c",
                &script,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{scheme}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        worker.join().unwrap();
    }
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn unsupported_network_paths_cannot_send_packets() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    tcp.set_nonblocking(true).unwrap();
    let output=scproxy("direct").env("UDP_PORT",udp.local_addr().unwrap().port().to_string()).env("TCP_PORT",tcp.local_addr().unwrap().port().to_string()).args(["python3","-c",r#"
import ctypes as c, errno, os, socket
lib=c.CDLL(None,use_errno=True)
for call in (425,426,427):
    assert lib.syscall(call,0,0,0,0,0,0)==-1 and c.get_errno()==errno.ENOSYS
for family,kind,protocol,error in [(socket.AF_INET6,socket.SOCK_STREAM,0,errno.EAFNOSUPPORT),(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP,errno.EPROTONOSUPPORT)]:
    try: socket.socket(family,kind,protocol); raise AssertionError('unsupported socket allowed')
    except OSError as e: assert e.errno==error,e
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for destination in [('127.0.0.1',int(os.environ['UDP_PORT'])),('8.8.8.8',123)]:
    try: s.sendto(b'no leak',destination); raise AssertionError('UDP allowed')
    except OSError as e: assert e.errno==errno.ENETUNREACH,e
    try: s.connect(destination); raise AssertionError('UDP connect allowed')
    except OSError as e: assert e.errno==errno.ENETUNREACH,e
    try: s.send(b'no leak'); raise AssertionError('unconnected UDP send allowed')
    except OSError as e: assert e.errno==errno.EDESTADDRREQ,e
s=socket.socket()
try: s.sendto(b'no leak',socket.MSG_FASTOPEN,('127.0.0.1',int(os.environ['TCP_PORT']))); raise AssertionError('Fast Open allowed')
except OSError as e: assert e.errno==errno.EOPNOTSUPP,e
for ip in ['198.18.0.1','198.18.200.1']:
    with socket.socket() as unknown:
        unknown.settimeout(1)
        try: unknown.connect((ip,443)); raise AssertionError('reserved or unknown FakeIP allowed')
        except OSError as e: assert e.errno==errno.ENETUNREACH,e
"#]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(udp.recv(&mut [0; 100]).is_err());
    assert!(tcp.accept().is_err());
}
