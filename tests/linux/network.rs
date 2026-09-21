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
s=socket.socket()
try: s.sendto(b'no leak',socket.MSG_FASTOPEN,('127.0.0.1',int(os.environ['TCP_PORT']))); raise AssertionError('Fast Open allowed')
except OSError as e: assert e.errno==errno.EOPNOTSUPP,e
"#]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(udp.recv(&mut [0; 100]).is_err());
    assert!(tcp.accept().is_err());
}
