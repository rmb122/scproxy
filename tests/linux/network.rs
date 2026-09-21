use super::support::*;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::time::Duration;

#[test]
#[ignore = "requires Linux seccomp, user/mount namespaces, and Python 3"]
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
#[ignore = "requires Linux seccomp, user/mount namespaces, and Python 3"]
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
for destination in [('127.0.0.1',int(os.environ['UDP_PORT'])),('8.8.8.8',53)]:
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

#[test]
#[ignore = "requires Linux seccomp, user/mount namespaces, a C compiler, and static libc"]
fn static_binary_dns_abi_and_readiness() {
    let temp = TestDir::new("dns");
    let binary = temp.0.join("dns");
    let compiled = std::process::Command::new("cc")
        .args([
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-static",
            "-pthread",
            "tests/fixtures/dns.c",
            "-o",
        ])
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let output = scproxy("direct").arg(&binary).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"DNS ABI OK\n");
}

#[test]
#[ignore = "requires Linux seccomp, user/mount namespaces, and Python 3"]
fn glibc_dns_handles_ipv4_and_empty_ipv6_without_host_resolution() {
    let output=scproxy("http://127.0.0.1:1").args(["python3","-c",r#"
import socket, threading
errors=[]
def query(index):
    try:
        result=socket.getaddrinfo('unique-%d.invalid'%index,443,0,socket.SOCK_STREAM)
        assert result and all(item[0]==socket.AF_INET and item[4][0].startswith(('198.18.','198.19.')) for item in result)
    except BaseException as e: errors.append(e)
threads=[threading.Thread(target=query,args=(i,)) for i in range(24)]
for t in threads:t.start()
for t in threads:t.join()
assert not errors, errors
"#]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
