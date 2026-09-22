//! Proxy protocols, socket identity, connection dispatch, and data integrity.
use super::support::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

#[test]
#[ignore = "requires Linux seccomp, pidfd_getfd, and Python 3"]
fn fake_dns_rules_and_explicit_outbound_bind() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = listener.local_addr().unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let source_port = occupied.local_addr().unwrap().port();
    drop(occupied);
    let server = std::thread::spawn(move || {
        let mut stream = accept_with_timeout(listener);
        let mut reader = BufReader::new(&mut stream);
        let mut first = String::new();
        reader.read_line(&mut first).unwrap();
        assert_eq!(first, "CONNECT example.test:443 HTTP/1.1\r\n");
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nHELLO").unwrap();
        let mut ack = [0; 3];
        stream.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"ACK");
    });
    let output = scproxy("socks5://127.0.0.1:1")
        .args(["-r", &format!("domain:example.test=http://{proxy}")])
        .env("SCPROXY_TEST_SOURCE_PORT", source_port.to_string())
        .args([
            "python3",
            "-c",
            r#"
import os, socket
target = socket.getaddrinfo('example.test', 443, socket.AF_INET, socket.SOCK_STREAM)[0][4]
assert target[0].startswith(('198.18.', '198.19.')), target
s = socket.socket()
s.settimeout(5)
s.bind(('0.0.0.0', int(os.environ['SCPROXY_TEST_SOURCE_PORT'])))
s.connect(target)
assert s.getpeername() == target
data = b''
while len(data) < 5:
    chunk = s.recv(5 - len(data))
    assert chunk
    data += chunk
assert data == b'HELLO'
s.sendall(b'ACK')
"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn peer_name_socket_option_preserves_target_and_buffer_semantics() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let mut stream = tunnel(listener, "203.0.113.25:443");
        stream.write_all(b"R").unwrap();
        let mut ack = [0];
        stream.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"!");
    });
    let script = format!(
        "{SOCKET_API}\n{}",
        r#"
import os
target = ('203.0.113.25', 443)
s = socket.create_connection(target, timeout=3)
assert s.recv(1) == b'R'
check_peer_option(s, target)
with socket.socket(fileno=os.dup(s.fileno())) as duplicate:
    assert peer_name(duplicate) == target
s.sendall(b'!')
"#
    );
    let output = scproxy(&proxy)
        .args(["python3", "-c", &script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn relayed_oob_is_rejected_without_affecting_normal_data() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let mut stream = tunnel(listener, "203.0.113.25:443");
        stream.write_all(b"R").unwrap();
        let mut bytes = [0; 2];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"AB");
        stream.write_all(b"OK").unwrap();
        stream.read_exact(&mut bytes[..1]).unwrap();
        assert_eq!(bytes[0], b'!');
    });
    let script = format!(
        "{SOCKET_API}\n{}",
        r#"
s = socket.create_connection(('203.0.113.25', 443), timeout=3)
assert s.recv(1) == b'R'
s.sendall(b'A')
check_oob_rejected(s)
s.sendall(b'B')
assert s.recv(2, socket.MSG_WAITALL) == b'OK'
s.sendall(b'!')
"#
    );
    let output = scproxy(&proxy)
        .args(["python3", "-c", &script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn nonblocking_connect_preserves_dup_fork_epoll_and_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let mut stream = tunnel(listener, "203.0.113.25:443");
        let mut bytes = [0; 4];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"FORK");
        stream.write_all(b"HELLO").unwrap();
        stream.read_exact(&mut bytes[..1]).unwrap();
        assert_eq!(bytes[0], b'!');
    });
    let output = scproxy("http://127.0.0.1:1")
        .args([
            "-r",
            &format!("ip:203.0.113.25={proxy}"),
            "python3",
            "-c",
            r#"
import errno, os, select, socket
s=socket.socket(); s.bind(('0.0.0.0',0)); port=s.getsockname()[1]; s.setblocking(False)
duplicate=socket.socket(fileno=os.dup(s.fileno())); duplicate.setblocking(False)
ep=select.epoll(); ep.register(duplicate.fileno(),select.EPOLLOUT)
target=('203.0.113.25',443)
assert s.connect_ex(target) in (0,errno.EINPROGRESS)
assert ep.poll(3); assert duplicate.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)==0
assert s.getpeername()==duplicate.getpeername()==target
assert s.getsockname()[1]==port
pid=os.fork()
if pid==0:
    s.close(); duplicate.settimeout(3); duplicate.sendall(b'FORK')
    data=b''
    while len(data)<5: data+=duplicate.recv(5-len(data))
    assert data==b'HELLO'; assert duplicate.getpeername()==target
    duplicate.sendall(b'!'); os._exit(0)
s.close(); duplicate.close(); assert os.waitpid(pid,0)[1]==0
"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn bidirectional_backpressure_and_both_eof_directions_preserve_payloads() {
    for mode in ["echo", "app-eof", "upstream-eof"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut stream = tunnel(listener, "203.0.113.10:443");
            let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
            if mode == "upstream-eof" {
                stream.write_all(&payload).unwrap();
                stream.shutdown(std::net::Shutdown::Write).unwrap();
                let mut byte = [0];
                match stream.read(&mut byte) {
                    Ok(0) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                    result => panic!("expected closure: {result:?}"),
                };
            } else {
                std::thread::sleep(std::time::Duration::from_millis(50));
                let mut received = vec![0; payload.len()];
                stream.read_exact(&mut received).unwrap();
                assert_eq!(received, payload);
                if mode == "echo" {
                    stream.write_all(&received).unwrap();
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    assert_eq!(&byte, b"!");
                } else {
                    let mut byte = [0];
                    match stream.read(&mut byte) {
                        Ok(0) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                        result => panic!("expected closure: {result:?}"),
                    };
                }
            }
        });
        let output = scproxy(&proxy)
            .env("MODE", mode)
            .args([
                "python3",
                "-c",
                r#"
import os,socket,time
s=socket.create_connection(('203.0.113.10',443),timeout=5)
payload=bytes(i%251 for i in range(1024*1024)); mode=os.environ['MODE']
if mode!='upstream-eof': s.sendall(payload)
if mode=='app-eof': s.shutdown(socket.SHUT_WR)
if mode=='echo':
    time.sleep(.05); data=bytearray()
    while len(data)<len(payload):
        chunk=s.recv(4096); assert chunk; data.extend(chunk)
    assert data==payload; s.sendall(b'!')
else:
    data=bytearray()
    while True:
        try: chunk=s.recv(4096)
        except ConnectionResetError: break
        if not chunk: break
        data.extend(chunk)
    assert data==(payload if mode=='upstream-eof' else b''),len(data)
"#,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        server.join().unwrap();
    }
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn direct_domain_route_uses_the_supervisors_resolver() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let mut stream = accept_with_timeout(listener);
        stream.write_all(b"DIRECT").unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"!");
    });
    let output=scproxy("http://127.0.0.1:1").args(["-r","domain:localhost=direct"]).env("PORT",port.to_string()).args(["python3","-c",r#"
import os,socket,struct
q=b'\x12\x34\x01\x00\x00\x01'+b'\x00'*6+b'\x09localhost\x00\x00\x01\x00\x01'
d=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); d.settimeout(3); d.sendto(q,('172.23.255.254',53)); ip=socket.inet_ntoa(d.recv(512)[-4:])
assert ip.startswith(('198.18.','198.19.')),ip
s=socket.create_connection((ip,int(os.environ['PORT'])),timeout=3)
data=b''
while len(data)<6: data+=s.recv(6-len(data))
assert data==b'DIRECT'; s.sendall(b'!')
"#]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn socks5_authenticated_domain_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let route = format!("socks5://alice:secret@{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let mut s = accept_with_timeout(listener);
        let mut prefix = [0; 2];
        s.read_exact(&mut prefix).unwrap();
        assert_eq!(prefix[0], 5);
        let mut methods = vec![0; prefix[1] as usize];
        s.read_exact(&mut methods).unwrap();
        assert!(methods.contains(&2));
        s.write_all(&[5, 2]).unwrap();
        s.read_exact(&mut prefix).unwrap();
        assert_eq!(prefix, [1, 5]);
        let mut username = [0; 5];
        s.read_exact(&mut username).unwrap();
        assert_eq!(&username, b"alice");
        let mut length = [0];
        s.read_exact(&mut length).unwrap();
        let mut password = vec![0; length[0] as usize];
        s.read_exact(&mut password).unwrap();
        assert_eq!(password, b"secret");
        s.write_all(&[1, 0]).unwrap();
        let mut header = [0; 5];
        s.read_exact(&mut header).unwrap();
        assert_eq!(&header[..4], &[5, 1, 0, 3]);
        let mut host = vec![0; header[4] as usize];
        s.read_exact(&mut host).unwrap();
        assert_eq!(host, b"socks.invalid");
        s.read_exact(&mut prefix).unwrap();
        assert_eq!(u16::from_be_bytes(prefix), 443);
        s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        s.write_all(b"SOCKS").unwrap();
        s.read_exact(&mut length).unwrap();
        assert_eq!(&length, b"!");
    });
    let output = scproxy(&route)
        .args([
            "python3",
            "-c",
            r#"
import socket
s=socket.create_connection(('socks.invalid',443),timeout=3)
data=b''
while len(data)<5:data+=s.recv(5-len(data))
assert data==b'SOCKS';s.sendall(b'!')
"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn rejected_proxy_handshake_closes_the_local_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let route = format!("http://{}", listener.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        let mut stream = accept_with_timeout(listener);
        let mut reader = BufReader::new(&mut stream);
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
        }
        stream.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").unwrap();
    });
    let output = scproxy(&route)
        .args([
            "python3",
            "-c",
            r#"
import socket
s=socket.create_connection(('203.0.113.20',443),timeout=3)
try:assert s.recv(1)==b''
except ConnectionResetError:pass
"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    worker.join().unwrap();
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn one_listener_dispatches_concurrent_targets_and_rejects_other_processes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let mut connections = Vec::new();
        // One initial connection, 24 simultaneous requests, and one later request.
        for _ in 0..26 {
            let mut stream = accept_with_timeout(listener.try_clone().unwrap());
            connections.push(std::thread::spawn(move || {
                let mut reader = BufReader::new(&mut stream);
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                let target = first.strip_prefix("CONNECT ").unwrap();
                let target = target.strip_suffix(" HTTP/1.1\r\n").unwrap();
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                stream
                    .write_all(format!("HTTP/1.1 200 OK\r\n\r\n{target}\n").as_bytes())
                    .unwrap();
                let mut ack = [0];
                stream.read_exact(&mut ack).unwrap();
                assert_eq!(&ack, b"!");
            }));
        }
        for connection in connections {
            connection.join().unwrap();
        }
    });
    let mut command = scproxy(&proxy);
    command.stdin(std::process::Stdio::piped());
    let mut managed = ManagedChild::spawn_with_command(
        command,
        r#"
import concurrent.futures, os, socket, sys
def connect(index):
    target=('203.0.113.%d'%(index+1),4000+index)
    s=socket.socket(); s.settimeout(5)
    if index%3==0: s.bind(('0.0.0.0',0))
    if index%3==1:
        s.setsockopt(socket.IPPROTO_IP,24,1) # IP_BIND_ADDRESS_NO_PORT
        s.bind(('127.0.0.2',0))
    s.connect(target)
    assert s.getpeername()==target
    data=b''
    while not data.endswith(b'\n'):
        part=s.recv(128); assert part; data+=part
    assert data==('%s:%d\n'%target).encode(), (target,data)
    inode=os.readlink('/proc/self/fd/%d'%s.fileno())[8:-1]
    with open('/proc/net/tcp') as table:
        entries=[line.split() for line in table.readlines()[1:]]
    actual=next(row[2] for row in entries if row[9]==inode)
    assert actual.split(':')[0]=='0100007F',actual
    return s,actual
print(os.getppid(),os.getpid(),flush=True)
first,address=connect(0)
print(int(address.split(':')[1],16),flush=True)
assert sys.stdin.readline().strip()=='continue'
with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
    connections=list(pool.map(connect,range(1,25)))
assert all(peer==address for _,peer in connections),connections
for s,_ in connections:
    s.sendall(b'!');s.close()
first.sendall(b'!');first.close()
last,peer=connect(25); assert peer==address
last.sendall(b'!');last.close()
"#,
    );
    managed.read_process_ids();
    let port: u16 = managed.read_line().parse().unwrap();
    let mut stranger = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).unwrap();
    stranger
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let result = stranger.read(&mut [0]);
    assert!(
        matches!(result, Ok(0))
            || result.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
    );
    managed
        .child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"continue\n")
        .unwrap();
    assert!(managed.wait().success());
    managed.descendants.clear();
    server.join().unwrap();
}
