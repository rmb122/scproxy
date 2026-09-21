use super::support::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

#[test]
#[ignore = "requires Linux user/mount namespaces and seccomp"]
fn internal_dns_mounts_are_readable_by_all_users() {
    let output = scproxy("direct")
        .args(["sh", "-c", "stat -c '%a' /etc/resolv.conf /etc/nsswitch.conf; cat /etc/resolv.conf /etc/nsswitch.conf"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "644\n644\nnameserver 172.23.255.254\nhosts: files dns\n"
    );
}

#[test]
#[ignore = "requires Linux user/mount namespaces, seccomp, and Python 3"]
fn http_greeting_and_subsequent_responses_reach_the_namespace() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("http://localhost:{}", listener.local_addr().unwrap().port());
    let server = std::thread::spawn(move || {
        let mut stream = accept_with_timeout(listener);
        let mut reader = BufReader::new(&mut stream);
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nHELLO").unwrap();
        for _ in 0..20 {
            let mut request = [0; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"PING");
            stream.write_all(b"PONG").unwrap();
        }
        let mut ack = [0; 3];
        stream.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"ACK");
    });
    let output = scproxy(&proxy)
        .args([
            "python3",
            "-u",
            "-c",
            r#"
import socket, statistics, time
s = socket.create_connection(('203.0.113.1', 22), timeout=5)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
def read_exact(n):
    data = b''
    while len(data) < n:
        chunk = s.recv(n - len(data))
        assert chunk
        data += chunk
    return data
assert read_exact(5) == b'HELLO'
elapsed = []
for _ in range(20):
    start = time.perf_counter()
    s.sendall(b'PING')
    assert read_exact(4) == b'PONG'
    elapsed.append((time.perf_counter() - start) * 1000)
s.sendall(b'ACK')
print('Outbound median round trip: %.3f ms' % statistics.median(elapsed))
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
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
}

#[test]
#[ignore = "requires Linux user/mount namespaces, seccomp, pidfd_getfd, and Python 3"]
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

fn tunnel(listener: TcpListener, expected: &str) -> std::net::TcpStream {
    let mut stream = accept_with_timeout(listener);
    let mut reader = BufReader::new(&mut stream);
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    assert_eq!(first, format!("CONNECT {expected} HTTP/1.1\r\n"));
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        if line == "\r\n" {
            break;
        }
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
    stream
}

#[test]
#[ignore = "requires Linux seccomp, user/mount namespaces, and Python 3"]
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
#[ignore = "requires Linux seccomp, user/mount namespaces, and Python 3"]
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
#[ignore = "requires Linux seccomp, user/mount namespaces, and Python 3"]
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
#[ignore = "requires Linux seccomp, user/mount namespaces, and Python 3"]
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
#[ignore = "requires Linux seccomp, user/mount namespaces, prlimit permissions, and Python 3"]
fn descriptor_exhaustion_fails_one_request_and_recovers() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let route = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let mut stream = tunnel(listener, "203.0.113.15:443");
        stream.write_all(b"OK").unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"!");
    });
    let mut command = scproxy(&route);
    command.stdin(std::process::Stdio::piped());
    let mut managed = ManagedChild::spawn_with_command(
        command,
        r#"
import errno,os,socket,sys
print(os.getppid(),os.getpid(),flush=True)
assert sys.stdin.readline().strip()=='exhausted'
s=socket.socket()
try:s.connect(('203.0.113.15',443));raise AssertionError('connect should report exhaustion')
except OSError as e:assert e.errno in (errno.EMFILE,errno.ENFILE),e
s.close();print('recovered next',flush=True)
assert sys.stdin.readline().strip()=='restored'
s=socket.create_connection(('203.0.113.15',443),timeout=3)
data=b''
while len(data)<2:data+=s.recv(2-len(data))
assert data==b'OK';s.sendall(b'!')
"#,
    );
    managed.read_process_ids();
    let pid = managed.child.id() as libc::pid_t;
    let mut original = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::prlimit(pid, libc::RLIMIT_NOFILE, std::ptr::null(), &mut original) },
        0
    );
    let exhausted = libc::rlimit {
        rlim_cur: 0,
        rlim_max: original.rlim_max,
    };
    assert_eq!(
        unsafe { libc::prlimit(pid, libc::RLIMIT_NOFILE, &exhausted, std::ptr::null_mut()) },
        0
    );
    managed
        .child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"exhausted\n")
        .unwrap();
    assert_eq!(managed.read_line(), "recovered next");
    assert_eq!(
        unsafe { libc::prlimit(pid, libc::RLIMIT_NOFILE, &original, std::ptr::null_mut()) },
        0
    );
    managed
        .child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"restored\n")
        .unwrap();
    assert!(managed.wait().success());
    managed.descendants.clear();
    server.join().unwrap();
}

#[test]
#[ignore = "requires Linux seccomp, user/mount namespaces, and Python 3"]
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
