use super::support::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

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
