//! Domain relay routing, native numeric direct TCP, and host resolution lifecycle.
use super::support::*;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn fake_domains_with_shared_real_addresses_do_not_override_numeric_routes() {
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
            for index in 0..4 {
                let host = if index % 2 == 0 {
                    "localhost"
                } else {
                    "127.0.0.1"
                };
                let mut connection = tunnel(proxy.try_clone().unwrap(), &format!("{host}:{port}"));
                connection.write_all(b"PROXY").unwrap();
                let mut ack = [0];
                connection.read_exact(&mut ack).unwrap();
                assert_eq!(&ack, b"!");
            }
        });
        let mut command = scproxy(if default_direct { "direct" } else { &route });
        command.args(["-r", &format!("ip:127.0.0.1={route}")]);
        if default_direct {
            command.args(["-r", &format!("domain:localhost={route}")]);
        } else {
            command.args(["-r", "domain:127.0.0.1=direct"]);
        }
        let script = format!(
            "{DNS_API}\n{SOCKET_API}\n{}",
            r#"
import os
port=int(os.environ['PORT'])
# Both names identify the same host address, but retain independent FakeIPs.
# Numeric host NSS input keeps this test independent of external DNS.
for tcp in [False, True]:
    direct=dns_lookup('127.0.0.1',tcp)
    proxy=dns_lookup('localhost',tcp)
    for records in [direct,proxy]:
        assert len(records)==1 and records[0][0].startswith(('198.18.','198.19.')),records
        assert records[0][1]==300,records
    assert direct[0][0]!=proxy[0][0]
    assert dns_lookup('localhost',tcp,28)==[]
    for ip,expected in [(direct[0][0],b'DIRECT'),(proxy[0][0],b'PROXY'),('127.0.0.1',b'PROXY')]:
        with socket.create_connection((ip,port),timeout=3) as connection:
            assert connection.getpeername()==peer_name(connection)==(ip,port)
            check_oob_rejected(connection)
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
    for mode in ["default", "ip"] {
        let mut command = scproxy(if mode == "default" {
            "direct"
        } else {
            "http://127.0.0.1:1"
        });
        if mode == "ip" {
            command.args(["-r", &format!("cidr:{ip}/32=direct")]);
        }
        let script = format!(
            "{DNS_API}\n{SOCKET_API}\n{}",
            r#"
import fcntl,os,select
ip=os.environ['IP']
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

#[cfg(target_env = "gnu")]
#[test]
#[ignore = "requires a dynamic GNU build, Linux seccomp, Python 3, and a C compiler"]
fn slow_direct_resolution_does_not_block_connect_drain_or_shutdown() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let temp = TestDir::new("host-lookup");
    let preload = temp.0.join("lookup.so");
    compile_c_fixture(
        "tests/fixtures/host_lookup.c",
        &preload,
        &["-shared", "-fPIC", "-ldl"],
    );
    for mode in ["drain", "failure", "cancel"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let ready = temp.0.join(format!("{mode}-ready"));
        let release = temp.0.join(format!("{mode}-release"));
        let mut command = Command::new("python3");
        command.args(["-c", "import os,sys;os.environ['SCPROXY_TEST_RESOLVER_PID']=str(os.getpid());os.execv(sys.argv[1],sys.argv[1:])"])
            .arg(env!("CARGO_BIN_EXE_scproxy")).args(["-x","direct"])
            .env("LD_PRELOAD",&preload)
            .env("SCPROXY_TEST_RESOLVER_READY",&ready)
            .env("SCPROXY_TEST_RESOLVER_RELEASE",&release)
            .env("SCPROXY_TEST_MODE",mode).env("PORT",port.to_string())
            .stdin(Stdio::piped());
        let script = format!(
            "{DNS_API}\n{}",
            r#"
import errno,os,select,sys,time
print(os.getppid(),os.getpid(),flush=True)
answer=dns_lookup('slow-direct.invalid')
assert answer[0][0].startswith(('198.18.','198.19.'))
print('DNS ready',flush=True)
assert sys.stdin.readline().strip()=='connect'
client=socket.socket();client.setblocking(False)
started=time.monotonic()
assert client.connect_ex((answer[0][0],int(os.environ['PORT']))) in (0,errno.EINPROGRESS)
assert time.monotonic()-started<2,'nonblocking connect waited for DNS'
assert select.select([], [client], [], 2)[1]
assert client.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)==0
print('connect ready',flush=True)
client.settimeout(3)
if os.environ['SCPROXY_TEST_MODE']=='drain':
    client.sendall(b'PAYLOAD');client.close()
elif os.environ['SCPROXY_TEST_MODE']=='failure':
    try:assert client.recv(1)==b''
    except ConnectionResetError:pass
else:
    sys.stdin.readline()
"#
        );
        let mut managed = ManagedChild::spawn_with_command(command, &script);
        managed.read_process_ids();
        assert_eq!(managed.read_line(), "DNS ready");
        assert!(!ready.exists(), "DNS query must not start a host lookup");
        managed
            .child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"connect\n")
            .unwrap();
        assert_eq!(managed.read_line(), "connect ready");
        let deadline = Instant::now() + Duration::from_secs(3);
        while !ready.exists() {
            assert!(Instant::now() < deadline, "host resolver did not start");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            listener.accept().is_err(),
            "upstream connected before DNS completed"
        );
        if mode == "drain" {
            let command_pid = managed.descendants[1];
            while std::path::Path::new(&format!("/proc/{command_pid}")).exists() {
                assert!(
                    Instant::now() < deadline,
                    "command did not exit before DNS completed"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(
                managed.child.try_wait().unwrap().is_none(),
                "broker must drain the pending lookup"
            );
            std::fs::write(&release, b"go").unwrap();
            let mut upstream = accept_with_timeout(listener);
            let mut payload = [0; 7];
            upstream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"PAYLOAD");
            drop(upstream);
            assert!(managed.wait().success());
        } else if mode == "failure" {
            std::fs::write(&release, b"go").unwrap();
            assert!(managed.wait().success());
            assert!(listener.accept().is_err());
        } else {
            kill(Pid::from_raw(managed.child.id() as i32), Signal::SIGTERM).unwrap();
            assert_eq!(
                managed.wait_timeout(Duration::from_secs(4)).code(),
                Some(143)
            );
            for pid in &managed.descendants {
                assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
            }
        }
        managed.descendants.clear();
    }
}
