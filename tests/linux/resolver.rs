//! Resolver configuration, DNS wire APIs, and libc integration.
use super::support::*;

#[test]
#[ignore = "requires Linux seccomp ADDFD_SEND, pidfd_getfd, and Python 3"]
fn resolver_files_are_virtual_read_only_and_have_independent_open_offsets() {
    let original = std::fs::read("/etc/resolv.conf").unwrap();
    let nss = std::fs::read("/etc/nsswitch.conf").unwrap();
    let output = scproxy("direct")
        .args([
            "python3",
            "-c",
            r#"
import ctypes as c, errno, fcntl, mmap, os, platform, stat
expected=b'nameserver 172.23.255.254\n'
lib=c.CDLL(None,use_errno=True); lib.syscall.restype=c.c_long
openat=257 if platform.machine()=='x86_64' else 56
def opened(path, flags=os.O_RDONLY, directory=-100):
    fd=lib.syscall(openat,directory,c.c_char_p(path),flags,0)
    assert fd>=0,(path,c.get_errno())
    return fd
first=opened(b'/etc/resolv.conf');second=opened(b'/etc/resolv.conf',os.O_CLOEXEC)
assert fcntl.fcntl(first,fcntl.F_GETFD)&fcntl.FD_CLOEXEC==0
assert fcntl.fcntl(second,fcntl.F_GETFD)&fcntl.FD_CLOEXEC
assert stat.S_IMODE(os.fstat(first).st_mode)==0o444
assert fcntl.fcntl(first,fcntl.F_GET_SEALS)==15
assert os.read(first,5)==expected[:5]
assert os.read(second,4096)==expected
os.lseek(first,0,os.SEEK_SET)
with mmap.mmap(first,0,access=mmap.ACCESS_READ) as data: assert data[:]==expected
os.close(first);os.close(second)
for flags in [os.O_WRONLY,os.O_RDWR,os.O_RDONLY|os.O_TRUNC]:
    assert lib.syscall(openat,-100,c.c_char_p(b'/etc/resolv.conf'),flags,0)==-1
    assert c.get_errno()==errno.EACCES
for path in [b'/etc/./resolv.conf',os.fsencode(os.path.realpath('/etc/resolv.conf'))]:
    fd=opened(path);assert os.read(fd,4096)==expected;os.close(fd)
directory=os.open('/etc',os.O_RDONLY|os.O_DIRECTORY)
fd=opened(b'resolv.conf',directory=directory);assert os.read(fd,4096)==expected;os.close(fd)
os.chdir('/etc');fd=opened(b'resolv.conf');assert os.read(fd,4096)==expected;os.close(fd)
class How(c.Structure):_fields_=[('flags',c.c_uint64),('mode',c.c_uint64),('resolve',c.c_uint64)]
how=How(flags=os.O_RDONLY|os.O_CLOEXEC)
fd=lib.syscall(437,directory,c.c_char_p(b'resolv.conf'),c.byref(how),c.sizeof(how))
assert fd>=0,c.get_errno();assert os.read(fd,4096)==expected;os.close(fd)
how.resolve=8
assert lib.syscall(437,directory,c.c_char_p(b'resolv.conf'),c.byref(how),c.sizeof(how))==-1
assert c.get_errno()==errno.EOPNOTSUPP
os.close(directory)
assert lib.syscall(openat,-100,c.c_char_p(b'/etc/resolv.conf/'),os.O_RDONLY,0)==-1
assert c.get_errno()==errno.ENOTDIR
if platform.machine()=='x86_64':
    fd=lib.syscall(2,c.c_char_p(b'/etc/resolv.conf'),os.O_RDONLY,0)
    assert fd>=0,c.get_errno();assert os.read(fd,4096)==expected;os.close(fd)
# A valid pathname can end immediately before an unmapped page.
lib.mmap.restype=c.c_void_p
page=os.sysconf('SC_PAGE_SIZE')
region=lib.mmap(None,page*2,3,0x22,-1,0)
assert region not in (None,c.c_void_p(-1).value)
assert lib.munmap(c.c_void_p(region+page),page)==0
path=b'/etc/resolv.conf\0';pointer=region+page-len(path);c.memmove(pointer,path,len(path))
fd=lib.syscall(openat,-100,c.c_void_p(pointer),os.O_RDONLY,0)
assert fd>=0,c.get_errno();assert os.read(fd,4096)==expected;os.close(fd)
assert lib.munmap(c.c_void_p(region),page)==0
hosts=[line for line in open('/etc/nsswitch.conf') if line.split(':',1)[0].strip()=='hosts']
assert hosts==['hosts: files dns\n'],hosts
print('virtual resolver OK')
"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"virtual resolver OK\n");
    assert_eq!(std::fs::read("/etc/resolv.conf").unwrap(), original);
    assert_eq!(std::fs::read("/etc/nsswitch.conf").unwrap(), nss);
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn dns_server_addresses_and_udp_tcp_queries_are_intercepted() {
    let output = scproxy("http://127.0.0.1:1").args(["python3", "-c", &format!("{SOCKET_API}\n{}", r#"
import socket,struct
servers=[('203.0.113.53',53),('127.0.0.53',53)]
def query(name):
    return b'\x12\x34\x01\x00\x00\x01'+b'\x00'*6+b''.join(bytes([len(label)])+label.encode() for label in name.split('.'))+b'\0\0\1\0\1'
def check(answer,request):
    assert answer[:2]==request[:2] and answer[7]==1
    assert answer[12:len(request)]==request[12:]
    assert answer[-4]==198 and answer[-3] in (18,19)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3)
requests={server:query('server%d.invalid'%i) for i,server in enumerate(servers)}
# Identical transaction IDs on a single unconnected socket must not confuse sources.
for server,request in requests.items():s.sendto(request,server)
seen=set()
for _ in servers:
    answer,server=s.recvfrom(4096);assert server in requests;check(answer,requests[server]);seen.add(server)
assert seen==set(servers)
for server in servers:
    s.connect(server);assert s.getpeername()==peer_name(s)==server
    s.send(query('connected.invalid'));answer,source=s.recvfrom(4096);assert source==server;check(answer,query('connected.invalid'))
s.close()
def exact(s,n):
    data=b''
    while len(data)<n:
        part=s.recv(n-len(data));assert part;data+=part
    return data
for server in servers:
    s=socket.create_connection(server,timeout=3);assert s.getpeername()==peer_name(s)==server
    check_oob_rejected(s)
    for name in ['tcp.invalid','second.invalid']:
        request=query(name);frame=struct.pack('!H',len(request))+request
        s.sendall(frame[:1]);s.sendall(frame[1:7]);s.sendall(frame[7:])
        answer=exact(s,struct.unpack('!H',exact(s,2))[0]);check(answer,request)
    s.close()
"#)]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn host_resolver_unix_sockets_are_refused_but_application_ipc_works() {
    let output = scproxy("direct").args(["python3", "-c", r#"
import errno,os,socket,tempfile
for path in ['/run/nscd/socket','/var/run/nscd/socket','/run/systemd/resolve/io.systemd.Resolve']:
    s=socket.socket(socket.AF_UNIX)
    try:s.connect(path);raise AssertionError('resolver IPC was allowed')
    except OSError as error:assert error.errno==errno.ECONNREFUSED,error
    finally:s.close()
with tempfile.TemporaryDirectory() as directory:
    path=directory+'/app.sock';server=socket.socket(socket.AF_UNIX);server.bind(path);server.listen()
    client=socket.socket(socket.AF_UNIX);client.connect(path);peer,_=server.accept()
    client.sendall(b'IPC');assert peer.recv(3)==b'IPC';peer.close();client.close();server.close()
"#]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires Linux seccomp, a C compiler, and static libc"]
fn static_binary_dns_abi_and_readiness() {
    let temp = TestDir::new("dns");
    let binary = temp.0.join("dns");
    compile_c_fixture("tests/fixtures/dns.c", &binary, &["-static", "-pthread"]);
    let output = scproxy("http://127.0.0.1:1").arg(&binary).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"DNS ABI OK\n");
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn libc_resolves_ipv4_and_empty_ipv6_over_udp_and_tcp() {
    for options in ["", "use-vc"] {
        let output = scproxy("http://127.0.0.1:1")
            .env("RES_OPTIONS", options)
            .args(["python3", "-c", r#"
import socket, threading
errors = []
def query(index):
    try:
        result = socket.getaddrinfo('unique-%d.invalid' % index, 443, 0, socket.SOCK_STREAM)
        assert result and all(item[0] == socket.AF_INET and item[4][0].startswith(('198.18.', '198.19.')) for item in result)
    except BaseException as error:
        errors.append(error)
threads = [threading.Thread(target=query, args=(i,)) for i in range(4)]
for thread in threads: thread.start()
for thread in threads: thread.join()
assert not errors, errors
"#])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{options}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
