//! Startup requirements and legacy descriptor access.
use super::support::*;
use std::process::Command;

const FILTER: &str = r#"
import ctypes as c, errno, json, os, platform, sys
class Instruction(c.Structure):
    _fields_=[('code',c.c_ushort),('jt',c.c_ubyte),('jf',c.c_ubyte),('k',c.c_uint)]
class Program(c.Structure):
    _fields_=[('len',c.c_ushort),('filter',c.POINTER(Instruction))]
lib=c.CDLL(None,use_errno=True)
mode=sys.argv[1]; allow=(6,0,0,0x7fff0000)
if mode=='no-namespaces':
    native=platform.machine()=='x86_64'
    os.environ['SCPROXY_ORIGINAL_NS']=json.dumps({name:os.readlink('/proc/self/ns/'+name) for name in ['mnt','user','net','pid','ipc','uts']})
    os.environ['SCPROXY_ORIGINAL_IDS']=json.dumps([os.getuid(),os.getgid()])
    instructions=[(0x20,0,0,0)]
    for number in ([272,165,166,308] if native else [97,40,39,268])+[428,429,430,431,432,442]:
        instructions += [(0x15,0,1,number),(6,0,0,0x50000|errno.EPERM)]
    instructions += [(0x15,0,1,435),(6,0,0,0x50000|errno.ENOSYS)]
    instructions += [(0x15,0,3,56 if native else 220),(0x20,0,0,16),(0x45,0,1,0x7e020080),(6,0,0,0x50000|errno.EPERM),allow]
elif mode=='no-addfd':
    instructions=[(0x20,0,0,0),(0x15,0,3,16 if platform.machine()=='x86_64' else 29),(0x20,0,0,24),(0x15,0,1,0x40182103),(6,0,0,0x50000|errno.ENOTTY),allow]
elif mode=='unavailable': instructions=[(0x20,0,0,0),(0x15,0,1,438),(6,0,0,0x50000|errno.ENOSYS),allow]
else:
    error=errno.EINVAL if mode=='legacy' else errno.EPERM
    instructions=[(0x20,0,0,0),(0x15,0,3,434),(0x20,0,0,24),(0x45,0,1,0x80),(6,0,0,0x50000|error),allow]
array=(Instruction*len(instructions))(*(Instruction(*i)for i in instructions))
program=Program(len(array),array)
assert lib.prctl(38,1,0,0,0)==0
assert lib.prctl(22,2,c.byref(program),0,0)==0
os.execvp(sys.argv[2],sys.argv[2:])
"#;
fn filtered(mode: &str, command: Command) -> Command {
    let mut result = Command::new("python3");
    result
        .args(["-c", FILTER, mode])
        .arg(command.get_program())
        .args(command.get_args());
    result
}
#[test]
#[ignore = "requires Linux seccomp, pidfd_getfd, and Python 3"]
fn missing_or_denied_capabilities_fail_before_command_exec() {
    for (mode, expected) in [
        ("unavailable", "pidfd"),
        ("denied", "Operation not permitted"),
        ("no-addfd", "ADDFD_SEND"),
    ] {
        let mut command = scproxy("direct");
        command.args(["sh", "-c", "printf 'unexpected exec'"]);
        let output = filtered(mode, command).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(expected), "{error}");
    }
}
#[test]
#[ignore = "requires Linux seccomp, pidfd_getfd, kcmp, and Python 3"]
fn legacy_pidfd_access_handles_worker_threads() {
    let mut command = scproxy("http://127.0.0.1:1");
    command.args([
        "python3",
        "-c",
        r#"
import socket,threading
errors=[]
def work():
    try: assert socket.gethostbyname('worker.invalid').startswith(('198.18.','198.19.'))
    except BaseException as error:errors.append(error)
t=threading.Thread(target=work);t.start();t.join();assert not errors,errors
"#,
    ]);
    let output = filtered("legacy", command).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires Linux seccomp ADDFD_SEND, pidfd_getfd, and Python 3"]
fn proxy_and_dns_work_with_all_namespace_creation_disabled() {
    let mut command = scproxy("http://127.0.0.1:1");
    command.args(["python3", "-c", r#"
import json,os,socket
for name,value in json.loads(os.environ['SCPROXY_ORIGINAL_NS']).items():assert os.readlink('/proc/self/ns/'+name)==value
assert [os.getuid(),os.getgid()]==json.loads(os.environ['SCPROXY_ORIGINAL_IDS'])
assert open('/etc/resolv.conf').read()=='nameserver 172.23.255.254\n'
assert socket.gethostbyname('without-namespaces.invalid').startswith(('198.18.','198.19.'))
print('no namespaces OK')
"#]);
    let output = filtered("no-namespaces", command).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"no namespaces OK\n");
}
