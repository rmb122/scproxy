use super::support::*;
use std::process::Command;

const FILTER: &str = r#"
import ctypes as c, errno, os, sys
class Instruction(c.Structure):
    _fields_=[('code',c.c_ushort),('jt',c.c_ubyte),('jf',c.c_ubyte),('k',c.c_uint)]
class Program(c.Structure):
    _fields_=[('len',c.c_ushort),('filter',c.POINTER(Instruction))]
lib=c.CDLL(None,use_errno=True)
mode=sys.argv[1]; allow=(6,0,0,0x7fff0000)
if mode=='unavailable': instructions=[(0x20,0,0,0),(0x15,0,1,438),(6,0,0,0x50000|errno.ENOSYS),allow]
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
#[ignore = "requires Linux seccomp, pidfd_getfd, user/mount namespaces, and Python 3"]
fn unavailable_and_denied_interfaces_fail_before_command_exec() {
    for mode in ["unavailable", "denied"] {
        let mut command = scproxy("direct");
        command.args(["sh", "-c", "printf 'unexpected exec'"]);
        let output = filtered(mode, command).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("pidfd"), "{error}");
        if mode == "denied" {
            assert!(error.contains("Operation not permitted"), "{error}");
        }
    }
}
#[test]
#[ignore = "requires Linux seccomp, pidfd_getfd, kcmp, user/mount namespaces, and Python 3"]
fn legacy_pidfd_access_handles_worker_threads() {
    let mut command = scproxy("direct");
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
