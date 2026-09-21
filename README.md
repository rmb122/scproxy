# scproxy

Run Linux programs through SOCKS5 or HTTP CONNECT using **seccomp user
notifications**. The program and its descendants keep the host network namespace.
No TUN device, user-space TCP/IP stack, libseccomp, or LD_PRELOAD is used.
Statically linked programs work too.

```sh
cargo build --release
./target/release/scproxy -x socks5://127.0.0.1:1080 curl https://example.com
./target/release/scproxy -x http://user:pass@proxy:8080 wget https://example.com
./target/release/scproxy -x direct -r domain:example.com=socks5://127.0.0.1:1080 curl https://example.com
./target/release/scproxy -x socks5://127.0.0.1:1080 -r cidr:10.0.0.0/8=direct ssh server
./target/release/scproxy -x direct -b ./custom.conf:/etc/example.conf my-command
```

## Usage

```text
scproxy [OPTIONS] <COMMAND>...

-x, --proxy <PROXY>   Required default route
-r, --rule <RULE>     Routing rule, repeatable
-b, --bind <SRC:DST>  File bind mount, repeatable
-v, --verbose        Debug logging; repeat for trace logging
-h, --help           Print help
-V, --version        Print version
```

Routes accept `direct`, `socks5://[user:pass@]host:port` (also `socks://`), and
`http://[user:pass@]host:port`. Options after the command name belong to the
command. Proxy server names are resolved by the supervisor using the host
resolver. The 32-second upstream timeout includes resolution, TCP setup, and
proxy authentication/handshake.

Routing rules use `MATCH=ROUTE`:

| Match | Example | Priority |
| --- | --- | --- |
| IP | `ip:1.1.1.1=direct` | Longest prefix; first rule wins ties |
| CIDR | `cidr:10.0.0.0/8=direct` | Longest prefix; first rule wins ties |
| Domain | `domain:example.com=http://127.0.0.1:8080` | First matching domain rule; case insensitive |
| Regex | `domain-regex:.*\.example\.com=socks5://127.0.0.1:1080` | First matching domain rule; regex flags control case sensitivity |

Domain rules apply to names recovered from fake DNS. Numeric destinations use
IP/CIDR rules. A `direct` domain route opts in to host-side DNS resolution.
IPv4 loopback (`127.0.0.0/8`) always connects directly to the host and bypasses
these rules.

## Host networking and DNS

Listening sockets bind directly on the host, including wildcard listeners.
Ports, conflicts, incoming peer addresses, and listener lifetimes follow native
Linux behavior. There is **no private localhost**, port publishing, port
remapping, or `--host-forward` option.

A private mount namespace provides `resolv.conf` pointing at the virtual resolver
`172.23.255.254` and `nsswitch.conf` containing `hosts: files dns`. Seccomp redirects
UDP requests for that resolver to an unprivileged loopback DNS service in the
supervisor. No host port 53 reservation or interface configuration is needed.
A queries receive fake addresses from `198.18.0.0/15`; other question types,
including AAAA, receive empty answers. DNS mappings are bounded and reuse the
oldest addresses when the pool wraps, as in nsproxy-rs.

Connecting to a fake address recovers its domain for the proxy's remote
resolution. DNS via the configured fake resolver is answered locally; UDP to
other destinations, including other DNS servers, is rejected. Programs using
their own DNS-over-HTTPS/TLS send ordinary proxied TCP connections and do not
participate in fake-IP domain routing. Pre-existing host resolver caches or
external resolver services accessed over Unix sockets are outside fake DNS.

## File mounts

Both `--bind` paths are relative to the launch directory unless absolute. They
must name regular files or symbolic links; dangling symlinks are allowed.
Symlink objects are mounted without following their targets. Relative link text
is preserved and resolves relative to the destination's parent directory.

Mounts are writable. Directories, `:ro` suffixes, duplicate targets, and overrides
of `/etc/resolv.conf` or `/etc/nsswitch.conf` are rejected. Host mount tables are
unchanged. Identical readable DNS mounts inherited from a launcher that already
unlinked its temporary configuration files are reused.

## Implementation and connection behavior

The unfiltered supervisor receives notifications from the command's inherited
seccomp filter. It accesses the notifying thread's descriptors through
`pidfd_getfd` and copies syscall arguments through `process_vm_readv/writev`.
The listener itself is obtained through pidfd after a `read/write` bootstrap;
there is no exempt descriptor number that an application could later reuse.

For outbound IPv4 TCP, the supervisor connects a duplicate of the **original
socket** to a shared local relay, then connects the upstream route. Each scproxy
instance keeps one dynamically allocated `127.0.0.1` TCP listener for its entire
lifetime. Accepted connections are dispatched by source IP and port to registered
application sockets; unrelated connections are closed. The accept loop runs
independently of local connects and upstream handshakes. It never
replaces the application's descriptor or changes its `O_NONBLOCK` flag.
Existing dup/fork/epoll references keep their identity. `getpeername` reports the
requested destination; `getsockname` reports the actual local relay connection.
Native local connection setup has a 32-second deadline. If the notifying call is
cancelled or times out, the supervisor disconnects the pending socket and waits
for its blocking worker to stop, without changing the socket's file status flags.
Explicit source binding applies to that local connection, not the upstream leg.
Because all relayed connections share one local destination, simultaneous sockets
bound to the same source IP and port cannot connect to different upstream targets.
Socket-cookie metadata is reclaimed using periodic socket diagnostics.

A successful `connect` or writable event means the local relay connected. A
subsequent upstream failure appears as EOF/reset, rather than the upstream's
original connect errno. Proxy handshake bytes never reach the application;
prefetched tunnel data is preserved. Relays use bounded buffers and terminate
both directions after either EOF, once queued data has drained. Independent
half-close support and waiting for later responses after half-close are
intentionally unsupported. Native host localhost connections retain kernel
closure semantics.

DNS supports connected and unconnected UDP, scatter/gather and batched messages,
peek/truncation, timeouts, and kernel poll/epoll readiness. Blocking DNS receives
are asynchronous in the broker and do not prevent another thread from sending.
Pending requests and upstream handshakes are bounded; overload returns an error
for the affected request. Descriptor exhaustion can recover without restarting
the command tree.

SIGTERM, SIGINT, and SIGHUP are forwarded to the command and its descendants,
including detached descendants. The reaper waits for them after the original
command exits. Termination has a two-second grace period; later signals do not
extend it. Loss of the supervisor also triggers command-tree termination.

After the command tree exits normally, pending proxy handshakes and relays get up
to 32 seconds to finish under the existing EOF/drain rules. The shared TCP accept
loop stays active during this wait. A drain timeout is reported as an error;
termination signals can interrupt the wait immediately. Signal-driven shutdown
does not add this drain period to the command tree's termination grace period.

## Requirements and limitations

- Linux 5.6 or newer, native x86_64 or aarch64. GNU and musl builds are supported.
- Seccomp user notification, `pidfd_getfd`, socket diagnostics, and permission to
  read/write managed process memory. These interfaces are probed before exec;
  missing permissions cause a startup error, with no unproxied fallback.
- A mount namespace is always used for DNS and optional file mounts. Unprivileged
  use requires enabled user namespaces. On systems restricting user namespaces
  through AppArmor or container policies, those policies must permit the tool.
- `PIDFD_THREAD` is preferred. Older kernels use a process pidfd and
  `kcmp(KCMP_FILE)`; that fallback cannot support private thread FD tables or a
  thread group whose leader has already exited. Permission errors do not select
  the fallback.
- IPv4 TCP and internal UDP DNS only. IPv6 and raw Internet/packet sockets are
  rejected. Unix sockets and netlink remain available.
- `io_uring_setup`, `io_uring_enter`, and `io_uring_register` return `ENOSYS`.
  Programs must support ordinary syscall fallback. TCP Fast Open sends return
  `EOPNOTSUPP`. 32-bit compatibility ABIs and x32 are unsupported.
- `no_new_privs` applies to the command tree; setuid privilege elevation is
  unavailable. Network connections established before launch or received from
  another process are not retroactively proxied. This is a transparent proxy
  launcher, not a general isolation sandbox.

## Tests

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo test -- --ignored --test-threads=1
```

Ignored tests exercise real kernel interfaces. They require the permissions
above, Python 3, `unshare`, `mount`, a C compiler, and static libc development
files. Tests use local proxy fixtures and need no public Internet connection.
Their private `/etc` fixtures do not change host files. Coverage includes proxy
protocols, DNS ABIs in a static executable, dup/fork/epoll, backpressure and EOF,
file/symlink mounts, permission failures, resource exhaustion, and lifecycle.

## Origin and license

Based on the local **nsproxy-rs** implementation, reusing its proxy protocols,
routing, fake DNS, mount handling, process reaper, and parts of its seccomp host
forwarding support. nsproxy-rs was inspired by
[nsproxy by NaLan ZeYu](https://github.com/nlzy/nsproxy).

GPL-3.0-only; see [LICENSE](LICENSE).
