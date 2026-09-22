# scproxy

Run Linux programs through SOCKS5 or HTTP CONNECT using **seccomp user
notifications**. The command inherits the launcher's existing namespaces and
user/group IDs; scproxy creates no user, mount, or network namespaces.
No TUN device, user-space TCP/IP stack, libseccomp, or LD_PRELOAD is used.
Statically linked programs work too.

```sh
cargo build --release
./target/release/scproxy -x socks5://127.0.0.1:1080 curl https://example.com
./target/release/scproxy -x http://user:pass@proxy:8080 wget https://example.com
./target/release/scproxy -x direct -r domain:example.com=socks5://127.0.0.1:1080 curl https://example.com
./target/release/scproxy -x socks5://127.0.0.1:1080 -r cidr:10.0.0.0/8=direct ssh server
```

## Usage

```text
scproxy [OPTIONS] <COMMAND>...

-x, --proxy <PROXY>   Required default route
-r, --rule <RULE>     Routing rule, repeatable
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

Domain rules apply to names recovered when connecting to FakeIPs, falling back
to `-x`. The selected route resolves the domain when establishing its upstream
connection. A direct domain's real addresses are used only for that connection;
they do not grant direct access to other domains or numeric connections.

Numeric destinations first use explicit IP/CIDR rules. Without a matching rule,
`0.0.0.0` and `127.0.0.0/8` default to direct; other addresses use `-x`.
For example, `-r cidr:127.0.0.0/8=socks5://proxy.example:1080` sends loopback
destinations through that proxy. `-r ip:0.0.0.0=http://proxy.example:8080` overrides
the zero address separately. Addresses are matched and sent to the selected
route as requested: `0.0.0.0` is never rewritten to `127.0.0.1`.
On a proxy route, loopback addresses refer to the proxy server's host.

## Host networking and DNS

Listening sockets bind directly on the host, including wildcard listeners.
Ports, conflicts, incoming peer addresses, and listener lifetimes follow native
Linux behavior. There is **no private localhost**, port publishing, port
remapping, or `--host-forward` option.

Seccomp supplies a read-only `resolv.conf` pointing at the virtual resolver
`172.23.255.254` and an `nsswitch.conf` whose `hosts` line is `files dns`; other NSS
databases retain the host configuration. Opening these standard paths (including
relative spellings and their resolved symlink targets) returns sealed memory-file
descriptors through atomic `SECCOMP_IOCTL_NOTIF_ADDFD`. Each open has its own file
offset. Host configuration files are never modified, and there are no bind mounts
or `-b`/`--bind` options.

Both UDP and TCP queries to any IPv4 address on port 53 are answered by the local
resolver, including queries addressed to `127.0.0.53`. No host port 53
reservation or interface configuration is needed. Replies report the originally
requested DNS server; overlapping UDP requests to different servers remain
separate even with the same transaction ID. All A queries receive a synthetic
address from `198.18.0.0/15` with a 300-second TTL, including direct domains.
DNS queries do not trigger host resolution. Other types, including AAAA, receive
empty answers. FakeIP mappings reuse the oldest addresses when the pool wraps.
Connections to unmapped addresses in the synthetic pool fail with `ENETUNREACH`.

FakeIP domain connections always use the local relay. Direct domains are resolved
in the background using host NSS, including its hosts file, and connected to a
real IPv4 address. Proxy domains are sent to the proxy for remote resolution.
Unknown domains still receive FakeIPs; resolution failures are observed when
connecting, as EOF/reset from the relay. Up to 32 direct host resolver calls run
at once, each with a five-second timeout. Timed-out calls retain their worker
slot until they finish, and do not hold up supervisor shutdown. Resolved IPv4
addresses are tried in order within the overall 32-second upstream timeout.

The supervisor supports up to 128 distinct UDP resolver endpoints per run.
Other UDP ports are rejected. IPv4 UDP/TCP port 53 is handled before all routing
rules, including explicit zero/loopback proxy rules. Programs using
DNS-over-HTTPS/TLS send ordinary routed TCP connections and do not participate in
fake-IP domain routing.

Connections to the nscd resolver socket and the systemd-resolved NSS socket are
refused so standard libc lookups cannot hand resolution to those host services.
Other application Unix sockets remain available. Applications that require a
resolver's Unix IPC protocol without a DNS fallback are unsupported.

Configuration virtualization applies to `open`, `openat`, and `openat2`;
path-based `stat` and `readlink` retain host results. Resolver configuration writes
are rejected. `openat2` resolution constraints on these virtual files return
`EOPNOTSUPP` instead of silently ignoring the constraints. Ordinary file opens
continue in the kernel; reads and mappings of injected files also use native
kernel operations.

## Implementation and connection behavior

The unfiltered supervisor receives notifications from the command's inherited
seccomp filter. It accesses the notifying thread's descriptors through
`pidfd_getfd` and copies syscall arguments through `process_vm_readv/writev`.
The listener itself is obtained through pidfd after a `read/write` bootstrap;
there is no exempt descriptor number that an application could later reuse.

Numeric IPv4 TCP destinations selecting direct continue the application's original
`connect` in the kernel. There is no local relay or second socket: connect errors,
nonblocking readiness, source bindings, socket options and half-close use native
TCP behavior. This includes zero/loopback destinations without an overriding
proxy rule; the kernel retains its native zero-address and source-binding behavior.

All FakeIP domain connections and numeric proxy routes connect a duplicate of
the **original socket** to a shared local relay, which then connects the upstream
route. Direct domains wait for real resolution only in the relay, so their
application-side nonblocking connect does not wait for DNS. Each scproxy
instance keeps one dynamically allocated `127.0.0.1` TCP listener for its entire
lifetime. Accepted connections are dispatched by source IP and port to registered
application sockets; unrelated connections are closed. The accept loop runs
independently of local connects and upstream handshakes. It never
replaces the application's descriptor or changes its `O_NONBLOCK` flag.
Existing dup/fork/epoll references keep their identity. `getpeername` and
`getsockopt(SOL_SOCKET, SO_PEERNAME)` report the requested destination, including
the original server for connected UDP DNS. `getsockname` reports the actual
local relay connection.
Native local connection setup has a 32-second deadline. If the notifying call is
cancelled or times out, the supervisor disconnects the pending socket and waits
for its blocking worker to stop, without changing the socket's file status flags.
Explicit source binding applies to that local connection, not the upstream leg.
Because all relayed connections share one local destination, simultaneous sockets
bound to the same source IP and port cannot connect to different upstream targets.
Socket-cookie metadata is reclaimed using periodic socket diagnostics.

For these relayed connections, a successful `connect` or writable event means
the local relay connected. A subsequent upstream failure appears as EOF/reset,
rather than the upstream's original connect errno. Proxy handshake bytes never
reach the application; prefetched tunnel data is preserved. Relays use bounded
buffers and terminate both directions after either EOF, once queued data has
drained. Independent half-close support and waiting for later responses after half-close are
intentionally unsupported, including for direct domains. Numeric direct routes
and host listeners retain kernel closure semantics.

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

- Linux 5.14 or newer, native x86_64 or aarch64. GNU and musl builds are supported.
- Seccomp user notification with atomic FD injection (`ADDFD_SEND`),
  `pidfd_getfd`, socket diagnostics, and permission to read/write managed process
  memory. These interfaces are probed before exec;
  missing permissions cause a startup error, with no unproxied fallback.
- No namespace creation, UID/GID mappings, or mount privileges are needed.
- `PIDFD_THREAD` is preferred. Older kernels use a process pidfd and
  `kcmp(KCMP_FILE)`; that fallback cannot support private thread FD tables or a
  thread group whose leader has already exited. Permission errors do not select
  the fallback.
- IPv4 TCP and IPv4 UDP/TCP DNS only. IPv6 and raw Internet/packet sockets are
  rejected. Unix sockets (except the resolver shortcuts above) and netlink remain
  available.
- `io_uring_setup`, `io_uring_enter`, and `io_uring_register` return `ENOSYS`.
  Programs must support ordinary syscall fallback. TCP Fast Open sends return
  `EOPNOTSUPP`. 32-bit compatibility ABIs and x32 are unsupported.
- TCP urgent data is unsupported by the relays. `MSG_OOB` sends and receives on
  relayed TCP connections, including TCP DNS, return `EOPNOTSUPP`. Native host
  connections retain their kernel urgent-data behavior.
- `no_new_privs` applies to the command tree; setuid privilege elevation is
  unavailable. Network connections established before launch or received from
  another process are not retroactively proxied. This is a transparent proxy
  launcher, not a general isolation sandbox.

## Tests

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --bin scproxy
cargo test --bin scproxy -- --ignored --test-threads=1
cargo test --test linux -- --ignored --test-threads=1
```

Unit tests live beside their implementation in `#[cfg(test)] mod tests`. They
cover routing, DNS mapping and packet handling, and deterministic regressions
for protocol handshakes, connection races, and cancellation. Kernel-backed unit
tests are marked ignored and run separately.

The single `linux` integration target groups essential behavior into
`capabilities`, `network`, `resolver`, `direct`, `outbound`, and `lifecycle`
scenarios. Shared helpers live in `tests/linux/support.rs` and `tests/fixtures/`.
Integration tests cover proxy and DNS operation, domain/IP route isolation,
overridable local defaults, slow direct resolution, static programs, descriptor
identity, peer addresses, urgent-data rejection, backpressure and EOF, startup
failures, and command-tree cleanup. These tests require the permissions above,
Python 3, a C compiler, and static libc development files. They use local proxy
fixtures and need no public Internet connection or namespace creation. The slow
NSS integration fixture uses `LD_PRELOAD` with dynamic GNU builds; resolver
timeout/cancellation unit tests also run on musl.

GPL-3.0-only; see [LICENSE](LICENSE).
