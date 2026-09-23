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

| Match  | Example                                                 | Priority                                                         |
| ------ | ------------------------------------------------------- | ---------------------------------------------------------------- |
| IP     | `ip:1.1.1.1=direct`                                     | Longest prefix; first rule wins ties                             |
| CIDR   | `cidr:10.0.0.0/8=direct`                                | Longest prefix; first rule wins ties                             |
| Domain | `domain:example.com=http://127.0.0.1:8080`              | First matching domain rule; case insensitive                     |
| Regex  | `domain-regex:.*\.example\.com=socks5://127.0.0.1:1080` | First matching domain rule; regex flags control case sensitivity |

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

Listeners use the host network, including localhost and wildcard addresses.
Ports and conflicts follow normal Linux behavior.

scproxy provides read-only resolver configuration without modifying host files.
`198.18.0.1` is reserved for DNS; domain FakeIPs start at `198.18.0.2` within
`198.18.0.0/15`. IPv4 UDP/TCP queries to any address on port 53 are intercepted
before routing rules. A queries return FakeIPs, including direct domains;
other types, including AAAA, receive empty answers.

Domains are resolved when connecting: direct routes use the host resolver, while
proxy routes resolve remotely. nscd/systemd-resolved resolver sockets are blocked
to keep libc lookups on the intercepted DNS path. DoH/DoT queries are not
intercepted and their TCP connections follow normal routing.

## Implementation and connection behavior

The supervisor uses seccomp user notifications to redirect selected operations.
Numeric IP direct routes use native TCP; FakeIP and proxy routes use a local
relay. Original socket descriptors and nonblocking flags are preserved.
Ordinary `send`/`recv` calls execute directly in the kernel.

For relayed connections, successful `connect` only confirms the local connection;
upstream failures appear as EOF/reset. `getpeername` reports the requested
destination, while `getsockname` and source bindings reflect the local relay hop.
Relays close both directions after either EOF once queued data has drained;
independent half-close is unsupported. Native direct connections retain kernel
half-close behavior.

Termination signals are forwarded to the command tree with a two-second grace
period. After normal command-tree exit, pending relays have up to 32 seconds to
drain; a timeout returns an error.

## Requirements and limitations

- Linux 5.14+, native x86_64 or aarch64. GNU and musl builds are supported.
- Requires seccomp user notifications with FD injection, `pidfd_getfd`, socket
  diagnostics, and access to managed processes. Startup fails if unavailable.
- IPv4 TCP and DNS only. IPv6, non-DNS UDP, and raw Internet/packet sockets are
  unsupported.
- `io_uring` is disabled; applications need ordinary syscall fallback.
  TCP Fast Open and relayed TCP urgent data are unsupported.
- Without effective `CAP_SYS_ADMIN`, scproxy enables `no_new_privs`, preventing
  setuid elevation. An inherited `no_new_privs` flag remains set.
- Pre-existing or externally received connections are not retroactively proxied.
  scproxy is not an isolation sandbox.

## Tests

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets -- --include-ignored --test-threads=1
```

The full suite includes Linux integration tests and requires the permissions
above, Python 3, a C compiler, and static libc development files. Tests use local
fixtures and need no public Internet connection.
Capability tests also require `unshare`, user namespaces, and an unset
`no_new_privs` flag in the test runner.

GPL-3.0-only; see [LICENSE](LICENSE).
