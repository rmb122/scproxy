# Project Guidelines

## Engineering and Communication

1. Follow KISS and YAGNI. Keep solutions simple and avoid unnecessary code or abstractions.
2. Keep code modular and organize it by functionality. Avoid files containing thousands of lines.
3. Group tests for the same functionality by scenario, give each test layer a clear responsibility, reuse shared fixtures and helpers, and avoid duplicate coverage. When moving tests, update test configuration, type-checking scope, and documentation together.
4. When fixing a bug, identify and explain its root cause, fix it in the module responsible for the behavior, and add necessary regression tests covering the actual triggering scenario.
5. Use Chinese only when communicating with the user, including progress updates, reports, root cause explanations, and validation results. Clearly describe what changed, why it changed, and the results of checks actually performed.
6. Use English for code comments and Git commit messages, including both the subject and body.
7. Use ASCII punctuation and symbols instead of Chinese or full-width punctuation and symbols, including in Chinese replies to the user.

## TCP Closure Semantics (Explicit User Requirement)

Outbound TCP relays terminate the entire forwarding connection after either direction reaches EOF or half-closes, subject to the existing buffer-drain conditions. Keeping the other direction open independently after a half-close is intentionally unsupported.

- Outbound forwarding (`src/broker/relay.rs`): EOF from the application or upstream triggers the existing `close_after_drain` logic. Preserve its current conditions: `to_application` and `to_host` are empty, and the application-facing relay socket's `TIOCOUTQ` and `FIONREAD` queues are empty. Once these conditions are met, drop both streams without waiting for future responses from the other direction. Do not expand these conditions to require draining the upstream socket's unread receive queue after application EOF.
- Implementation terminology (`src/broker/engine.rs`, `src/broker/tcp.rs`): This project uses native TCP streams rather than smoltcp sockets. Dropping both streams after the drain conditions closes the forwarding connection. Tokio `JoinHandle::abort()` cancels a task; it is not the smoltcp socket `abort()` operation mentioned in the reference project's guidelines. Review task cancellation separately from the relay's EOF handling.
- Native host networking: Host listeners, loopback TCP connections, and direct TCP routes use native kernel behavior, including half-close. Direct routes return real DNS addresses and let the application's original socket connect in the kernel. This project has no published-port forwarding path; do not add interception of native half-close behavior to enforce the relay policy on native connections.

Code changes, refactors, and reviews must respect this policy:

- RSTs during this closure process and the inability to receive later responses after a half-close are expected behaviors accepted by the user. Do not report these behaviors alone as defects.
- Unless the user explicitly changes this requirement, do not introduce independent per-direction closure states, FIN propagation, or half-close support for the outbound relays.
- Preserve the existing buffer-drain conditions. This policy applies only to closure semantics. Other data integrity issues, such as losing prefetched tunnel data after an HTTP CONNECT response, remain subject to normal review.
