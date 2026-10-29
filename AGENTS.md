# AGENTS.md

## Scope

These instructions apply to the entire repository. A more deeply nested `AGENTS.md`, if added later, takes precedence for files below its directory. Explicit user instructions take precedence over this file.

## Project overview

Wispdeck is a self-hosted Wisp v2.0 TCP proxy with a server-rendered administration interface. It is one Rust application with no database, Node.js toolchain, SPA, Docker socket access, or message broker.

The application uses:

- Rust 2024, Tokio, and Axum.
- Askama templates and minimal embedded CSS.
- Serde and TOML persistence under `/data`.
- Argon2id for administrator and Wisp-user password hashes.
- `tracing` for stdout/stderr logging.
- A pinned `wisp-mux` Git revision for the initial protocol backend.
- Podman as the documented and verified container CLI.

Read `README.md` and `config.example.toml` before changing deployment behavior, configuration, authentication, or protocol support.

## Repository map

- `src/main.rs`: CLI entry point and explicit administrator password-reset command.
- `src/app.rs`: application assembly, routes, listener, and graceful shutdown.
- `src/core/`: protocol-independent runtime state, sessions, identities, and metrics.
- `src/protocol/backend.rs`: replaceable protocol backend interface.
- `src/protocol/wisp_mux/`: the only module allowed to import or expose `wisp-mux` types.
- `src/proxy/`: DNS resolution, destination policy, exact-address dialing, and TCP forwarding.
- `src/auth/`: separate administrator and Wisp-user authentication.
- `src/admin/`: authenticated routes, forms, sessions, and server-rendered administration pages.
- `src/config/`: schema, validation, atomic TOML storage, and permissions.
- `templates/`: Askama HTML templates.
- `static/`: small static assets embedded into the binary.
- `.github/workflows/`: Rust checks, Podman builds, and trusted multi-architecture publishing.

## Build and test commands

Use locked dependencies for reproducibility:

```sh
cargo check --locked
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo build --release --locked
podman build --format docker --tag wispdeck:verify --file Containerfile .
```

Run focused tests while iterating, then run the complete applicable checks before finishing. Tests must use local fixtures and must not contact public SMTP, IMAP, DNS, or arbitrary Internet services.

For local development:

```sh
mkdir -p ./data
WISPDECK_DATA_DIR=./data WISP_ADMIN_PASSWORD='a strong development password' cargo run --locked -- serve
```

The default listener is `127.0.0.1:8080`. Secure admin cookies are enabled by default and are not sent by browsers over plain HTTP. Set `admin.secure_cookie = false` only for loopback HTTP development; never make that the production default.

## Dependency rules

- Keep dependencies minimal and justify additions.
- Commit `Cargo.lock`; CI and container builds use `--locked`.
- Do not replace or float the pinned `wisp-mux` dependency. Its required revision is `9cde724aea1a0f5e46b1c962b3d19ca1389af074`.
- Consult source code at the pinned revision before using or changing a `wisp-mux` API. Do not rely on older crates.io documentation.
- Do not add a database, Node.js, npm, a JavaScript build step, a heavyweight frontend framework, or Docker socket integration.

## Architecture boundaries

- Keep all `wisp-mux` imports and concrete packet, stream, extension, and multiplexor types inside `src/protocol/wisp_mux/`.
- Core, proxy, authentication, configuration, and administration code must remain usable with a mock or replacement `ProtocolBackend`.
- The proxy layer must not depend on a concrete Wisp implementation.
- Administration routes must call core/auth/config services rather than manipulating protocol-library objects.
- Prefer the smallest correct change. Add abstractions only where they preserve these boundaries or remove real duplication.

## Protocol invariants

- The Wisp endpoint is exactly `/wisp/`; preserve the trailing slash.
- Require `Sec-WebSocket-Protocol` and authenticated Wisp v2 negotiation.
- Reject Wisp v1, authentication omission, invalid passwords, and v2-to-v1 downgrade attempts.
- Password extension `0x02` is required. Its custom verifier must retain strict metadata bounds checks and verify Argon2id hashes rather than pass hashes to the upstream plaintext verifier.
- Do not store Wisp passwords in plaintext or expose existing passwords through the UI or logs.
- TCP is the only supported stream type. Reject UDP and unknown stream types, and do not advertise UDP.
- Do not claim complete Wisp v2.1 support. The pinned backend advertises v2.0 and does not implement stream-open confirmation extension `0x05`.
- Preserve bounded flow control, stream/client/dial limits, cancellation, half-close behavior, and cleanup.
- Add protocol tests for handshake, authentication, malformed input, closure, or stream behavior whenever those paths change.

## Network security invariants

- Defaults allow outbound TCP ports 465, 587, and 993 only.
- Direct IP destinations remain denied by default.
- Deny loopback, private, ULA, link-local, multicast, unspecified, documentation, mapped-private, reserved, and other non-public addresses by default.
- For hostnames, resolve once, validate every returned address, and connect to the exact validated `SocketAddr`. Never validate one DNS result and reconnect by hostname.
- DNS or policy validation failure must fail closed.
- Keep buffers and task creation bounded. Validate the theoretical aggregate buffer ceiling when changing related limits.
- Never log proxied payload bytes, passwords, session tokens, CSRF tokens, or bootstrap secrets.
- Preserve useful but non-sensitive close reasons and error messages.

## Authentication invariants

- Administrator authentication and Wisp-user authentication are separate systems.
- `WISP_ADMIN_PASSWORD` is only a first-start bootstrap input. If `/data/admin-credentials.toml` exists, it is authoritative and the environment variable must never reset or overwrite it.
- Persist only Argon2id hashes and non-secret metadata for administrator credentials.
- The normal server command must never perform an implicit password reset. Recovery belongs only to the interactive `reset-admin-password` CLI command.
- Administrator password changes require the current password and invalidate all administrator sessions.
- Keep administrator sessions short-lived and in memory. Preserve `HttpOnly`, `Secure` by default, and `SameSite=Strict` cookie behavior.
- Check both authorization and CSRF tokens on every state-changing administration route, including logout and disconnect actions.
- Preserve login throttling and constant-time CSRF comparisons.
- Disabling, removing, or resetting a Wisp user must revoke that user's active sessions.

## Persistence and configuration

- Persist data only under the configured data directory, `/data` in the container.
- Validate complete configuration before replacing active state.
- Use atomic same-directory temporary-file replacement. Keep secret files mode `0600` and ordinary configuration mode `0640` on Unix.
- Do not mutate active in-memory settings until persistence succeeds.
- Apply policy and timeout changes only where the runtime actually supports immediate application.
- Clearly label listener, logging, semaphore-capacity, or other restart-required settings. Never claim a setting is active before it is applied.
- Preserve existing valid data on validation or save failure.
- Do not put credentials in `config.example.toml`, tests, documentation, fixtures, or committed files.

## Rust style and error handling

- Follow `rustfmt` and keep Clippy clean with warnings denied.
- Avoid `unwrap` and `expect` on untrusted input, persisted data, forms, protocol packets, and normal network paths. They are acceptable in tightly controlled tests when failure should panic the test.
- Return contextual errors without attaching secrets or arbitrary TCP data.
- Prefer explicit cancellation, timeouts, bounded channels, and semaphores for asynchronous resource ownership.
- Avoid holding async locks across network or filesystem operations unless required and reviewed carefully.
- Use atomics only for independent counters; use locks or channels when state must change consistently.
- Keep comments concise and focused on non-obvious security or protocol reasoning.

## Admin UI

- Keep pages server-rendered and accessible. Do not introduce an SPA or frontend build pipeline.
- Preserve the established visual language in `static/style.css` and existing templates.
- Validate every form server-side. HTML constraints are only a usability aid.
- Escape all user-controlled output through Askama; do not mark arbitrary values safe.
- Never render existing passwords, password hashes, administrator tokens, or CSRF tokens except CSRF values in authenticated hidden form fields.
- The Dashboard's recent-errors list is bounded, in memory, and not a replacement for process logs.

## Logging and observability

- Use `tracing`; process logs go to stdout/stderr and are viewed with tools such as `podman logs`.
- Respect the configured log filter at startup and document restart requirements for changes.
- Keep health checks cheap and unauthenticated at `/healthz`; do not expose configuration or internal state there.
- Metrics and recent errors must not contain credentials or payload contents.

## Containers and deployment

- Keep `Containerfile` multi-stage and the runtime image non-root and free of compilers or build tooling.
- Keep the internal container listener at `0.0.0.0:8080`; host mappings may use a different port.
- Use Podman CLI commands for local and pull-request build verification.
- Docker compatibility may be documented as expected, but do not claim it was verified unless it was actually tested.
- Buildx is intentionally limited to trusted branch/tag jobs that publish AMD64/ARM64 manifests to GHCR.
- Caddy is optional, but production requires Caddy or another HTTPS/WSS TLS terminator. Do not imply that Wispdeck terminates TLS.
- Preserve `/wisp/` when proxying; do not use path-stripping reverse-proxy rules.

## Documentation expectations

Update `README.md`, `config.example.toml`, templates, container examples, and workflows when behavior or defaults change. In particular, document:

- Exact tested Wisp version and extensions.
- Known v2.1 limitations.
- Runtime versus restart-required settings.
- Credential storage and bootstrap behavior.
- Podman commands and any unverified deployment paths.
- Commands actually run and checks that were skipped or failed.

Do not claim interoperability, architecture support, container compatibility, or test coverage that was not exercised.

## Completion checklist

Before finishing a non-trivial change:

1. Confirm architecture and security invariants still hold.
2. Add or update focused tests for changed behavior.
3. Run `cargo fmt --check`.
4. Run `cargo clippy --all-targets --all-features --locked -- -D warnings`.
5. Run `cargo test --locked`.
6. Run `cargo build --release --locked` for release-affecting changes.
7. Run a Podman build for container-affecting changes.
8. Report exactly which checks ran and any remaining limitations.
