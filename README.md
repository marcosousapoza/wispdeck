# Wispdeck

Wispdeck is a self-hosted, authenticated Wisp TCP proxy with a small server-rendered administration interface. It is a Rust application with no database, JavaScript toolchain, Docker socket access, or background broker. Wispdeck is not affiliated with any existing product that uses the same name.

The recommended deployment is one Wispdeck container behind an HTTPS reverse proxy such as Caddy. Caddy is not integral to Wispdeck and is not included in its container. A persistent `/data` volume contains configuration and credentials.

## Supported protocol

- Wisp v2.0 INFO negotiation through pinned `wisp-mux` 6.0.0 commit `9cde724aea1a0f5e46b1c962b3d19ca1389af074`.
- `/wisp/` requires `Sec-WebSocket-Protocol`; the selected value is echoed as required by WebSocket negotiation.
- Password extension `0x02` is required. Missing credentials, incorrect credentials, v1 clients, and v2-to-v1 downgrade attempts are rejected.
- Concurrent TCP streams, Wisp flow control, bounded per-stream message queues, stream closure, and session cleanup.
- TCP only. UDP is rejected and is not advertised.
- The pinned backend advertises v2.0, not complete finalized v2.1. In particular, stream-open confirmation extension `0x05` is not implemented or advertised.

Wispdeck replaces the pinned library's plaintext-map password verifier with a narrow adapter-local extension implementation using the same wire ID and format. Wisp user passwords are verified against Argon2id hashes. Malformed extension metadata is bounds-checked before parsing. Passwords still travel inside the Wisp WebSocket protocol, so HTTPS/WSS is mandatory.

### Wisp-user authentication

The administrator creates a Wisp username and password under **Wisp users**. The user configures that username and password in their Wisp client; this is separate from the administrator login. During connection setup, Wispdeck's server INFO packet marks password extension `0x02` as required. The client returns its username and password in its client INFO packet over WSS. Wispdeck verifies the password against the user's Argon2id hash and only then accepts streams. Existing passwords cannot be recovered or displayed; an administrator can only assign a new one. Disabling, removing, or resetting a user disconnects that user's current sessions.

## Architecture

`src/core` owns runtime state, identities, metrics, and policy-independent session tracking. `src/protocol/backend.rs` is the internal backend interface. Only `src/protocol/wisp_mux` imports `wisp-mux`. `src/proxy` owns DNS, destination checks, exact-address dialing, timeouts, and forwarding. Authentication, administration, and TOML persistence are independent of concrete Wisp types. A mock can implement `ProtocolBackend` without changes to core, proxy, or admin code.

## Safe defaults

- Outbound TCP ports: 465, 587, and 993.
- UDP disabled.
- Direct IP destinations denied.
- Loopback, private, ULA, link-local, multicast, unspecified, documentation, mapped-private, and other reserved addresses denied.
- A hostname is resolved once. Every returned address must pass policy, and Wispdeck connects to an exact validated socket address rather than resolving the hostname again.
- 64 clients, 16 streams per client, 64 pending dials, 64 KiB WebSocket messages, and 8 queued Wisp messages per stream. Validation rejects combinations whose theoretical inbound queue capacity exceeds the configured 512 MiB total-buffer ceiling.

A port allowlist is not a complete anti-abuse boundary. Add host or container egress firewall rules that deny internal networks and restrict allowed destination ports. DNS and application policy should be treated as one layer, not the only layer.

## Build and run locally

Requirements are a current stable Rust toolchain and network access for the pinned Git dependency.

```sh
cargo build --locked
mkdir -p ./data
WISPDECK_DATA_DIR=./data WISP_ADMIN_PASSWORD='a long first-start password' cargo run --locked -- serve
```

The default bind address is `127.0.0.1:8080`. Open `http://127.0.0.1:8080/admin/login`.

A Secure cookie is a browser cookie carrying the `Secure` attribute. Browsers send it only over HTTPS, which prevents an administrator session token from being transmitted over unencrypted HTTP. Wispdeck's cookie is also `HttpOnly`, so browser JavaScript cannot read it, and `SameSite=Strict`, which limits cross-site requests. `admin.secure_cookie` starts as `false` so the first administrator login works over loopback or a trusted private network without editing files in the data directory. The login page and Dashboard warn while it is disabled. Configure HTTPS, verify the HTTPS administration page works, then enable **Require HTTPS for administrator sessions** under **Server settings**. The change applies immediately.

On the first start only, `WISP_ADMIN_PASSWORD` must be nonempty and at least 12 characters. Wispdeck writes only an Argon2id hash to `admin-credentials.toml`. Once that file exists it is authoritative: leaving or changing the environment variable cannot overwrite the password. Environment variables may be visible to operators who can inspect process or container configuration; this is the accepted bootstrap trade-off.

Change the password under **Administrator**. The current password is required and every admin session is invalidated. For local recovery, stop the server and run the interactive command below against the same data directory:

```sh
WISPDECK_DATA_DIR=./data wispdeck reset-admin-password
```

The password is read from the terminal without being placed in shell history or process arguments.

## Data and configuration

```text
/data/config.toml
/data/admin-credentials.toml
/data/wisp-users.toml
/data/wisp-user-secrets.toml
```

Credential files are atomically replaced with mode `0600`; ordinary configuration uses `0640`. `wisp-user-secrets.toml` contains only Argon2id hashes, not plaintext passwords. Existing passwords are never displayed by the UI. Do not share the data directory as a diagnostic bundle.

Copy `config.example.toml` for all settings and defaults. The admin UI validates before atomically saving. Destination policy and timeouts apply to new streams. Bind address and log-level changes require restart. Client and semaphore capacity changes are persisted but require restart; the UI says so rather than claiming they are active. Disabling or removing a Wisp user revokes that user's active sessions. Tightening policy affects new streams; use Connections to terminate existing sessions.

Admin sessions are in memory and intentionally disappear on restart. Cookies are HttpOnly, SameSite=Strict, and short-lived. The Secure attribute is enabled from **Server settings** after HTTPS is configured. State-changing forms require a per-session CSRF token. Login attempts are throttled after repeated failures.

## Logging

Wispdeck uses `tracing` and writes process logs to stdout/stderr. With Podman, inspect them with `podman logs <container-name>` or configure the host's container log driver. The `log_level` setting is applied at startup, so changing it requires a restart.

The Dashboard's **Recent errors** panel is not the full process log. It contains at most 20 recent Wisp session or TCP forwarding errors held in memory and is cleared on restart. Credentials, administrator session tokens, and proxied TCP payloads are not logged or placed in that panel.

## Container

Podman is the documented and locally verified container CLI. The multi-stage `Containerfile` produces a distroless image containing the native binary and runtime libraries, runs as UID/GID 65532, and supports AMD64 and ARM64 in the publishing workflow. Ensure the host volume is writable by UID 65532.

```sh
mkdir -p ./wispdeck-data
chown 65532:65532 ./wispdeck-data
podman build -t wispdeck -f Containerfile .
podman run --rm --name wispdeck -p 127.0.0.1:8080:8080 \
  -v ./wispdeck-data:/data:Z \
  -e WISP_ADMIN_PASSWORD='a long first-start password' wispdeck
```

Docker should work with the same OCI `Containerfile`, but it has not been verified for this revision. If using Docker, omit `:Z` when SELinux relabeling is not needed:

```sh
docker build -t wispdeck -f Containerfile .
docker run --rm --name wispdeck -p 127.0.0.1:8080:8080 \
  -v "$PWD/wispdeck-data:/data" \
  -e WISP_ADMIN_PASSWORD='a long first-start password' wispdeck
```

The image sets the runtime-only `WISPDECK_LISTEN=0.0.0.0:8080` override so its loopback-mapped port is reachable. Outside the image, the safe persisted default remains `127.0.0.1:8080`. The bootstrap variable can be removed after credentials exist. `GET /healthz` returns `204` and requires no authentication.

### Rootless Podman Quadlet

The files under `deploy/quadlet/` run Wispdeck as a rootless systemd user service. They create a persistent SELinux-relabeled named volume, publish Wispdeck only on `127.0.0.1:8080`, inject the bootstrap password from a Podman secret, and opt into registry auto-updates.

Create the bootstrap secret without placing the password in the Quadlet or shell history:

```sh
read -rsp 'Initial administrator password: ' WISP_ADMIN_PASSWORD
printf '%s' "$WISP_ADMIN_PASSWORD" | podman secret create wispdeck-admin-password -
unset WISP_ADMIN_PASSWORD
```

Install and start the rootless Quadlets from a repository checkout:

```sh
install -d -m 0700 ~/.config/containers/systemd
install -m 0644 deploy/quadlet/wispdeck.container ~/.config/containers/systemd/
install -m 0644 deploy/quadlet/wispdeck-data.volume ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start wispdeck.service
```

Do not pre-create `config.toml` with a helper container. On first start Wispdeck creates the configuration and credential files with the correct ownership and permissions inside the named volume. The initial HTTP login is intentionally available for setup, with prominent security warnings; configure HTTPS before creating Wisp users or carrying real traffic.

The `[Install]` section makes the generated service part of `default.target`; do not run `systemctl --user enable wispdeck.service` because generated Quadlet services are transient. To start the user service after boot without an interactive login, enable lingering once:

```sh
loginctl enable-linger "$USER"
```

Inspect the service and its logs with:

```sh
systemctl --user status wispdeck.service
journalctl --user -u wispdeck.service -f
```

Enable Podman's user auto-update timer if automatic `latest` updates are desired:

```sh
systemctl --user enable --now podman-auto-update.timer
```

The Podman secret remains attached on later starts, but Wispdeck ignores `WISP_ADMIN_PASSWORD` after `/data/admin-credentials.toml` exists. Changing or recreating that secret cannot reset an existing administrator password. Use the documented `reset-admin-password` recovery command instead.

For Caddy running on the host, keep `reverse_proxy 127.0.0.1:8080`. For another host port, change `PublishPort` in `wispdeck.container`, run `systemctl --user daemon-reload`, and restart `wispdeck.service`.

## Caddy

Caddy is optional, but a production deployment needs Caddy or another HTTPS/WSS-capable reverse proxy unless TLS is terminated elsewhere. Wispdeck itself serves HTTP and WebSocket traffic without TLS. Keep port 8080 bound to loopback or a private container network. Caddy forwards both paths without stripping `/wisp/`:

```caddyfile
wisp.example.com {
    encode zstd gzip

    handle /wisp/* {
        reverse_proxy 127.0.0.1:8080
    }

    handle /admin/* {
        reverse_proxy 127.0.0.1:8080
    }

    handle /static/* {
        reverse_proxy 127.0.0.1:8080
    }

    respond 404
}
```

Caddy automatically handles WebSocket upgrades and HTTPS. Do not use `handle_path`, which would strip the Wisp path. Do not expose Wispdeck's internal HTTP listener directly to the public Internet.

Wispdeck forwards raw TCP. It does not terminate or inspect SMTP/IMAP TLS. Browser-side Epoxy TLS or an equivalent implementation must validate server certificates and correctly implement implicit TLS or SMTP STARTTLS.

## CI and images

`.github/workflows/ci.yml` runs formatting, Clippy with warnings denied, locked tests, a locked release build, and `podman build` through the Podman CLI. `.github/workflows/container.yml` also verifies every pull request with the Podman CLI. Its trusted branch/tag publishing job retains Buildx only for the required AMD64/ARM64 GHCR manifest. Pull requests never authenticate to or publish into GHCR; default-branch pushes and `vX.Y.Z` tags publish version, SHA, and appropriate `latest` tags to:

```sh
podman pull ghcr.io/<owner>/wispdeck:latest
```

Replace `<owner>` with the GitHub repository owner. In repository package settings, make the GHCR package public if anonymous pulls are desired. Publishing uses `GITHUB_TOKEN` with only contents-read and packages-write permissions. `docker pull` is expected to work against the same OCI image but has not been verified here.

## Security notes and limitations

- WSS is required because the Wisp password extension sends credentials inside the encrypted WebSocket, not with application-layer encryption.
- Administrator and Wisp credentials are separate. Admin credentials cannot authenticate Wisp and vice versa.
- No Ed25519 Wisp authentication is implemented; the protocol adapter leaves room for another verifier later.
- Argon2 verification occurs during the pinned library's synchronous extension decode callback. Client and login limits bound work, but operators should still apply reverse-proxy connection and request-rate limits.
- Recent error messages contain destinations and error classes, never credentials or proxied payload bytes.
- Protect `/data`, backups, container configuration, DNS, and the host itself. Use a second-layer egress firewall.
- The current interoperability target is the pinned `wisp-mux` client/server implementation at commit `9cde724`; finalized v2.1-only extension `0x05` is unsupported.

## Verification

```sh
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo build --release --locked
podman build -f Containerfile .
```
