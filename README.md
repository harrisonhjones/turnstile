# Turnstile

Turnstile is a standalone **access-control service**. Instead of every service
reimplementing authentication, authorization, and rate limiting, they ask
Turnstile — one `Check` call per request answers *"is this caller allowed to do
this action on this thing, and are they within their rate limit?"* — and
Turnstile keeps the audit trail of what happened.

A turnstile admits the authorized (auth), meters each pass (rate limiting), and
counts every entry (audit).

## What you use it for

- **Central access control for many projects.** Run one shared instance; each
  service namespaces its own actions and resources (`photos:listAlbums`,
  `payments:createCharge`), and those namespaces stay isolated from each other.
- **Issuing and managing API keys.** Mint opaque bearer keys with fine-grained
  allow/deny policy statements, per-key rate limits, expiry, and enable/disable
  — via an API or the built-in web console.
- **A single, tamper-resistant policy point.** A global deny-only "ceiling"
  applies on top of every key, so you can revoke a capability everywhere at once.
- **An audit trail.** Turnstile records every access decision and management
  change itself; browse and filter it by key, action, decision, and time.

It speaks [Connect](https://connectrpc.com), so the hot path is
gRPC-wire-compatible while management is also plain `curl`- and browser-friendly.

## Install

Requires **Go** (version pinned in `go.mod`); SQLite is pure-Go, so there's no
CGO or system SQLite to install.

**With `go install`** (no clone needed):

```sh
go install harrisonhjones.com/turnstile/cmd/turnstile@latest
```

This builds from source with the committed proto stubs and ships the **UI
placeholder** (the console isn't compiled in). For the real console, grab a
[release binary](https://github.com/harrisonhjones/turnstile/releases), run the
[Docker image](#run-with-docker), or build from source with `mage build:all`.

**From source** — builds use [mage](https://magefile.org)
(`go install github.com/magefile/mage@latest`):

```sh
git clone https://github.com/harrisonhjones/turnstile
cd turnstile

# Build the binary and run it. Uses the committed proto stubs and ships the
# UI placeholder, so nothing beyond Go and mage is needed:
mage build:backend && ./turnstile

# During development, `mage run:backend` builds and runs in one step (with hot
# reload if `air` is installed).
```

The full build — regenerating protos and compiling the web UI into the binary —
is `mage build:all`, which needs extra tooling (buf, the protoc plugins, and
Node); see [DEVELOPMENT.md](DEVELOPMENT.md). It isn't required just to run the
service.

## Run with Docker

A published multi-arch image (`linux/amd64`, `linux/arm64`) is on Docker Hub. All
state (keys, policy, audit) lives in a SQLite database under `/data`, so mount a
volume to persist it:

```sh
docker run -d --name turnstile \
  -v turnstile-data:/data -p 8080:8080 \
  harrisonhjones/turnstile:latest
```

Use a **named volume** as above (a bind mount must be pre-owned by uid `65532`,
since the image runs non-root). Pass configuration with `-e KEY=value`; under
mutual TLS add `--no-healthcheck` (the built-in probe presents no client cert).
You can also build the image locally: `docker build -t turnstile .`. Full env-var
table and deployment notes: [DOCKERHUB.md](DOCKERHUB.md).

On first start against an empty database, Turnstile prints a **bootstrap
management key once** — save it; it guards the management API and web console:

```json
{"time":"2026-08-25T12:00:00Z","level":"WARN","msg":"created bootstrap management key — store this token now, it will not be shown again","token":"tsk_..."}
```

Then open the console at **http://localhost:8080/ui/** and sign in with that
token.

Configuration is via environment variables (all optional, with sane defaults);
copy `.env.example` to `.env` to customize. See
[DEVELOPMENT.md](DEVELOPMENT.md#configuration) for the reference.

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — how it works, the design decisions,
  transport, and repository layout.
- **[DEVELOPMENT.md](DEVELOPMENT.md)** — building, testing, configuration, and
  contributing.
- **[CLIENT-INTEGRATION.md](CLIENT-INTEGRATION.md)** — for host services: how to
  call `Check`/`Authenticate` (with `curl` and Go examples).
- **[ADMINISTRATION.md](ADMINISTRATION.md)** — for operators: running the
  service, minting/managing keys, editing policy, auditing, and securing
  host→Turnstile (mTLS or network isolation).

Low-level details live in Godoc — read the package docs with `go doc ./internal/...`
(there's no mage target for it).
