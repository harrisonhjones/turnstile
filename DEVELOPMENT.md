# Development

## Prerequisites

- **Go** (see the version pinned in `go.mod`). SQLite is pure-Go
  (`modernc.org/sqlite`), so no CGO or system SQLite is required.
- **[mage](https://magefile.org)** for build/dev tasks: `go install github.com/magefile/mage@latest`.
- **Proto tooling** (only needed to regenerate stubs after editing the proto):
  ```sh
  go install github.com/bufbuild/buf/cmd/buf@latest
  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
  go install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest
  ```
- **Node** (for the management UI): any recent LTS. `mage build:ui` runs
  `npm ci` on first use.
- **[air](https://github.com/air-verse/air)** (optional) for Go hot reload:
  `go install github.com/air-verse/air@latest`.

## Mage targets

Run `mage` with no args to list them. Targets are namespaced so each acts on the
whole project, just the Go backend, or just the web UI:

| Target | What it does |
|---|---|
| `gen` (`generate`) | Run `buf generate` → Go + Connect stubs into `gen/`. |
| `build:all` | `gen` → build UI → compile the backend (the shippable artifact). |
| `build:backend` | Compile the `turnstile` binary. Embeds whatever is in `ui/dist`. |
| `build:ui` | Build the Ionic React app into `internal/management/ui/dist`. |
| `run:backend` | Build + run the service (hot reload via `air` if on `PATH`). |
| `run:ui` | Vite dev server for the UI (proxies the API to the backend). |
| `fmt:all` / `fmt:backend` / `fmt:ui` | gofmt / oxfmt. |
| `vet:all` / `vet:backend` / `vet:ui` | `go vet` (+ golangci-lint if installed) / oxlint. |
| `test:unit` | `go test ./...` — includes the end-to-end tests that run the service over an in-process Connect client (`internal/server`). |
| `test:integration` | Runs tests behind the `integration` build tag (for external-dependency tests). Placeholder — none defined yet, so it currently runs nothing. |
| `check` | The CI gate: `vet:backend` then `test:unit`. |
| `clean:all` / `clean:backend` / `clean:ui` | Remove build artifacts. |
| `resetDB` | Delete the SQLite file + WAL/SHM sidecars (honors `DB_PATH`). |

## Typical loops

**Backend only:**
```sh
mage run:backend         # serves on :8080, prints the bootstrap admin token on first run
```

**Backend + live UI:**
```sh
mage run:backend         # terminal 1
mage run:ui              # terminal 2 — Vite dev server, proxies API calls to :8080
```

**Editing the proto:** edit `proto/turnstile/v1/turnstile.proto`, then
`mage gen`, then rebuild. The generated code under `gen/` is committed so the
project builds without buf.

## Configuration

All configuration is via environment variables, seeded on startup from an
optional `.env` file in the working directory (`cp .env.example .env`); real
environment variables always take precedence. Every value is optional with a
sane default.

| Variable | Default | Purpose |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | Address to bind. Serves the Connect API, the UI at `/ui/`, and `/health`. |
| `DB_PATH` | `turnstile.db` | SQLite database file path. |
| `AUDIT_RETENTION_DAYS` | `365` | Days of audit log to keep; `0` keeps entries forever. |
| `SERVICE_CREDENTIAL` | *(unset)* | If set, required as `Authorization: Bearer` on the host-facing RPCs (`Check`/`Authenticate`/`ReportAudit`). Unset leaves them open (rely on mTLS or network isolation). |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | *(unset)* | Set both to serve HTTPS. |
| `TLS_CLIENT_CA_FILE` | *(unset)* | With TLS enabled, require and verify client certificates against this CA (mTLS). |

See [`.env.example`](.env.example) for the annotated source of truth. The
host→Turnstile authentication options (service credential vs. mTLS) are covered
in [ARCHITECTURE.md](ARCHITECTURE.md).

## Testing

```sh
mage check       # the CI gate: static analysis (vet) + unit tests
mage test:unit   # just the unit tests
```

The race detector isn't wired to a mage target; when you need it, run
`go test -race ./...` directly.

- `internal/policy` — the statement engine (deny-wins, wildcards, multi-resource
  OR, namespace isolation) and validation (well-formedness, global deny-only).
- `internal/ratelimit` — burst/refill, key overrides, and the reserve-then-
  confirm refund (a block on one limiter never burns a token on the other).
- `internal/store` — key CRUD, policy optimistic concurrency, admin credentials,
  audit filters + keyset pagination.
- `internal/token` — authentication (generic failure collapsing), the global
  deny ceiling, and bootstrap.
- `internal/server` — end-to-end over an in-process Connect client: admin
  guarding, `Check` allow/deny/rate-limit, `ReportAudit`, `QueryAudit`, and
  policy version conflicts.

## Resetting state

```sh
mage resetDB             # then restart to get a fresh bootstrap admin token
```

## CI, releases, and Docker

Two GitHub Actions workflows drive this (`.github/workflows/`):

- **`ci.yml`** — on every pull request and push to `main`: gofmt check, `go vet`,
  `go build`, and `go test -race`. This is the merge gate.
- **`release.yml`** — cuts releases two ways: (1) on push to `main` it derives
  the next version from the **Conventional Commit** messages since the last tag
  and, when a bump is warranted, tags it automatically; or (2) pushing a
  `vX.Y.Z` tag releases that exact version. The auto-bump needs a pre-existing
  tag as its baseline, so **seed the first release by pushing a tag once**
  (`git tag v0.1.0 && git push origin v0.1.0`); after that, pushes to `main`
  auto-bump on their own.

### Automatic versioning

Version bumps follow the commit types merged since the last tag:

| Commit | Bump |
|---|---|
| `fix:` / `perf:` / most types | patch (`x.y.Z`) |
| `feat:` | minor (`x.Y.0`) |
| any type with `!` (e.g. `feat!:`) or a `BREAKING CHANGE:` footer | major (`X.0.0`) |
| only `docs:`/`chore:`/`ci:`/etc. (no releasable change) | none — no tag, no release |

So releasing is just merging Conventional Commits to `main`; there's no manual
tagging step. (`workflow_dispatch` is also available to run it by hand.)

### What a release produces

When a bump happens, the workflow tags `vX.Y.Z` and then:

- **GoReleaser** (`.goreleaser.yaml`) builds cross-platform binaries
  (linux/darwin × amd64/arm64), checksums, and a grouped changelog, and publishes
  a **GitHub Release**. The version is stamped into the binary via
  `-ldflags -X main.version=…` (check with `turnstile -version`).
- A multi-arch **container image** is built from the repo `Dockerfile` and pushed
  to **Docker Hub** as `harrisonhjones/turnstile:X.Y.Z` and `:latest`, and the
  Hub description is synced from `DOCKERHUB.md`.

GoReleaser and tagging use the workflow's `GITHUB_TOKEN`. The Docker Hub push
requires two repo secrets: **`DOCKERHUB_USERNAME`** and **`DOCKERHUB_TOKEN`**
(a Docker Hub access token). The binary carries `version`, `commit`, and `date`,
injected via ldflags in both GoReleaser and the Docker build.

### Docker locally

```sh
docker build -t turnstile .
docker run -p 8080:8080 -v turnstile-data:/data turnstile
```

The image is a static (CGO-free) binary on a distroless base; the SQLite DB lives
on the `/data` volume (`DB_PATH=/data/turnstile.db`). It embeds whatever is in
`internal/management/ui/dist` at build time — a plain checkout ships the UI
placeholder (the API still works); run `mage build:ui` before `docker build` to
bake in the real console.
