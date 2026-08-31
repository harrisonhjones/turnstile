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
mage run:backend         # serves on :8080, prints the bootstrap key token on first run
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
| `LISTEN_ADDR` | `:8080` | Address to bind. Serves the Connect API, the UI at `/ui/`, `/health`, and (when enabled) `/metrics`. |
| `DB_PATH` | `turnstile.db` | SQLite database file path. |
| `AUDIT_RETENTION_DAYS` | `365` | Days of audit log to keep; `0` keeps entries forever. |
| `METRICS_ENABLED` | `true` | Expose Prometheus metrics at `/metrics` (unauthenticated, like `/health`). Set `false`/`0`/`off`/`no` to disable. |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | *(unset)* | Set both to serve HTTPS. |
| `TLS_CLIENT_CA_FILE` | *(unset)* | With TLS enabled, require and verify client certificates against this CA (mTLS). |

See [`.env.example`](.env.example) for the annotated source of truth. The
host-facing RPCs are open at the application layer; guard them with optional
mTLS or network isolation — see [ARCHITECTURE.md](ARCHITECTURE.md). The
`-bootstrap` flag (or `TURNSTILE_BOOTSTRAP=true`) mints a fresh full-admin key on
start as a break-glass recovery path.

## Testing

```sh
mage check       # the CI gate: static analysis (vet) + unit tests
mage test:unit   # just the unit tests
```

`mage test:unit` (and `mage check`) run the tests with the race detector, matching
what CI runs, so a local `mage check` reproduces the CI gate.

- `internal/policy` — the statement engine (deny-wins, wildcards, multi-resource
  OR, namespace isolation) and validation (well-formedness, global deny-only).
- `internal/ratelimit` — burst/refill, key overrides, and the reserve-then-
  confirm refund (a block on one limiter never burns a token on the other).
- `internal/store` — key CRUD (including in-place secret rotation), policy
  optimistic concurrency, audit filters + keyset pagination.
- `internal/token` — authentication (generic failure collapsing), the global
  deny ceiling, key-only management authorization, and bootstrap.
- `internal/server` — end-to-end over an in-process Connect client: management
  authorization (`turnstile:` actions), `Check` allow/deny/rate-limit,
  `ReportAudit`, `QueryAudit`, and policy version conflicts.

## Resetting state

```sh
mage resetDB             # then restart to get a fresh bootstrap key token
```

## CI, releases, and Docker

Three GitHub Actions workflows drive this, named after *when* they run
(`.github/workflows/`):

- **`build-test.yml`** — the reusable quality gate (gofmt check, `go vet`,
  `go build`, `go test -race`). Defined once and called by the two below via
  `workflow_call` so the PR check and the release gate can't drift.
- **`on-pull-request.yml`** — on every pull request: calls `build-test`, then
  runs `release-validate` (`goreleaser check`, a snapshot build, and a prebuilt
  multi-arch image build). This is the only place `release-validate` *gates* — the
  release doesn't run on PRs — so **route Docker/GoReleaser-config changes through
  a PR** to catch a broken config before merge.
- **`on-push-to-main.yml`** — cuts releases two ways: (1) on push to `main` it
  derives the next version from the **Conventional Commit** messages since the
  last tag and tags it automatically (every push cuts at least a patch); or
  (2) pushing a `vX.Y.Z` tag releases that exact version. The release job
  `needs:` `build-test`, so a direct push that breaks tests can't ship. The
  auto-bump needs a pre-existing tag as its baseline, so **seed the first release
  by pushing a tag once** (`git tag v0.1.0 && git push origin v0.1.0`); after
  that, pushes to `main` auto-bump on their own.

### Automatic versioning

Version bumps follow the commit types merged since the last tag:

| Commit | Bump |
|---|---|
| `feat:` | minor (`x.Y.0`) |
| any type with `!` (e.g. `feat!:`) or a `BREAKING CHANGE:` footer | major (`X.0.0`) |
| anything else (`fix:`/`refactor:`/`perf:`/`docs:`/`chore:`/`ci:`/…) | patch (`x.y.Z`) |

Patch is the catch-all, so every push to `main` cuts at least a patch release.

So releasing is just merging Conventional Commits to `main`; there's no manual
tagging step. (`workflow_dispatch` is also available to run it by hand.)

### What a release produces

When a bump happens, the workflow tags `vX.Y.Z` and then, in order:

- **GoReleaser** (`.goreleaser.yaml`) builds cross-platform binaries
  (linux/darwin/windows × amd64/arm64; Windows ships as `.zip`, the rest as
  `.tar.gz`), checksums, and a grouped changelog, and publishes a
  **GitHub Release**. The version is stamped into the binary via
  `-ldflags -X main.version=…` (check with `turnstile -version`).
- Then a multi-arch **container image** is built and pushed to **Docker Hub** as
  `harrisonhjones/turnstile:X.Y.Z` and `:latest`, and the Hub description is
  synced from `DOCKERHUB.md`. The image build **COPYs the binary GoReleaser
  already cross-compiled** (`BIN_MODE=prebuilt`) instead of recompiling in-image,
  so the release doesn't build the binary twice and needs no QEMU (every image
  stage is `$BUILDPLATFORM`-pinned or COPY-only — nothing foreign-arch executes).
  The Release is created before the image so a failed release never leaves images
  (including `:latest`) without a matching Release.

GoReleaser and tagging use the workflow's `GITHUB_TOKEN`. The Docker Hub push
requires two repo secrets: **`DOCKERHUB_USERNAME`** and **`DOCKERHUB_TOKEN`**
(a Docker Hub access token). The binary carries `version`, `commit`, and `date`,
injected via ldflags in both GoReleaser and the Docker build. Actions are pinned
to commit SHAs (with a version comment); bump both together when upgrading.

**If a release run fails partway:** the run is idempotent — just "Re-run failed
jobs". It reuses the tag already at HEAD and, if the Release already exists,
re-runs GoReleaser with `--skip=publish` (rebuilding `dist/` for the image step
without re-uploading), so it resumes rather than skipping the version. A
`workflow_dispatch` on a commit that already carries a tag replays the release
the same way rather than cutting a new version. (To abandon a version, delete its
remote tag: `git push origin :vX.Y.Z`.)

### Docker locally

```sh
docker build -t turnstile .
docker run -p 8080:8080 -v turnstile-data:/data turnstile
```

The image is a static (CGO-free) binary on a distroless base; the SQLite DB lives
on the `/data` volume (`DB_PATH=/data/turnstile.db`). A plain `docker build .`
uses the default **`BIN_MODE=compile`**: it builds the console from source in a
Node stage and compiles the binary in-image, so every locally-built image ships
the real UI (the local `internal/management/ui/dist` is `.dockerignore`d and not
used — no need to run `mage build:ui` first). CI instead builds with
`--build-arg BIN_MODE=prebuilt`, which COPYs GoReleaser's already-compiled binary
from `dist/` — same image, without recompiling.

Use a **named volume** as shown (`-v turnstile-data:/data`); it inherits the
image's `/data` ownership so the non-root process can write. A **bind mount**
(`-v /host/path:/data`) takes host ownership — pre-create it owned by uid `65532`,
or the container can't write its database.

Under **mutual TLS** (`TLS_CLIENT_CA_FILE` set), `/health` requires a client
certificate that the built-in probe doesn't present, so the container would report
unhealthy — run such deployments with `docker run --no-healthcheck` (or override
the healthcheck).
