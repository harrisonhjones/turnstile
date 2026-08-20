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
| `test:unit` | `go test ./...`. |
| `test:integration` | End-to-end tests over an in-process server. |
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

## Testing

```sh
mage test:unit           # or: go test ./...
```

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
