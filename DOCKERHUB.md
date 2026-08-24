# Turnstile

Standalone **access-control service**: issues API keys, evaluates a
statement-based policy engine, enforces rate limits, and records an audit trail,
over gRPC/Connect with a SQLite backend.

Source, docs, and issues: https://github.com/harrisonhjones/turnstile

## Tags

- `latest` — the most recent release.
- `X.Y.Z` — a specific release (SemVer, auto-derived from Conventional Commits).

Images are multi-arch (`linux/amd64`, `linux/arm64`).

## Run

```sh
docker run -p 8080:8080 -v turnstile-data:/data harrisonhjones/turnstile:latest
```

On first start against an empty database the container logs a **bootstrap admin
token once** — capture it from `docker logs`; it guards the management API and
the console at `http://localhost:8080/ui/`.

## Configuration

All via environment variables (all optional, sane defaults). Common ones:

- `LISTEN_ADDR` (default `:8080`)
- `DB_PATH` (default `/data/turnstile.db` in the image — mount a volume at `/data`)
- `AUDIT_RETENTION_DAYS` (default `365`)
- `SERVICE_CREDENTIAL`, `TLS_CERT_FILE`, `TLS_KEY_FILE`, `TLS_CLIENT_CA_FILE`

See the repository's `DEVELOPMENT.md` for the full reference.
