# Turnstile management UI

An Ionic React (Vite + TypeScript) single-page app for operating Turnstile:
create/list/edit/disable **keys**, view/edit the global **policy** (deny-only
ceiling), and browse/filter the **audit log**.

It is a plain API client: it talks to Turnstile over the **Connect HTTP/JSON**
protocol (`POST /turnstile.v1.Turnstile/<Method>`), authenticating with an
**management key** pasted at sign-in (sent as `Authorization: Bearer`). No
generated client — see `src/api.ts`.

## Develop

```
npm install
npm run dev        # Vite dev server on :5173, proxies the API to :8080
```

Run the backend (`mage run:backend`) alongside it. The dev server proxies
`/turnstile.v1.Turnstile/*` and `/health` to `http://localhost:8080`.

## Build

`mage build:ui` (or `npm run build`) compiles into `dist/`, which the Go binary
embeds via `go:embed` and serves at `/ui/`. Only `dist/.gitkeep` is tracked; the
build output is gitignored.

## Scripts

- `dev` — Vite dev server
- `build` — type-check + production build
- `lint` — oxlint
- `format` / `format:check` — oxfmt
