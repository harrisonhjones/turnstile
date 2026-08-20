// Package management serves the embedded management web UI: the Ionic React
// single-page app that talks to Turnstile over the Connect HTTP/JSON protocol.
// The UI is a plain API client — it authenticates by sending an admin
// credential as a Bearer header, so this package adds no server-side auth or
// session state.
//
// The UI is compiled by `mage build:ui` into ui/dist and embedded here. The
// build output is gitignored; only an empty ui/dist/.gitkeep is checked in so
// this package compiles without a Node build. When no built index.html is
// embedded, the handler serves placeholderIndex (a "run mage build:ui" page)
// instead. Run `mage build:ui` (or `mage build:all`) to embed the real app.
package management

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:ui/dist
var staticFiles embed.FS

// placeholderIndex is served when no built index.html is embedded (e.g. a
// checkout that hasn't run the UI build). It keeps /ui/ responding with a
// helpful page rather than a 500.
const placeholderIndex = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Turnstile</title>
  </head>
  <body>
    <main style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 15vh auto; padding: 0 1.5rem; line-height: 1.5">
      <h1>Turnstile</h1>
      <p>The management UI has not been built. Run <code>mage build:ui</code> (or <code>mage build:all</code>) to compile it, then reload.</p>
    </main>
  </body>
</html>
`

// Handler returns an http.Handler that serves the management SPA. Mount it at
// /ui/. Unknown sub-paths fall back to index.html so client-side navigation
// works on reload.
func Handler() (http.Handler, error) {
	sub, err := fs.Sub(staticFiles, "ui/dist")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(sub))

	mux := http.NewServeMux()
	mux.Handle("/", spaFallback(sub, fileServer))
	return http.StripPrefix("/ui", mux), nil
}

// spaFallback serves a static file when it exists, otherwise index.html. This
// keeps a single-page app working when the user reloads on a sub-route.
func spaFallback(fsys fs.FS, fileServer http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "" || path == "/" {
			serveIndex(fsys, w, r)
			return
		}
		name := path
		if name[0] == '/' {
			name = name[1:]
		}
		if _, err := fs.Stat(fsys, name); err != nil {
			serveIndex(fsys, w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

func serveIndex(fsys fs.FS, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		// No built UI embedded — serve the placeholder instead of failing.
		_, _ = w.Write([]byte(placeholderIndex))
		return
	}
	_, _ = w.Write(data)
}
