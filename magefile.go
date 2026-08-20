//go:build mage

// Magefile defines build/test/quality targets for Turnstile. Run `mage` with no
// args to list targets, or `mage <namespace>:<target>`.
//
// Targets are grouped by namespace so each can act on the whole project, just
// the Go backend, or just the web UI (the Ionic React app in
// internal/management/ui, which the backend embeds):
//
//	build:all | build:backend | build:ui
//	run:backend | run:ui
//	fmt:all   | fmt:backend   | fmt:ui
//	vet:all   | vet:backend   | vet:ui
//	clean:all | clean:backend | clean:ui
//	test:unit | test:integration
//	gen | check | resetDB
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const binName = "turnstile"

const uiDir = "internal/management/ui"

// ensureUIDeps installs the UI's npm dependencies if node_modules is absent, so
// UI targets work on a fresh checkout.
func ensureUIDeps() error {
	if _, err := os.Stat(uiDir + "/node_modules"); os.IsNotExist(err) {
		fmt.Println("installing UI dependencies (npm ci)")
		return sh.RunV("npm", "--prefix", uiDir, "ci")
	}
	return nil
}

// npmRun runs an npm script in the UI project, installing deps first if needed.
func npmRun(script string) error {
	if err := ensureUIDeps(); err != nil {
		return err
	}
	return sh.RunV("npm", "--prefix", uiDir, "run", script)
}

// ---- gen ----

// Gen runs buf to generate the Go + Connect stubs from the protos into gen/.
// Requires buf, protoc-gen-go, and protoc-gen-connect-go on PATH:
//
//	go install github.com/bufbuild/buf/cmd/buf@latest
//	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
//	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest
func Gen() error {
	fmt.Println("generating protobuf + Connect stubs (buf generate)")
	return sh.RunV("buf", "generate")
}

// Generate is an alias for Gen.
func Generate() error { return Gen() }

// ---- build ----

// Build groups build targets: `mage build:all|backend|ui`.
type Build mg.Namespace

// All generates protos, builds the UI, then compiles the backend (the shippable
// artifact). Order matters: the backend embeds ui/dist, so the UI must be built
// first.
func (Build) All() {
	mg.SerialDeps(Gen, Build.UI, Build.Backend)
}

// UI builds the Ionic React front end into internal/management/ui/dist, which
// the Go binary embeds and serves at /ui/. Installs npm deps on first run.
func (Build) UI() error {
	fmt.Println("building UI")
	if err := npmRun("build"); err != nil {
		return err
	}
	// Vite empties dist on build, deleting the tracked .gitkeep; recreate it so
	// the tree stays clean and go:embed of ui/dist keeps compiling.
	return os.WriteFile(uiDir+"/dist/.gitkeep", nil, 0o644)
}

// Backend compiles the turnstile binary into the working directory. It embeds
// whatever is currently in ui/dist — run `mage build:ui` (or `mage build:all`)
// first to embed the real UI rather than the checked-in placeholder.
func (Build) Backend() error {
	fmt.Println("building", binName)
	return sh.RunV("go", "build", "-o", binName, "./cmd/turnstile/")
}

// ---- run ----

// Run groups run targets: `mage run:backend` (the service) and `mage run:ui`
// (the Vite dev server for UI development).
type Run mg.Namespace

// Backend builds and runs the service in the foreground, inheriting the current
// environment. It also loads a .env file on startup (see .env.example).
//
// If `air` is on PATH it runs under air for hot reload on Go source edits.
// Otherwise it builds once and runs the binary directly. Install air with:
//
//	go install github.com/air-verse/air@latest
func (Run) Backend() error {
	if path, err := exec.LookPath("air"); err == nil {
		fmt.Println("starting", binName, "with hot reload (air)")
		return sh.RunV(path)
	}
	fmt.Println("air not found; running without hot reload (go install github.com/air-verse/air@latest to enable)")
	mg.Deps(Build.Backend)
	fmt.Println("starting", binName)
	return sh.RunV("./" + binName)
}

// UI runs the Vite dev server with hot module reload. It proxies API calls to
// the backend, so run `mage run:backend` alongside it. Installs npm deps on
// first run.
func (Run) UI() error {
	if err := ensureUIDeps(); err != nil {
		return err
	}
	fmt.Println("starting Vite dev server (proxies the Connect API to the backend)")
	return sh.RunV("npm", "--prefix", uiDir, "run", "dev")
}

// ---- test ----

// Test groups the test targets: `mage test:unit` and `mage test:integration`.
type Test mg.Namespace

// Unit runs the unit tests (no external dependencies).
func (Test) Unit() error {
	fmt.Println("running unit tests")
	return sh.RunV("go", "test", "./...")
}

// Integration runs the integration tests (end-to-end over an in-process
// server). They are ordinary Go tests behind the `integration` build tag.
func (Test) Integration() error {
	fmt.Println("running integration tests")
	return sh.RunV("go", "test", "-tags", "integration", "./...", "-run", "Integration", "-v")
}

// ---- fmt ----

// Fmt groups formatting targets: `mage fmt:all|backend|ui`.
type Fmt mg.Namespace

// All formats both the backend and the UI.
func (Fmt) All() {
	mg.Deps(Fmt.Backend, Fmt.UI)
}

// Backend formats all Go source with gofmt.
func (Fmt) Backend() error {
	fmt.Println("formatting Go source")
	return sh.RunV("gofmt", "-w", ".")
}

// UI formats the web UI with oxfmt (the oxc formatter).
func (Fmt) UI() error {
	fmt.Println("formatting UI (oxfmt)")
	return npmRun("format")
}

// ---- vet ----

// Vet groups static-analysis targets: `mage vet:all|backend|ui`.
type Vet mg.Namespace

// All vets both the backend and the UI.
func (Vet) All() {
	mg.Deps(Vet.Backend, Vet.UI)
}

// Backend runs the Go static-analysis gate: `go vet` plus golangci-lint if it is
// installed, otherwise a gofmt formatting check as a lightweight fallback.
func (Vet) Backend() error {
	fmt.Println("vetting Go source")
	if err := sh.RunV("go", "vet", "./..."); err != nil {
		return err
	}
	if _, err := exec.LookPath("golangci-lint"); err == nil {
		fmt.Println("running golangci-lint")
		return sh.RunV("golangci-lint", "run")
	}
	fmt.Println("golangci-lint not found; checking formatting with gofmt")
	out, err := sh.Output("gofmt", "-l", ".")
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) != "" {
		return fmt.Errorf("these files need formatting (run `mage fmt:backend`):\n%s", out)
	}
	return nil
}

// UI lints the web UI with oxlint.
func (Vet) UI() error {
	fmt.Println("linting UI (oxlint)")
	return npmRun("lint")
}

// ---- clean ----

// Clean groups cleanup targets: `mage clean:all|backend|ui`.
type Clean mg.Namespace

// All removes both backend and UI build artifacts.
func (Clean) All() {
	mg.Deps(Clean.Backend, Clean.UI)
}

// Backend removes the compiled binary.
func (Clean) Backend() error {
	fmt.Println("cleaning backend")
	if err := os.Remove(binName); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// UI removes the generated UI build output, leaving ui/dist at its checked-in
// state: just the tracked .gitkeep.
func (Clean) UI() error {
	fmt.Println("cleaning UI build output")
	if err := sh.RunV("git", "checkout", "--", uiDir+"/dist/.gitkeep"); err != nil {
		return err
	}
	return sh.RunV("git", "clean", "-fdX", "--", uiDir+"/dist")
}

// ---- aggregate / misc ----

// Check runs the backend quality gate: vet (vet + lint) then unit tests.
func Check() error {
	mg.SerialDeps(Vet.Backend, Test.Unit)
	return nil
}

// ResetDB deletes the SQLite database (and its WAL/SHM sidecar files) so the
// next server start bootstraps a fresh admin credential. Honors DB_PATH;
// defaults to turnstile.db. Missing files are ignored, so it is safe anytime.
func ResetDB() error {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "turnstile.db"
	}
	for _, p := range []string{dbPath, dbPath + "-shm", dbPath + "-wal"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	fmt.Printf("reset database at %s — the next start will print a new bootstrap admin token\n", dbPath)
	return nil
}
