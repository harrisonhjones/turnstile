// Package token handles authentication and authorization for Turnstile.
//
// There is one kind of secret: an API key ("tsk_…"), an opaque, high-entropy
// string whose SHA-256 hash is all that is stored (looked up by hash, so there
// is no plaintext to leak and no constant-time-comparison concern). Authenticate
// validates one and yields a Principal.
//
// There is no separate "admin credential": the management API is guarded by the
// same keys and policy engine as everything else. A key manages Turnstile when
// its policy allows the relevant "turnstile:<op>" action (see the server's
// requireManage), evaluated against the caller's own statements.
//
// The Authorizer evaluates a caller's key statements merged beneath the global
// deny-only policy (see the policy package) for the hot path, or the key's own
// statements alone for management actions, against an action and one or more
// resource representations of the target object.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// APIKeyPrefix marks a client/management API key secret ("tsk_…").
const APIKeyPrefix = "tsk_"

// NewID returns a typed, namespaced random identifier of the form
// "turnstile:<typ>:<random-hex>", e.g. NewID("key") -> "turnstile:key:1a2b3c…".
// The id doubles as the authorization resource for per-object management actions
// (a key's id is the resource of turnstile:*-key actions targeting it), and sets
// the pattern for future object types (turnstile:user:<random>).
//
// It panics if the system CSPRNG fails: crypto/rand.Read essentially never
// errors on a healthy host, and continuing with a predictable (all-zero) ID
// would be worse than crashing — a silently non-random ID could collide or be
// guessable.
func NewID(typ string) string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("token: crypto/rand failed generating ID: %v", err))
	}
	return "turnstile:" + typ + ":" + hex.EncodeToString(buf)
}

// Generate creates a new random secret with the given prefix and returns the
// plaintext alongside its SHA-256 hash. Only the hash should be persisted; the
// plaintext is shown to the operator exactly once.
func Generate(prefix string) (plaintext, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate random token: %w", err)
	}
	// URL-safe, unpadded so the token is a clean single word.
	plaintext = prefix + base64.RawURLEncoding.EncodeToString(buf)
	return plaintext, Hash(plaintext), nil
}

// Hash returns the hex-encoded SHA-256 hash of a secret. Used both when issuing
// and when validating a presented token or credential.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ExtractBearer pulls the token from an "Authorization: Bearer <token>" header
// value. Returns an empty string if the header is missing or malformed.
func ExtractBearer(header string) string {
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}
