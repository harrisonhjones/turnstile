// Package policy implements a domain-agnostic, statement-based authorization
// evaluator inspired by AWS IAM / Service Control Policies.
//
// A Statement grants (allow) or blocks (deny) a set of actions on a set of
// resources. Actions and resources are opaque strings — Turnstile never parses
// them. By convention a host namespaces them with its service name
// ("beeper:sendMessage", "beeper:chat:!abc"), which is what isolates one
// project's grants from another's ("beeper:*" can't match "plaid:*"); the
// engine itself knows nothing about the prefix.
//
// Statements are evaluated in order against a requested action and the
// resource(s) identifying the target object:
//
//   - A matching deny wins immediately (short-circuit).
//   - Otherwise, the first matching allow grants access.
//   - If nothing matches, the action is denied (implicit deny).
//
// The global service policy is evaluated before per-key statements, so a global
// deny can never be overridden by a key-level allow. The global policy is a
// restriction ceiling (like an AWS SCP): callers should validate it with
// ValidateGlobalStatements, which permits deny statements only. This matters
// because Evaluate treats the merged list uniformly — the first matching allow
// from anywhere grants access — so a global allow would be additive to every
// key, not a restriction. Restricting the global layer to deny-only preserves
// the ceiling semantics.
//
// # Multiple resource representations
//
// A single object is often reachable by more than one resource identity. A
// chat, for example, might be named both by its own id and by the account it
// belongs to. Evaluate accepts all representations of the target object; a
// statement's resource pattern matches if it matches ANY of them. This is what
// lets a broad resource pattern grant access to a whole class of objects
// without listing each one.
package policy

import "strings"

// Effect is the outcome a statement applies when it matches.
type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

// Statement is a single allow/deny rule over actions and resources.
type Statement struct {
	Effect    Effect   `json:"effect"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
	Note      string   `json:"note,omitempty"`
}

// Decision is the result of evaluating a request against a set of statements.
type Decision struct {
	Allowed bool
	// Matched is the statement that determined the outcome, or nil on implicit
	// deny (no statement matched).
	Matched *Statement
}

// Evaluate decides whether action is permitted on the object identified by the
// given resource representations, given an ordered list of statements.
//
// Statements should already be merged in precedence order (global first, then
// per-key). A matching deny short-circuits; otherwise the first matching allow
// wins; otherwise the result is an implicit deny.
func Evaluate(statements []Statement, action string, resources ...string) Decision {
	var firstAllow *Statement
	for i := range statements {
		s := &statements[i]
		if !s.matches(action, resources) {
			continue
		}
		if s.Effect == Deny {
			return Decision{Allowed: false, Matched: s}
		}
		if firstAllow == nil {
			firstAllow = s
		}
	}
	if firstAllow != nil {
		return Decision{Allowed: true, Matched: firstAllow}
	}
	return Decision{Allowed: false, Matched: nil}
}

// matches reports whether the statement applies to the given action and any of
// the object's resource representations.
func (s *Statement) matches(action string, resources []string) bool {
	if !anyPatternMatches(s.Actions, action) {
		return false
	}
	for _, r := range resources {
		if anyPatternMatches(s.Resources, r) {
			return true
		}
	}
	return false
}

func anyPatternMatches(patterns []string, value string) bool {
	for _, p := range patterns {
		if matchPattern(p, value) {
			return true
		}
	}
	return false
}

// matchPattern matches a value against a pattern supporting a single trailing
// '*' wildcard. "*" matches anything; "foo*" matches any value with prefix
// "foo"; otherwise matching is exact.
func matchPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	}
	return pattern == value
}
