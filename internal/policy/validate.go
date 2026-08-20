package policy

import (
	"fmt"
	"strings"
)

// ValidateStatements checks that a set of statements is well-formed. It is used
// when creating/updating API keys and when updating the global policy, so both
// surfaces reject the same malformed input.
//
// Rules:
//   - at least one statement
//   - effect is "allow" or "deny"
//   - actions and resources are non-empty, with no empty entries
//   - a "*" wildcard appears only as a trailing character (matchPattern only
//     honors it there, so a mid-pattern "*" is a silent no-op and almost
//     certainly a mistake)
func ValidateStatements(statements []Statement) error {
	if len(statements) == 0 {
		return fmt.Errorf("at least one statement is required")
	}
	for i, s := range statements {
		if s.Effect != Allow && s.Effect != Deny {
			return fmt.Errorf("statement %d: effect must be %q or %q, got %q", i, Allow, Deny, s.Effect)
		}
		if len(s.Actions) == 0 {
			return fmt.Errorf("statement %d: at least one action is required", i)
		}
		if len(s.Resources) == 0 {
			return fmt.Errorf("statement %d: at least one resource is required", i)
		}
		for _, a := range s.Actions {
			if err := validatePattern(a); err != nil {
				return fmt.Errorf("statement %d: action %q: %w", i, a, err)
			}
		}
		for _, r := range s.Resources {
			if err := validatePattern(r); err != nil {
				return fmt.Errorf("statement %d: resource %q: %w", i, r, err)
			}
		}
	}
	return nil
}

// ValidateGlobalStatements validates the global service policy. Beyond the
// well-formedness checks in ValidateStatements, it requires every statement to
// be a Deny: the global policy is a ceiling (like an AWS SCP), so it may only
// take capabilities away, never grant them. An Allow at the global level would
// be additive to every key — see the package doc — which is almost never what
// an operator intends. An empty global policy is valid (no restrictions).
func ValidateGlobalStatements(statements []Statement) error {
	for i, s := range statements {
		if s.Effect != Deny {
			return fmt.Errorf("statement %d: the global policy may only contain deny statements (it is a restriction ceiling, not a grant); got effect %q", i, s.Effect)
		}
	}
	// Reuse the well-formedness checks for non-empty policies. An empty global
	// policy is allowed, so only validate when there is at least one statement.
	if len(statements) == 0 {
		return nil
	}
	return ValidateStatements(statements)
}

// validatePattern rejects empty patterns and any "*" that isn't a lone "*" or a
// single trailing wildcard.
func validatePattern(p string) error {
	if p == "" {
		return fmt.Errorf("must not be empty")
	}
	if p == "*" {
		return nil
	}
	if i := strings.IndexByte(p, '*'); i != -1 && i != len(p)-1 {
		return fmt.Errorf("'*' is only allowed as a trailing wildcard")
	}
	return nil
}
