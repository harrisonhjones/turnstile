package policy

// GrantsAction reports whether the given statements could ever allow action on
// some resource. It is a coarse, resource-independent check — NOT an
// authorization decision (per-call, per-resource enforcement still runs via
// Evaluate). It is useful for surfacing capability in a UI without a concrete
// resource in hand.
//
// It returns true when at least one allow statement matches the action and no
// deny statement blanket-denies it (matches the action with a "*" resource).
// So:
//   - no allow matches the action           → false (calls will always be denied)
//   - an allow matches, no blanket deny      → true  (calls may succeed, subject
//     to per-resource checks)
//   - a blanket deny matches the action      → false
func GrantsAction(statements []Statement, action string) bool {
	var hasAllow bool
	for i := range statements {
		s := &statements[i]
		if !anyPatternMatches(s.Actions, action) {
			continue
		}
		switch s.Effect {
		case Deny:
			// A deny on this action for all resources ("*") can never be
			// escaped, so the action is effectively unavailable.
			if anyPatternMatches(s.Resources, "*") {
				return false
			}
		case Allow:
			hasAllow = true
		}
	}
	return hasAllow
}
