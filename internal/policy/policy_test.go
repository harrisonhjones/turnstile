package policy

import "testing"

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name       string
		statements []Statement
		action     string
		resources  []string
		want       bool
	}{
		{
			name:       "implicit deny with no statements",
			statements: nil,
			action:     "svc:read",
			resources:  []string{"svc:thing:1"},
			want:       false,
		},
		{
			name: "first allow grants",
			statements: []Statement{
				{Effect: Allow, Actions: []string{"svc:read"}, Resources: []string{"svc:thing:*"}},
			},
			action:    "svc:read",
			resources: []string{"svc:thing:1"},
			want:      true,
		},
		{
			name: "no matching action is implicit deny",
			statements: []Statement{
				{Effect: Allow, Actions: []string{"svc:write"}, Resources: []string{"*"}},
			},
			action:    "svc:read",
			resources: []string{"svc:thing:1"},
			want:      false,
		},
		{
			name: "deny wins over an earlier allow",
			statements: []Statement{
				{Effect: Allow, Actions: []string{"svc:read"}, Resources: []string{"*"}},
				{Effect: Deny, Actions: []string{"svc:read"}, Resources: []string{"svc:secret:*"}},
			},
			action:    "svc:read",
			resources: []string{"svc:secret:1"},
			want:      false,
		},
		{
			name: "deny wins even when it appears before the allow",
			statements: []Statement{
				{Effect: Deny, Actions: []string{"svc:read"}, Resources: []string{"svc:secret:*"}},
				{Effect: Allow, Actions: []string{"svc:read"}, Resources: []string{"*"}},
			},
			action:    "svc:read",
			resources: []string{"svc:secret:1"},
			want:      false,
		},
		{
			name: "matches any of several resource representations (OR)",
			statements: []Statement{
				{Effect: Allow, Actions: []string{"svc:read"}, Resources: []string{"account:wa*"}},
			},
			action:    "svc:read",
			resources: []string{"chat:!abc", "account:wa123"}, // second representation matches
			want:      true,
		},
		{
			name: "star action and star resource is full access",
			statements: []Statement{
				{Effect: Allow, Actions: []string{"*"}, Resources: []string{"*"}},
			},
			action:    "anything:goes",
			resources: []string{"whatever:1"},
			want:      true,
		},
		{
			name: "namespace isolation: beeper allow does not match plaid action",
			statements: []Statement{
				{Effect: Allow, Actions: []string{"beeper:*"}, Resources: []string{"*"}},
			},
			action:    "plaid:read",
			resources: []string{"plaid:acct:1"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.statements, tt.action, tt.resources...)
			if got.Allowed != tt.want {
				t.Errorf("Evaluate() allowed = %v, want %v (matched=%v)", got.Allowed, tt.want, got.Matched)
			}
		})
	}
}

func TestEvaluateLayers(t *testing.T) {
	global := []Statement{{Effect: Deny, Actions: []string{"svc:danger"}, Resources: []string{"*"}}}
	key := []Statement{{Effect: Allow, Actions: []string{"svc:*"}, Resources: []string{"*"}}}

	// A deny in the earlier (global) layer wins over an allow in a later layer.
	if EvaluateLayers("svc:danger", []string{"svc:x"}, global, key).Allowed {
		t.Error("global deny must override a later key allow")
	}
	// The key's allow still grants a benign action.
	if !EvaluateLayers("svc:read", []string{"svc:x"}, global, key).Allowed {
		t.Error("key allow should grant svc:read")
	}
	// Layered evaluation matches Evaluate on the concatenation.
	merged := append(append([]Statement{}, global...), key...)
	for _, action := range []string{"svc:danger", "svc:read", "other:thing"} {
		layered := EvaluateLayers(action, []string{"svc:x"}, global, key)
		concat := Evaluate(merged, action, "svc:x")
		if layered.Allowed != concat.Allowed {
			t.Errorf("action %q: layered=%v concat=%v", action, layered.Allowed, concat.Allowed)
		}
	}
	// No layers → implicit deny.
	if EvaluateLayers("svc:read", []string{"svc:x"}).Allowed {
		t.Error("no layers should be an implicit deny")
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{"*", "anything", true},
		{"foo*", "foobar", true},
		{"foo*", "foo", true},
		{"foo*", "fo", false},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		{"beeper:", "beeper:sendMessage", false}, // no trailing star = exact
		{"beeper:*", "beeper:sendMessage", true},
	}
	for _, tt := range tests {
		if got := matchPattern(tt.pattern, tt.value); got != tt.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

func TestGrantsAction(t *testing.T) {
	tests := []struct {
		name       string
		statements []Statement
		action     string
		want       bool
	}{
		{
			name:       "no allow means false",
			statements: []Statement{{Effect: Deny, Actions: []string{"svc:x"}, Resources: []string{"a:1"}}},
			action:     "svc:x",
			want:       false,
		},
		{
			name:       "allow with scoped resource means true",
			statements: []Statement{{Effect: Allow, Actions: []string{"svc:x"}, Resources: []string{"a:*"}}},
			action:     "svc:x",
			want:       true,
		},
		{
			name: "blanket deny on the action means false",
			statements: []Statement{
				{Effect: Allow, Actions: []string{"svc:x"}, Resources: []string{"a:*"}},
				{Effect: Deny, Actions: []string{"svc:x"}, Resources: []string{"*"}},
			},
			action: "svc:x",
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GrantsAction(tt.statements, tt.action); got != tt.want {
				t.Errorf("GrantsAction() = %v, want %v", got, tt.want)
			}
		})
	}
}
