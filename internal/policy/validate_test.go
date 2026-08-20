package policy

import "testing"

func TestValidateStatements(t *testing.T) {
	tests := []struct {
		name       string
		statements []Statement
		wantErr    bool
	}{
		{"empty is invalid", nil, true},
		{
			"valid allow",
			[]Statement{{Effect: Allow, Actions: []string{"svc:read"}, Resources: []string{"a:*"}}},
			false,
		},
		{
			"bad effect",
			[]Statement{{Effect: Effect("maybe"), Actions: []string{"a"}, Resources: []string{"b"}}},
			true,
		},
		{
			"no actions",
			[]Statement{{Effect: Allow, Actions: nil, Resources: []string{"b"}}},
			true,
		},
		{
			"no resources",
			[]Statement{{Effect: Allow, Actions: []string{"a"}, Resources: nil}},
			true,
		},
		{
			"mid-pattern wildcard rejected",
			[]Statement{{Effect: Allow, Actions: []string{"sv*c"}, Resources: []string{"b"}}},
			true,
		},
		{
			"empty entry rejected",
			[]Statement{{Effect: Allow, Actions: []string{""}, Resources: []string{"b"}}},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStatements(tt.statements)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateStatements() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateGlobalStatements(t *testing.T) {
	t.Run("empty is valid (no restrictions)", func(t *testing.T) {
		if err := ValidateGlobalStatements(nil); err != nil {
			t.Errorf("empty global policy should be valid, got %v", err)
		}
	})
	t.Run("deny-only is valid", func(t *testing.T) {
		s := []Statement{{Effect: Deny, Actions: []string{"svc:*"}, Resources: []string{"*"}}}
		if err := ValidateGlobalStatements(s); err != nil {
			t.Errorf("deny-only global policy should be valid, got %v", err)
		}
	})
	t.Run("allow in global policy is rejected", func(t *testing.T) {
		s := []Statement{{Effect: Allow, Actions: []string{"svc:*"}, Resources: []string{"*"}}}
		if err := ValidateGlobalStatements(s); err == nil {
			t.Error("allow statement in global policy should be rejected")
		}
	})
}
