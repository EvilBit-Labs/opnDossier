package shared_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/schema/shared"
)

func TestIsValueTrue(t *testing.T) {
	t.Parallel()

	truthy := []string{
		"1", "on", "yes", "true", "enable", "enabled",
		"On", "ON", "oN",
		"Yes", "YES",
		"True", "TRUE",
		"Enable", "ENABLE",
		"Enabled", "ENABLED",
		" on ", "\ton\n", "  1  ",
	}

	for _, s := range truthy {
		t.Run("truthy/"+s, func(t *testing.T) {
			t.Parallel()
			if !shared.IsValueTrue(s) {
				t.Errorf("IsValueTrue(%q) = false, want true", s)
			}
			if shared.IsValueFalse(s) {
				t.Errorf("IsValueFalse(%q) = true, want false (truthy value)", s)
			}
		})
	}
}

func TestIsValueFalse(t *testing.T) {
	t.Parallel()

	falsy := []string{
		"0", "off", "no", "false", "disable", "disabled", "",
		"Off", "OFF",
		"No", "NO",
		"False", "FALSE",
		"Disable", "DISABLE",
		"Disabled", "DISABLED",
		" ", "\t", "\n", "   ",
		" off ", "\tno\n",
	}

	for _, s := range falsy {
		t.Run("falsy/"+s, func(t *testing.T) {
			t.Parallel()
			if !shared.IsValueFalse(s) {
				t.Errorf("IsValueFalse(%q) = false, want true", s)
			}
			if shared.IsValueTrue(s) {
				t.Errorf("IsValueTrue(%q) = true, want false (falsy value)", s)
			}
		})
	}
}

func TestIsValueTrue_Unknown(t *testing.T) {
	t.Parallel()

	// Unknown values must return false from BOTH helpers so callers can
	// distinguish them from explicit truthy/falsy values if needed.
	unknown := []string{"banana", "2", "-1", "foo", "truthy", "yesiree"}

	for _, s := range unknown {
		t.Run("unknown/"+s, func(t *testing.T) {
			t.Parallel()
			if shared.IsValueTrue(s) {
				t.Errorf("IsValueTrue(%q) = true, want false (unknown)", s)
			}
			if shared.IsValueFalse(s) {
				t.Errorf("IsValueFalse(%q) = true, want false (unknown)", s)
			}
		})
	}
}
