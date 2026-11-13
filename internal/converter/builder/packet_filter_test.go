package builder

import (
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// TestBuildSecuritySection_PacketFilterDisabled checks that the security
// section opens with a warning when pf is off, ahead of the NAT and rule tables
// it makes moot, and says nothing about it when pf is on.
func TestBuildSecuritySection_PacketFilterDisabled(t *testing.T) {
	t.Parallel()

	const warning = "All packet filtering is disabled"

	for _, disabled := range []bool{false, true} {
		out := NewMarkdownBuilder().BuildSecuritySection(&common.CommonDevice{
			System: common.System{PacketFilterDisabled: disabled},
		})

		at := strings.Index(out, warning)
		if (at >= 0) != disabled {
			t.Errorf("disabled=%v: warning present = %v:\n%s", disabled, at >= 0, out)

			continue
		}

		if disabled && at > strings.Index(out, "NAT Configuration") {
			t.Errorf("warning follows the NAT section:\n%s", out)
		}
	}
}
