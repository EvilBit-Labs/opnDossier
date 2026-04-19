package opnsense_test

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// findKeaScope returns the Kea-sourced DHCPScope whose description matches.
// Fails the test fatally when no such scope exists so caller assertions do
// not dereference a nil scope.
func findKeaScope(t *testing.T, scopes []common.DHCPScope, description string) *common.DHCPScope {
	t.Helper()
	for i := range scopes {
		if scopes[i].Source == common.DHCPSourceKea && scopes[i].Description == description {
			return &scopes[i]
		}
	}
	t.Fatalf("kea scope %q not found in %d scopes", description, len(scopes))
	return nil
}

// findWarning returns the first [common.ConversionWarning] whose Field equals
// field and Value equals value. Returns nil when no matching warning exists.
// Caller is responsible for `require.NotNil` when presence is required.
func findWarning(warnings []common.ConversionWarning, field, value string) *common.ConversionWarning {
	for i := range warnings {
		if warnings[i].Field == field && warnings[i].Value == value {
			return &warnings[i]
		}
	}
	return nil
}
