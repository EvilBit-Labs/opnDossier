//go:build deadcode

package internal

// deadcode_logic_test.go unit-tests the pure allowlist logic in
// deadcode_test.go (parseDeadcodeAllowlist, checkDeadcodeAllowlist) against
// fabricated inputs, independent of the deadcode binary and the filesystem.
//
// These are the automated stand-ins for the plan's "mutate the tree and
// rerun" test scenarios: rather than injecting a real unreferenced function
// into a live package (invasive, and racy under `t.Parallel()` in a shared
// module), each scenario is reproduced as a fabricated deadcode-symbol list
// and allowlist, exercising exactly the same violation-detection code path
// TestDeadCodeGuard runs against the real tree.

import (
	"bufio"
	"strings"
	"testing"
)

func sym(path, name string) deadcodeSymbol {
	return deadcodeSymbol{Path: path, Name: name}
}

// TestCheckDeadcodeAllowlist_UnlistedSymbolFails covers: an unreferenced
// exported function with no allowlist entry makes the guard fail and name
// it.
func TestCheckDeadcodeAllowlist_UnlistedSymbolFails(t *testing.T) {
	t.Parallel()

	found := []deadcodeSymbol{sym("pkgpath", "NewThing")}

	result := checkDeadcodeAllowlist(found, nil)

	if len(result.Unlisted) != 1 || result.Unlisted[0] != found[0] {
		t.Fatalf("expected exactly %v unlisted, got %v", found, result.Unlisted)
	}

	if len(result.Stale) != 0 || len(result.BadClass) != 0 || len(result.BadReason) != 0 {
		t.Fatalf("expected no other violations, got %+v", result)
	}
}

// TestCheckDeadcodeAllowlist_ValidEntryPasses covers: adding that same
// function to the allowlist with a class and reason makes the guard pass.
func TestCheckDeadcodeAllowlist_ValidEntryPasses(t *testing.T) {
	t.Parallel()

	target := sym("pkgpath", "NewThing")
	found := []deadcodeSymbol{target}
	allowlist := []deadcodeAllowlistEntry{
		{Symbol: target, Class: "public-surface", Reason: "exercised only via reflection in a downstream tool"},
	}

	result := checkDeadcodeAllowlist(found, allowlist)

	if len(result.Unlisted) != 0 || len(result.Stale) != 0 || len(result.BadClass) != 0 || len(result.BadReason) != 0 {
		t.Fatalf("expected a clean result, got %+v", result)
	}
}

// TestCheckDeadcodeAllowlist_MissingClassOrReasonFails covers: an allowlist
// entry with no class, or no reason text, fails the guard.
func TestCheckDeadcodeAllowlist_MissingClassOrReasonFails(t *testing.T) {
	t.Parallel()

	tests := map[string]deadcodeAllowlistEntry{
		"empty class":        {Class: "", Reason: "a reason"},
		"unrecognized class": {Class: "because-i-said-so", Reason: "a reason"},
		"empty reason":       {Class: "public-surface", Reason: ""},
	}

	for name, entry := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			target := sym("pkgpath", "NewThing")
			entry.Symbol = target
			found := []deadcodeSymbol{target}

			result := checkDeadcodeAllowlist(found, []deadcodeAllowlistEntry{entry})

			wantBadClass := !deadcodeAllowlistClasses[entry.Class]
			wantBadReason := entry.Reason == ""

			if gotBadClass := len(result.BadClass) == 1; gotBadClass != wantBadClass {
				t.Errorf("BadClass = %v, want %v", result.BadClass, wantBadClass)
			}

			if gotBadReason := len(result.BadReason) == 1; gotBadReason != wantBadReason {
				t.Errorf("BadReason = %v, want %v", result.BadReason, wantBadReason)
			}

			if len(result.Unlisted) != 0 {
				t.Errorf("expected the symbol to be matched (not unlisted), got %v", result.Unlisted)
			}
		})
	}
}

// TestCheckDeadcodeAllowlist_StaleEntryFails covers: an allowlist entry
// naming a symbol that no longer exists among the currently-unreachable
// symbols fails the guard (R11) -- whether because the symbol was deleted,
// renamed, or has become reachable.
func TestCheckDeadcodeAllowlist_StaleEntryFails(t *testing.T) {
	t.Parallel()

	stale := sym("pkgpath", "LongGoneFunc")
	allowlist := []deadcodeAllowlistEntry{
		{Symbol: stale, Class: "public-surface", Reason: "used to be exempt"},
	}

	// found is empty: nothing currently unreachable matches the entry.
	result := checkDeadcodeAllowlist(nil, allowlist)

	if len(result.Stale) != 1 || result.Stale[0].Symbol != stale {
		t.Fatalf("expected %v to be reported stale, got %v", stale, result.Stale)
	}
}

// TestParseDeadcodeAllowlist_ValidFile covers the documented format,
// including comments, blank lines, and a real-shaped entry.
func TestParseDeadcodeAllowlist_ValidFile(t *testing.T) {
	t.Parallel()

	input := `# a comment
` + "\n" + `pkg/schema/shared|FlexBool.UnmarshalXML|reflection-dispatched|encoding/xml invokes it via reflection

pkg/model|NewThing|public-surface|snapshot-locked public surface
`

	entries, err := parseDeadcodeAllowlist(bufio.NewScanner(strings.NewReader(input)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(entries), entries)
	}

	if entries[0].Symbol != sym("pkg/schema/shared", "FlexBool.UnmarshalXML") {
		t.Errorf("entry[0].Symbol = %v", entries[0].Symbol)
	}

	if entries[0].Class != "reflection-dispatched" {
		t.Errorf("entry[0].Class = %q", entries[0].Class)
	}
}

// TestParseDeadcodeAllowlist_MalformedLines covers the parser's error paths:
// wrong field count, empty path/symbol, and duplicate entries.
func TestParseDeadcodeAllowlist_MalformedLines(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"too few fields":  "pkg/model|NewThing|public-surface\n",
		"empty path":      "|NewThing|public-surface|a reason\n",
		"empty symbol":    "pkg/model||public-surface|a reason\n",
		"duplicate entry": "pkg/model|NewThing|public-surface|a reason\npkg/model|NewThing|public-surface|again\n",
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := parseDeadcodeAllowlist(bufio.NewScanner(strings.NewReader(input)))
			if err == nil {
				t.Fatalf("expected an error for input %q, got none", input)
			}
		})
	}
}

// TestCheckDeadcodeAllowlist_ReflectionDispatchedEntryDoesNotFail covers:
// shared.FlexBool.UnmarshalXML, seeded in the real allowlist as
// reflection-dispatched, does not fail the guard.
func TestCheckDeadcodeAllowlist_ReflectionDispatchedEntryDoesNotFail(t *testing.T) {
	t.Parallel()

	target := sym("github.com/EvilBit-Labs/opnDossier/pkg/schema/shared", "FlexBool.UnmarshalXML")
	found := []deadcodeSymbol{target}
	allowlist := []deadcodeAllowlistEntry{
		{
			Symbol: target,
			Class:  "reflection-dispatched",
			Reason: "encoding/xml invokes UnmarshalXML via reflection; never a static call deadcode's RTA can see",
		},
	}

	result := checkDeadcodeAllowlist(found, allowlist)

	if len(result.Unlisted) != 0 || len(result.Stale) != 0 || len(result.BadClass) != 0 || len(result.BadReason) != 0 {
		t.Fatalf("expected a clean result, got %+v", result)
	}
}
