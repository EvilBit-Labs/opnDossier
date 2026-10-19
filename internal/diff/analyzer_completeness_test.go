package diff

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// varyField gives v a value different from its zero, for the kinds the models
// use. Returns false for kinds it has no probe for.
func varyField(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		v.SetString("diff-probe")

		return true
	case reflect.Bool:
		v.SetBool(!v.Bool())

		return true
	case reflect.Int:
		v.SetInt(v.Int() + 1)

		return true
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))

		return true
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))

		return true
	case reflect.Struct:
		for _, f := range v.Fields() {
			if f.Kind() == reflect.String && f.CanSet() {
				f.SetString("diff-probe")

				return true
			}
		}

		return false
	default:
		return false
	}
}

// fillValue gives v non-zero content all the way down. Every pointer and slice
// is a fresh allocation, as it is in each parse of a config.
func fillValue(t *testing.T, v reflect.Value) {
	t.Helper()

	switch v.Kind() {
	case reflect.String:
		v.SetString("filled")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int:
		v.SetInt(1)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fillValue(t, v.Index(0))
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fillValue(t, v.Elem())
	case reflect.Struct:
		for _, f := range v.Fields() {
			fillValue(t, f)
		}
	default:
		require.Failf(t, "no fill for this kind", "%s", v.Kind())
	}
}

// varyLeaves changes each scalar reachable from a filled v through structs,
// pointers and slices, one at a time, and calls check while it is changed.
func varyLeaves(t *testing.T, v reflect.Value, path string, check func(path string)) {
	t.Helper()

	switch v.Kind() {
	case reflect.Struct:
		for i := range v.NumField() {
			varyLeaves(t, v.Field(i), path+"."+v.Type().Field(i).Name, check)
		}
	case reflect.Pointer:
		varyLeaves(t, v.Elem(), path, check)
	case reflect.Slice:
		varyLeaves(t, v.Index(0), path+"[0]", check)
	default:
		saved := reflect.New(v.Type()).Elem()
		saved.Set(v)
		require.Truef(t, varyField(v), "no probe for %s (%s)", path, v.Kind())
		check(path)
		v.Set(saved)
	}
}

// assertEqualityCoversEveryField varies each field of a zero value in turn and
// asserts the equality helper notices, so a field added to the model without
// being added to the helper fails here rather than silently disappearing from
// every diff.
//
// It then checks the helper compares by value. The zero values of the first
// pass hold no reference, and that pass only asserts that a change is noticed,
// so a helper that compares a pointer and not what it points to passes it while
// reporting every unchanged item that holds a reference as modified. Two values
// filled separately must compare equal, and a change to any leaf of either must
// be noticed.
func assertEqualityCoversEveryField[T any](t *testing.T, equal func(a, b T) bool, ignored map[string]string) {
	t.Helper()

	var zero T
	typ := reflect.TypeOf(zero)
	require.Equal(t, reflect.Struct, typ.Kind())

	for i := range typ.NumField() {
		name := typ.Field(i).Name

		if reason, skip := ignored[name]; skip {
			t.Logf("skipping %s: %s", name, reason)

			continue
		}

		var a, b T
		bv := reflect.ValueOf(&b).Elem().Field(i)

		if !varyField(bv) {
			t.Logf("skipping %s: no probe for kind %s", name, bv.Kind())

			continue
		}

		assert.Falsef(t, equal(a, b),
			"%s is not compared, so a change to it produces no diff entry; add it to the equality helper", name)
	}

	filled := func() T {
		var x T
		fillValue(t, reflect.ValueOf(&x).Elem())

		return x
	}

	require.True(t, equal(filled(), filled()),
		"equal content held in separate allocations compares unequal, so an unchanged item is reported as modified")

	for i := range typ.NumField() {
		name := typ.Field(i).Name

		if _, skip := ignored[name]; skip {
			continue
		}

		a, b := filled(), filled()

		varyLeaves(t, reflect.ValueOf(&b).Elem().Field(i), name, func(path string) {
			assert.Falsef(t, equal(a, b), "%s is not compared by value, so a change to it produces no diff entry", path)
		})
	}
}

// TestRulesEqual_ComparesEveryFirewallRuleField guards the silent
// under-reporting that motivated the rewrite: rulesEqual covered seven of the
// model's thirty-three fields, so flipping a rule's direction, making it
// floating, moving it to another gateway or turning its logging off all
// produced "no changes detected".
func TestRulesEqual_ComparesEveryFirewallRuleField(t *testing.T) {
	t.Parallel()

	assertEqualityCoversEveryField(t, rulesEqual, map[string]string{
		"UUID":    "identity; CompareFirewallRules pairs on it",
		"Tracker": "identity; compareRulesWithoutUUID pairs on it",
	})
}

// TestUsersEqual_ComparesEveryUserField guards the same class on users, where
// UID and APIKeys were omitted.
func TestUsersEqual_ComparesEveryUserField(t *testing.T) {
	t.Parallel()

	assertEqualityCoversEveryField(t, usersEqual, nil)
}

// TestCompareFirewallRules_NoUUID_DetectsContentChange is the end-to-end half.
// pfSense rules never carry a uuid element, and the fallback compared only the
// rule COUNT, so a rule flipped from pass to block reported no changes at all.
func TestCompareFirewallRules_NoUUID_DetectsContentChange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func([]common.FirewallRule)
	}{
		{"action flipped to block", func(r []common.FirewallRule) { r[0].Type = common.RuleTypeBlock }},
		{"source widened to any", func(r []common.FirewallRule) {
			r[0].Source = common.RuleEndpoint{Address: "any"}
		}},
		{"logging turned off", func(r []common.FirewallRule) { r[0].Log = false }},
		{"direction reversed", func(r []common.FirewallRule) { r[0].Direction = common.DirectionOut }},
		{"made floating", func(r []common.FirewallRule) { r[0].Floating = true }},
		{"gateway redirected", func(r []common.FirewallRule) { r[0].Gateway = "GW_BACKUP" }},
	}

	newBase := func() []common.FirewallRule {
		return []common.FirewallRule{
			{
				Type: common.RuleTypePass, Description: "web", Interfaces: []string{"wan"}, Log: true,
				Source: common.RuleEndpoint{Address: "198.51.100.0/24"},
			},
			{
				Type: common.RuleTypeBlock, Description: "deny", Interfaces: []string{"wan"}, Log: true,
				Source: common.RuleEndpoint{Address: "any"},
			},
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			old := newBase()
			newCfg := newBase()
			tt.mutate(newCfg)

			changes := NewAnalyzer().CompareFirewallRules(old, newCfg)

			require.NotEmpty(t, changes, "a rule content change must produce a diff entry")
			assert.Len(t, changes, 1, "exactly the changed rule should be reported: %+v", changes)
			assert.Equal(t, ChangeModified, changes[0].Type)
		})
	}
}

// TestCompareFirewallRules_NoUUID_UnchangedIsQuiet is the false-positive half.
func TestCompareFirewallRules_NoUUID_UnchangedIsQuiet(t *testing.T) {
	t.Parallel()

	rules := []common.FirewallRule{
		{Type: common.RuleTypePass, Description: "web", Interfaces: []string{"wan"}},
		{Type: common.RuleTypeBlock, Description: "deny", Interfaces: []string{"wan"}},
	}

	assert.Empty(t, NewAnalyzer().CompareFirewallRules(rules, rules))
}

// TestCompareFirewallRules_NoUUID_InsertionDoesNotCascade checks that adding a
// rule at the top reports one addition rather than marking every rule below it
// as modified, which is what a purely positional pairing would do.
func TestCompareFirewallRules_NoUUID_InsertionDoesNotCascade(t *testing.T) {
	t.Parallel()

	old := []common.FirewallRule{
		{Type: common.RuleTypePass, Description: "web", Interfaces: []string{"wan"}},
		{Type: common.RuleTypePass, Description: "dns", Interfaces: []string{"wan"}},
		{Type: common.RuleTypeBlock, Description: "deny", Interfaces: []string{"wan"}},
	}
	newCfg := append([]common.FirewallRule{
		{Type: common.RuleTypePass, Description: "ssh", Interfaces: []string{"wan"}},
	}, old...)

	changes := NewAnalyzer().CompareFirewallRules(old, newCfg)

	require.Len(t, changes, 1, "only the inserted rule should be reported: %+v", changes)
	assert.Equal(t, ChangeAdded, changes[0].Type)
	assert.Contains(t, changes[0].Description, "ssh")
}

// TestCompareFirewallRules_PairsByTracker verifies the pfSense per-rule tracker
// is used as identity, so a reordered rule is not reported as a remove plus an
// add.
func TestCompareFirewallRules_PairsByTracker(t *testing.T) {
	t.Parallel()

	old := []common.FirewallRule{
		{Tracker: "1000000001", Type: common.RuleTypePass, Description: "web"},
		{Tracker: "1000000002", Type: common.RuleTypePass, Description: "dns"},
	}
	newCfg := []common.FirewallRule{
		{Tracker: "1000000002", Type: common.RuleTypePass, Description: "dns"},
		{Tracker: "1000000001", Type: common.RuleTypeBlock, Description: "web"},
	}

	changes := NewAnalyzer().CompareFirewallRules(old, newCfg)

	require.Len(t, changes, 1, "only the retyped rule should be reported: %+v", changes)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Contains(t, changes[0].Path, "1000000001")
}

// TestCompareUsers_DetectsAPIKeyAndUIDChanges covers the user fields that were
// omitted from usersEqual.
func TestCompareUsers_DetectsAPIKeyAndUIDChanges(t *testing.T) {
	t.Parallel()

	base := common.User{
		Name: "alice", UID: "2000", Scope: "local",
		APIKeys: []common.APIKey{{Key: "KEY-ORIGINAL", Secret: "SECRET-ORIGINAL"}},
	}

	tests := []struct {
		name   string
		mutate func(common.User) common.User
	}{
		{"api key rotated", func(u common.User) common.User {
			u.APIKeys = []common.APIKey{{Key: "KEY-ROTATED", Secret: "SECRET-ROTATED"}}

			return u
		}},
		{"api key added", func(u common.User) common.User {
			u.APIKeys = []common.APIKey{u.APIKeys[0], {Key: "KEY-SECOND"}}

			return u
		}},
		{"api key removed", func(u common.User) common.User {
			u.APIKeys = nil

			return u
		}},
		{"uid changed", func(u common.User) common.User {
			u.UID = "0"

			return u
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			changes := NewAnalyzer().CompareUsers([]common.User{base}, []common.User{tt.mutate(base)})

			require.Len(t, changes, 1, "change must be reported: %+v", changes)
			assert.Equal(t, ChangeModified, changes[0].Type)
		})
	}
}

// TestCompareFirewallRules_KnownLimits documents two behaviours of the pairing
// that are deliberate but sharp, so a future change to compareRulesWithoutUUID
// has to decide about them rather than discover them.
//
// Neither is a regression: the previous implementation compared only the rule
// count and reported nothing for either case.
func TestCompareFirewallRules_KnownLimits(t *testing.T) {
	t.Parallel()

	mk := func(desc string, typ common.FirewallRuleType) common.FirewallRule {
		return common.FirewallRule{Type: typ, Description: desc, Interfaces: []string{"wan"}}
	}

	t.Run("reordering alone is not reported by content comparison", func(t *testing.T) {
		t.Parallel()

		// pf is first-match, so moving a rule changes what the ruleset does.
		// Content pairing matches every rule to its identical twin regardless of
		// position, so a pure reorder produces no entry here. That is by design:
		// order changes are the order detector's job, reached via --detect-order
		// and covered by TestDetectOrder_WorksWithoutUUIDs.
		old := []common.FirewallRule{
			mk("a", common.RuleTypePass),
			mk("b", common.RuleTypePass),
			mk("c", common.RuleTypePass),
		}
		reordered := []common.FirewallRule{
			mk("c", common.RuleTypePass),
			mk("a", common.RuleTypePass),
			mk("b", common.RuleTypePass),
		}

		assert.Empty(t, NewAnalyzer().CompareFirewallRules(old, reordered),
			"content comparison does not report order; --detect-order does")
	})
}

// TestDetectOrder_WorksWithoutUUIDs guards --detect-order for pfSense.
//
// extractRuleUUIDs dropped every rule without a <uuid>, so the ordered list it
// handed DetectReorders was empty for any pfSense config and any older OPNsense
// one. The flag is documented and accepted, and silently found nothing.
//
// Rules with no identity at all stay out: a rule indistinguishable from its
// peers cannot be said to have moved.
func TestDetectOrder_WorksWithoutUUIDs(t *testing.T) {
	t.Parallel()

	mk := func(uuid, tracker, desc string) common.FirewallRule {
		return common.FirewallRule{
			UUID: uuid, Tracker: tracker, Description: desc,
			Type: common.RuleTypePass, Interfaces: []string{"wan"},
		}
	}

	tests := []struct {
		name         string
		old, newCfg  []common.FirewallRule
		wantReorders int
		wantPathPart string
	}{
		{
			name:         "uuid-bearing rules (OPNsense MVC)",
			old:          []common.FirewallRule{mk("u1", "", "a"), mk("u2", "", "b"), mk("u3", "", "c")},
			newCfg:       []common.FirewallRule{mk("u3", "", "c"), mk("u1", "", "a"), mk("u2", "", "b")},
			wantReorders: 3,
			wantPathPart: "uuid=",
		},
		{
			name:         "tracker-bearing rules (pfSense)",
			old:          []common.FirewallRule{mk("", "t1", "a"), mk("", "t2", "b"), mk("", "t3", "c")},
			newCfg:       []common.FirewallRule{mk("", "t3", "c"), mk("", "t1", "a"), mk("", "t2", "b")},
			wantReorders: 3,
			wantPathPart: "tracker=",
		},
		{
			name:         "no identity: not reportable",
			old:          []common.FirewallRule{mk("", "", "a"), mk("", "", "b")},
			newCfg:       []common.FirewallRule{mk("", "", "b"), mk("", "", "a")},
			wantReorders: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res, err := NewEngine(
				&common.CommonDevice{FirewallRules: tt.old},
				&common.CommonDevice{FirewallRules: tt.newCfg},
				Options{DetectOrder: true}, nil,
			).Compare(context.Background())
			require.NoError(t, err)

			var reorders []Change
			for _, c := range res.Changes {
				if c.Type == ChangeReordered {
					reorders = append(reorders, c)
				}
			}

			assert.Len(t, reorders, tt.wantReorders)
			if tt.wantPathPart != "" && len(reorders) > 0 {
				assert.Contains(t, reorders[0].Path, tt.wantPathPart,
					"the diff path must name the identity the rule was tracked by")
			}
		})
	}
}

// TestCompareFirewallRules_DeletionDoesNotMisattributeEdit covers the case that
// blind positional pairing got wrong.
//
// With `a, b, c(pass)` becoming `a, c(block)`, `a` anchors by content and both
// `b` and `c` are left over. Pairing leftovers by position handed the surviving
// `c` to `b`, reporting "b was modified into c" plus "c was removed" -- every
// change surfaced, but attributed to the wrong rules. Similarity pairing picks
// the real c-to-c pair, so the report reads "c was modified, b was removed".
func TestCompareFirewallRules_DeletionDoesNotMisattributeEdit(t *testing.T) {
	t.Parallel()

	mk := func(desc string, typ common.FirewallRuleType) common.FirewallRule {
		return common.FirewallRule{Type: typ, Description: desc, Interfaces: []string{"wan"}}
	}

	old := []common.FirewallRule{
		mk("allow web", common.RuleTypePass),
		mk("allow dns", common.RuleTypePass),
		mk("allow ssh", common.RuleTypePass),
	}
	newCfg := []common.FirewallRule{
		mk("allow web", common.RuleTypePass),
		mk("allow ssh", common.RuleTypeBlock), // edited
		// "allow dns" deleted
	}

	changes := NewAnalyzer().CompareFirewallRules(old, newCfg)
	require.Len(t, changes, 2, "one edit and one deletion: %+v", changes)

	byType := map[ChangeType]Change{}
	for _, c := range changes {
		byType[c.Type] = c
	}

	modified, ok := byType[ChangeModified]
	require.True(t, ok, "the edit must be reported: %+v", changes)
	assert.Contains(t, modified.Description, "allow ssh",
		"the edit belongs to the rule that was actually edited")

	removed, ok := byType[ChangeRemoved]
	require.True(t, ok, "the deletion must be reported: %+v", changes)
	assert.Contains(t, removed.Description, "allow dns",
		"the deletion belongs to the rule that was actually deleted")
}

// TestRuleSimilarity_Ordering pins the relative weights: the operator's own
// description outranks any single structural field, and an unrelated rule
// scores below the floor for calling it an edit.
func TestRuleSimilarity_Ordering(t *testing.T) {
	t.Parallel()

	base := common.FirewallRule{
		Type: common.RuleTypePass, Description: "allow ssh", Interfaces: []string{"wan"},
		Protocol:    "tcp",
		Source:      common.RuleEndpoint{Address: "10.0.0.0/8"},
		Destination: common.RuleEndpoint{Address: "192.168.1.1", Port: "22"},
	}

	sameNameEdited := base
	sameNameEdited.Type = common.RuleTypeBlock

	renamedButIdentical := base
	renamedButIdentical.Description = "ssh (was: allow ssh)"

	unrelated := common.FirewallRule{
		Type: common.RuleTypeBlock, Description: "drop bogons", Interfaces: []string{"lan"},
		Protocol:    "udp",
		Source:      common.RuleEndpoint{Address: "any"},
		Destination: common.RuleEndpoint{Address: "any", Port: "53"},
	}

	assert.GreaterOrEqual(t, ruleSimilarity(base, sameNameEdited), simMinScore,
		"a rule keeping its description is the same rule edited")
	assert.GreaterOrEqual(t, ruleSimilarity(base, renamedButIdentical), simMinScore,
		"a renamed but otherwise identical rule is still the same rule")
	assert.Less(t, ruleSimilarity(base, unrelated), simMinScore,
		"a rule sharing nothing meaningful is not an edit of this one")
}

// TestCompareFirewallRules_SimilarityCapFallsBackToPosition exercises the bound
// on the O(n*m) scoring. Above simMaxPairs leftovers the pairing degrades to
// positional, which is what every input got before similarity existed, so the
// changes must still all surface.
func TestCompareFirewallRules_SimilarityCapFallsBackToPosition(t *testing.T) {
	t.Parallel()

	n := simMaxPairs + 10
	old := make([]common.FirewallRule, n)
	newCfg := make([]common.FirewallRule, n)
	for i := range old {
		old[i] = common.FirewallRule{
			Type: common.RuleTypePass, Description: fmt.Sprintf("rule %d", i), Interfaces: []string{"wan"},
		}
		newCfg[i] = old[i]
		newCfg[i].Type = common.RuleTypeBlock // every rule differs, so none anchor
	}

	changes := NewAnalyzer().CompareFirewallRules(old, newCfg)

	assert.Len(t, changes, n, "every changed rule must still be reported past the cap")
}
