package analysis

import (
	"maps"
	"slices"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

// TestReachableObjects pins the contract in the function's doc comment. Two
// callers depend on it: the unused-object detector and the diff's alias rating.
func TestReachableObjects(t *testing.T) {
	t.Parallel()

	group := func(members ...string) common.NamedObject {
		return common.NamedObject{Type: "networkgroup", Members: members}
	}
	hosts := func(members ...string) common.NamedObject {
		return common.NamedObject{Type: common.NamedObjectTypeHost, Members: members}
	}

	tests := []struct {
		name    string
		objects common.NamedObjects
		roots   []string
		want    []string
	}{
		{
			name:    "no roots",
			objects: common.NamedObjects{"a": hosts("10.0.0.1")},
		},
		{
			name:    "a root names no object",
			objects: common.NamedObjects{"a": hosts("10.0.0.1")},
			roots:   []string{"gone"},
		},
		{
			name:    "a member that names no object is not an edge",
			objects: common.NamedObjects{"a": hosts("gone")},
			roots:   []string{"a"},
			want:    []string{"a"},
		},
		{
			name: "a walk goes past the first level",
			objects: common.NamedObjects{
				"outer": group("inner"),
				"inner": group("leaf"),
				"leaf":  hosts("10.0.0.1"),
				"spare": hosts("10.0.0.2"),
			},
			roots: []string{"outer"},
			want:  []string{"inner", "leaf", "outer"},
		},
		{
			// isDynamic classifies a networkgroup as opaque; the walk must not gate on it.
			name: "a dynamic type's members are followed",
			objects: common.NamedObjects{
				"netgroup": group("leaf"),
				"leaf":     hosts("10.0.0.1"),
			},
			roots: []string{"netgroup"},
			want:  []string{"leaf", "netgroup"},
		},
		{
			name: "a cycle terminates",
			objects: common.NamedObjects{
				"a": group("b"),
				"b": group("a"),
			},
			roots: []string{"a"},
			want:  []string{"a", "b"},
		},
		{
			name: "a member listed twice counts once",
			objects: common.NamedObjects{
				"a":    group("leaf", "leaf"),
				"leaf": hosts("10.0.0.1"),
			},
			roots: []string{"a", "a"},
			want:  []string{"a", "leaf"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ReachableObjects(tt.objects, tt.roots)

			assert.Equal(t, tt.want, slices.Sorted(maps.Keys(got)))
			for name, reachable := range got {
				assert.True(t, reachable, "a key of the result must be reachable: %s", name)
			}
		})
	}
}

// TestReachableObjects_LeavesRootsAlone pins that the walk works on its own
// queue: a stack over the caller's slice would write members over its roots.
func TestReachableObjects_LeavesRootsAlone(t *testing.T) {
	t.Parallel()

	objects := common.NamedObjects{
		"a": {Type: "networkgroup", Members: []string{"c", "d"}},
		"b": {Type: "networkgroup", Members: []string{"e"}},
		"c": {Type: common.NamedObjectTypeHost},
		"d": {Type: common.NamedObjectTypeHost},
		"e": {Type: common.NamedObjectTypeHost},
	}
	roots := []string{"a", "b"}

	ReachableObjects(objects, roots)

	assert.Equal(t, []string{"a", "b"}, roots)
}
