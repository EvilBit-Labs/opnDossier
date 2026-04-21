package builder

import (
	"testing"
	"time"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

func TestWithGeneratedTime(t *testing.T) {
	t.Parallel()

	fixed := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)

	t.Run("non-zero time overrides default", func(t *testing.T) {
		t.Parallel()
		b := NewMarkdownBuilder(WithGeneratedTime(fixed))
		if !b.generated.Equal(fixed) {
			t.Errorf("generated = %v, want %v", b.generated, fixed)
		}
	})

	t.Run("zero time preserves default", func(t *testing.T) {
		t.Parallel()
		before := time.Now()
		b := NewMarkdownBuilder(WithGeneratedTime(time.Time{}))
		after := time.Now()
		if b.generated.Before(before) || b.generated.After(after) {
			t.Errorf("generated = %v, want time.Now() window [%v, %v]", b.generated, before, after)
		}
	})

	t.Run("option flows through NewMarkdownBuilderWithConfig", func(t *testing.T) {
		t.Parallel()
		b := NewMarkdownBuilderWithConfig(&common.CommonDevice{}, nil, WithGeneratedTime(fixed))
		if !b.generated.Equal(fixed) {
			t.Errorf("generated = %v, want %v", b.generated, fixed)
		}
	})
}

func TestWithVersion(t *testing.T) {
	t.Parallel()

	const fixedVersion = "test-1.2.3"

	t.Run("non-empty version overrides default", func(t *testing.T) {
		t.Parallel()
		b := NewMarkdownBuilder(WithVersion(fixedVersion))
		if b.toolVersion != fixedVersion {
			t.Errorf("toolVersion = %q, want %q", b.toolVersion, fixedVersion)
		}
	})

	t.Run("empty version preserves default", func(t *testing.T) {
		t.Parallel()
		b := NewMarkdownBuilder(WithVersion(""))
		if b.toolVersion == "" {
			t.Error("toolVersion is empty; default constants.Version should have been retained")
		}
	})

	t.Run("option flows through NewMarkdownBuilderWithConfig", func(t *testing.T) {
		t.Parallel()
		b := NewMarkdownBuilderWithConfig(&common.CommonDevice{}, nil, WithVersion(fixedVersion))
		if b.toolVersion != fixedVersion {
			t.Errorf("toolVersion = %q, want %q", b.toolVersion, fixedVersion)
		}
	})
}

func TestOptions_Composition(t *testing.T) {
	t.Parallel()

	fixed := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	const fixedVersion = "test-1.2.3"

	b := NewMarkdownBuilder(
		WithGeneratedTime(fixed),
		WithVersion(fixedVersion),
	)

	if !b.generated.Equal(fixed) {
		t.Errorf("generated = %v, want %v", b.generated, fixed)
	}
	if b.toolVersion != fixedVersion {
		t.Errorf("toolVersion = %q, want %q", b.toolVersion, fixedVersion)
	}
}
