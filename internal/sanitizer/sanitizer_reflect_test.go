package sanitizer

import (
	"bytes"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/logging"
)

// newBufferLogger returns a Logger backed by a bytes.Buffer so tests can
// inspect the structured warning log. Mirrors the helper pattern used in
// internal/audit/plugin_hardening_test.go.
func newBufferLogger(t *testing.T) (*logging.Logger, *bytes.Buffer) {
	t.Helper()

	var buf bytes.Buffer
	logger, err := logging.New(logging.Config{
		Level:  "debug",
		Output: &buf,
	})
	if err != nil {
		t.Fatalf("failed to create buffer logger: %v", err)
	}

	return logger, &buf
}

// secretHolder is a struct with a sensitive field. It is intentionally
// placed inside a map[string]secretHolder value to exercise the
// struct-valued-map branch of sanitizeReflect.
type secretHolder struct {
	Password string `xml:"password"`
}

// ptrSecretHolder is the pointer equivalent, exercising the reflect.Ptr
// element kind path of the same guard.
type ptrSecretHolder struct {
	APIKey string `xml:"api_key"`
}

// structMapContainer wraps a map[string]secretHolder so SanitizeStruct can
// walk into it by reflecting over the parent struct. SanitizeStruct is
// documented to accept any value, but giving it a named parent makes the
// emitted path field meaningful.
type structMapContainer struct {
	Entries map[string]secretHolder `xml:"entries"`
}

type ptrMapContainer struct {
	Entries map[string]*ptrSecretHolder `xml:"entries"`
}

// TestSanitizeStruct_MapStructValues_WarnsAndSkips pins the GOTCHAS §14.4
// gap: struct-valued maps are known to be unreachable via reflect
// (map values are not addressable in Go). The sanitizer must not pretend
// it handled the map — it emits a warning so operators can detect a future
// schema that embeds secrets behind such a path. Todo #151 (tag-based
// redaction) will subsume this gap structurally.
func TestSanitizeStruct_MapStructValues_WarnsAndSkips(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    any
		wantType string
		wantPath string
		wantSkip string // value that must remain unchanged in the map
		valueFn  func(any) string
	}{
		{
			name: "map_with_struct_values",
			value: &structMapContainer{
				Entries: map[string]secretHolder{
					"admin": {Password: "s3cr3t-plaintext"},
				},
			},
			wantType: "map[string]sanitizer.secretHolder",
			wantPath: "entries",
			wantSkip: "s3cr3t-plaintext",
			valueFn: func(v any) string {
				c, ok := v.(*structMapContainer)
				if !ok {
					return ""
				}
				return c.Entries["admin"].Password
			},
		},
		{
			name: "map_with_pointer_values",
			value: &ptrMapContainer{
				Entries: map[string]*ptrSecretHolder{
					// #nosec G101 -- test fixture value, not a real credential.
					"api": {APIKey: "AKIA-plaintext-0001"},
				},
			},
			wantType: "map[string]*sanitizer.ptrSecretHolder",
			wantPath: "entries",
			wantSkip: "AKIA-plaintext-0001",
			valueFn: func(v any) string {
				c, ok := v.(*ptrMapContainer)
				if !ok {
					return ""
				}
				return c.Entries["api"].APIKey
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			s := NewSanitizer(ModeAggressive)
			logger, buf := newBufferLogger(t)
			s.SetLogger(logger)

			// Act
			if err := s.SanitizeStruct(tt.value); err != nil {
				t.Fatalf("SanitizeStruct() error = %v", err)
			}

			// Assert: warning emitted with the expected type and path.
			logOut := buf.String()
			if !strings.Contains(logOut, "skipping map with struct/pointer values") {
				t.Errorf("expected struct-map skip warning in log, got: %q", logOut)
			}
			if !strings.Contains(logOut, tt.wantType) {
				t.Errorf("warning log missing expected type %q; got: %q", tt.wantType, logOut)
			}
			if !strings.Contains(logOut, tt.wantPath) {
				t.Errorf("warning log missing expected path %q; got: %q", tt.wantPath, logOut)
			}

			// Assert: the secret itself is still cleartext — the warning
			// proves we skipped, it does NOT imply we redacted. This is
			// the acknowledged gap; redaction lands with todo #151.
			if got := tt.valueFn(tt.value); got != tt.wantSkip {
				t.Errorf("secret was unexpectedly mutated: got %q, want %q", got, tt.wantSkip)
			}
		})
	}
}

// TestSanitizeStruct_MapStructValues_NilLoggerNoPanic verifies the warning
// path is nil-safe. The logger field is optional and callers pre-dating
// SetLogger (e.g. cmd/sanitize.go on the XML path) must continue to work.
func TestSanitizeStruct_MapStructValues_NilLoggerNoPanic(t *testing.T) {
	t.Parallel()

	s := NewSanitizer(ModeAggressive)
	// Deliberately do NOT call SetLogger.

	container := &structMapContainer{
		Entries: map[string]secretHolder{
			"admin": {Password: "still-plaintext"},
		},
	}

	if err := s.SanitizeStruct(container); err != nil {
		t.Fatalf("SanitizeStruct() error = %v", err)
	}

	// With no logger attached, the guard returns silently. The secret
	// stays unchanged — same acknowledged gap as the primary test.
	if got := container.Entries["admin"].Password; got != "still-plaintext" {
		t.Errorf("secret was unexpectedly mutated: got %q", got)
	}
}

// TestSanitizeStruct_MapStringValues_StillSanitizes pins the happy path:
// the struct/pointer guard MUST NOT regress the existing map[string]string
// sanitization behavior that the XML path relies on for attributes and
// inline content.
func TestSanitizeStruct_MapStringValues_StillSanitizes(t *testing.T) {
	t.Parallel()

	type stringMapContainer struct {
		Passwords map[string]string `xml:"passwords"`
	}

	s := NewSanitizer(ModeAggressive)
	logger, buf := newBufferLogger(t)
	s.SetLogger(logger)

	container := &stringMapContainer{
		Passwords: map[string]string{
			"password": "plaintext-secret",
		},
	}

	if err := s.SanitizeStruct(container); err != nil {
		t.Fatalf("SanitizeStruct() error = %v", err)
	}

	// String map values are still redacted in place.
	if got := container.Passwords["password"]; got == "plaintext-secret" {
		t.Errorf("password not redacted for string-valued map; got %q", got)
	}

	// No struct-map warning should have fired.
	if strings.Contains(buf.String(), "skipping map with struct/pointer values") {
		t.Errorf("unexpected struct-map warning for string-valued map; log: %q", buf.String())
	}
}
