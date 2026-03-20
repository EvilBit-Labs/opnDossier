package parser

import (
	"context"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDeviceParser is a minimal DeviceParser implementation for testing.
type mockDeviceParser struct{}

// Parse returns an empty CommonDevice with no warnings or errors.
func (m *mockDeviceParser) Parse(
	_ context.Context,
	_ io.Reader,
) (*common.CommonDevice, []common.ConversionWarning, error) {
	return &common.CommonDevice{}, nil, nil
}

// ParseAndValidate returns an empty CommonDevice with no warnings or errors.
func (m *mockDeviceParser) ParseAndValidate(
	_ context.Context,
	_ io.Reader,
) (*common.CommonDevice, []common.ConversionWarning, error) {
	return &common.CommonDevice{}, nil, nil
}

// mockXMLDecoder is a minimal XMLDecoder implementation for testing.
type mockXMLDecoder struct{}

// Parse returns an empty OpnSenseDocument with no error.
func (m *mockXMLDecoder) Parse(_ context.Context, _ io.Reader) (*schema.OpnSenseDocument, error) {
	return &schema.OpnSenseDocument{}, nil
}

// ParseAndValidate returns an empty OpnSenseDocument with no error.
func (m *mockXMLDecoder) ParseAndValidate(_ context.Context, _ io.Reader) (*schema.OpnSenseDocument, error) {
	return &schema.OpnSenseDocument{}, nil
}

// mockConstructor returns a ConstructorFunc that produces a mockDeviceParser.
func mockConstructor() ConstructorFunc {
	return func(_ XMLDecoder) DeviceParser {
		return &mockDeviceParser{}
	}
}

// TestNewDeviceParserRegistry verifies that a new registry is non-nil and empty.
func TestNewDeviceParserRegistry(t *testing.T) {
	t.Parallel()

	reg := NewDeviceParserRegistry()

	require.NotNil(t, reg, "registry should not be nil")
	assert.Empty(t, reg.List(), "new registry should have no entries")
}

// TestRegister verifies successful registration scenarios including normalization.
func TestRegister(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		deviceType  string
		expectedKey string
		description string
	}{
		{
			name:        "registers with lowercase name",
			deviceType:  "mydevice",
			expectedKey: "mydevice",
			description: "exact lowercase should be stored as-is",
		},
		{
			name:        "normalizes uppercase to lowercase",
			deviceType:  "MYDEVICE",
			expectedKey: "mydevice",
			description: "uppercase input should be normalized to lowercase",
		},
		{
			name:        "normalizes mixed case to lowercase",
			deviceType:  "MyDevice",
			expectedKey: "mydevice",
			description: "mixed case input should be normalized to lowercase",
		},
		{
			name:        "trims leading and trailing whitespace",
			deviceType:  "  spacey  ",
			expectedKey: "spacey",
			description: "whitespace should be trimmed before storing",
		},
		{
			name:        "trims whitespace and normalizes case together",
			deviceType:  "  MiXeD  ",
			expectedKey: "mixed",
			description: "both trimming and lowercasing should apply",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := NewDeviceParserRegistry()

			assert.NotPanics(t, func() {
				reg.Register(tt.deviceType, mockConstructor())
			}, tt.description)

			fn, ok := reg.Get(tt.expectedKey)
			assert.True(t, ok, "should find registered entry by normalized key")
			assert.NotNil(t, fn, "constructor function should not be nil")
		})
	}
}

// TestRegisterPanics verifies all panic conditions in Register.
func TestRegisterPanics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(reg *DeviceParserRegistry)
		panicFn func(reg *DeviceParserRegistry)
	}{
		{
			name:  "panics on nil factory",
			setup: func(_ *DeviceParserRegistry) {},
			panicFn: func(reg *DeviceParserRegistry) {
				reg.Register("device", nil)
			},
		},
		{
			name:  "panics on empty name",
			setup: func(_ *DeviceParserRegistry) {},
			panicFn: func(reg *DeviceParserRegistry) {
				reg.Register("", mockConstructor())
			},
		},
		{
			name:  "panics on whitespace-only name",
			setup: func(_ *DeviceParserRegistry) {},
			panicFn: func(reg *DeviceParserRegistry) {
				reg.Register("   ", mockConstructor())
			},
		},
		{
			name: "panics on duplicate registration",
			setup: func(reg *DeviceParserRegistry) {
				reg.Register("duplicate", mockConstructor())
			},
			panicFn: func(reg *DeviceParserRegistry) {
				reg.Register("duplicate", mockConstructor())
			},
		},
		{
			name: "panics on case-insensitive duplicate",
			setup: func(reg *DeviceParserRegistry) {
				reg.Register("casedupe", mockConstructor())
			},
			panicFn: func(reg *DeviceParserRegistry) {
				reg.Register("CASEDUPE", mockConstructor())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := NewDeviceParserRegistry()
			tt.setup(reg)

			assert.Panics(t, func() {
				tt.panicFn(reg)
			}, "should panic for invalid input")
		})
	}
}

// TestGet verifies retrieval behavior including normalization and missing entries.
func TestGet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		register  string
		lookup    string
		wantFound bool
	}{
		{
			name:      "found returns function and true",
			register:  "found",
			lookup:    "found",
			wantFound: true,
		},
		{
			name:      "not found returns nil and false",
			register:  "registered",
			lookup:    "missing",
			wantFound: false,
		},
		{
			name:      "case-insensitive lookup",
			register:  "myparser",
			lookup:    "MYPARSER",
			wantFound: true,
		},
		{
			name:      "whitespace-trimmed lookup",
			register:  "trimmed",
			lookup:    "  trimmed  ",
			wantFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := NewDeviceParserRegistry()
			reg.Register(tt.register, mockConstructor())

			fn, ok := reg.Get(tt.lookup)

			assert.Equal(t, tt.wantFound, ok, "found flag mismatch")
			if tt.wantFound {
				assert.NotNil(t, fn, "constructor should not be nil when found")
			} else {
				assert.Nil(t, fn, "constructor should be nil when not found")
			}
		})
	}
}

// TestList verifies listing behavior including sorting and normalization.
func TestList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		registerTypes []string
		expectedList  []string
	}{
		{
			name:          "empty registry returns empty slice",
			registerTypes: []string{},
			expectedList:  []string{},
		},
		{
			name:          "single entry",
			registerTypes: []string{"alpha"},
			expectedList:  []string{"alpha"},
		},
		{
			name:          "multiple entries returned sorted",
			registerTypes: []string{"zulu", "alpha", "bravo"},
			expectedList:  []string{"alpha", "bravo", "zulu"},
		},
		{
			name:          "entries normalized to lowercase",
			registerTypes: []string{"UPPER", "Mixed"},
			expectedList:  []string{"mixed", "upper"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := NewDeviceParserRegistry()
			for _, dt := range tt.registerTypes {
				reg.Register(dt, mockConstructor())
			}

			list := reg.List()

			assert.Equal(t, tt.expectedList, list, "list content mismatch")
			assert.True(t, slices.IsSorted(list), "list should be sorted")
		})
	}
}

// TestDefaultRegistry verifies the singleton returns the same instance.
func TestDefaultRegistry(t *testing.T) {
	t.Parallel()

	reg1 := DefaultRegistry()
	reg2 := DefaultRegistry()

	require.NotNil(t, reg1, "DefaultRegistry should not return nil")
	assert.Same(t, reg1, reg2, "DefaultRegistry should return the same singleton instance")
}

// TestPackageLevelRegister verifies the package-level Register convenience function
// delegates to DefaultRegistry. Uses a unique name to avoid collision with other
// registrations on the global singleton.
func TestPackageLevelRegister(t *testing.T) {
	t.Parallel()

	uniqueName := "pkg-level-register-test-device"

	assert.NotPanics(t, func() {
		Register(uniqueName, mockConstructor())
	}, "package-level Register should not panic for valid input")

	fn, ok := DefaultRegistry().Get(uniqueName)
	assert.True(t, ok, "device type should be retrievable from DefaultRegistry after package-level Register")
	assert.NotNil(t, fn, "constructor should not be nil")
}

// TestConcurrentAccess verifies that concurrent Get and List calls on a registry
// with pre-registered entries do not race.
func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	reg := NewDeviceParserRegistry()
	reg.Register("device-a", mockConstructor())
	reg.Register("device-b", mockConstructor())
	reg.Register("device-c", mockConstructor())

	const goroutines = 100

	var wg sync.WaitGroup

	var getCount atomic.Int32
	var listCount atomic.Int32

	for i := range goroutines {
		wg.Add(1)

		go func(idx int) {
			defer wg.Done()

			if idx%2 == 0 {
				fn, ok := reg.Get("device-b")
				if ok && fn != nil {
					getCount.Add(1)
				}
			} else {
				list := reg.List()
				if len(list) == 3 {
					listCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()

	assert.Equal(t, int32(goroutines/2), getCount.Load(), "all Get calls should succeed")
	assert.Equal(t, int32(goroutines/2), listCount.Load(), "all List calls should succeed")
}

// TestFactoryIntegration verifies that NewFactoryWithRegistry uses the provided
// isolated registry and that CreateDevice dispatches correctly.
func TestFactoryIntegration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		registerTypes      []string
		xmlInput           string
		deviceTypeOverride string
		validateMode       bool
		wantErr            bool
		errContains        string
	}{
		{
			name:               "override with registered type succeeds",
			registerTypes:      []string{"testdevice"},
			xmlInput:           `<?xml version="1.0"?><testdevice></testdevice>`,
			deviceTypeOverride: "testdevice",
			validateMode:       false,
			wantErr:            false,
		},
		{
			name:               "override with unregistered type returns error",
			registerTypes:      []string{"testdevice"},
			xmlInput:           `<?xml version="1.0"?><testdevice></testdevice>`,
			deviceTypeOverride: "unknown",
			validateMode:       false,
			wantErr:            true,
			errContains:        "unsupported device type override",
		},
		{
			name:               "auto-detect from XML root element succeeds",
			registerTypes:      []string{"testdevice"},
			xmlInput:           `<?xml version="1.0"?><testdevice></testdevice>`,
			deviceTypeOverride: "",
			validateMode:       false,
			wantErr:            false,
		},
		{
			name:               "auto-detect with unregistered root element returns error",
			registerTypes:      []string{"testdevice"},
			xmlInput:           `<?xml version="1.0"?><otherdevice></otherdevice>`,
			deviceTypeOverride: "",
			validateMode:       false,
			wantErr:            true,
			errContains:        "unsupported device type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := NewDeviceParserRegistry()
			for _, dt := range tt.registerTypes {
				reg.Register(dt, mockConstructor())
			}

			decoder := &mockXMLDecoder{}
			factory := NewFactoryWithRegistry(decoder, reg)
			reader := strings.NewReader(tt.xmlInput)

			device, warnings, err := factory.CreateDevice(
				context.Background(),
				reader,
				tt.deviceTypeOverride,
				tt.validateMode,
			)

			if tt.wantErr {
				require.Error(t, err, "CreateDevice should return an error")
				assert.Contains(t, err.Error(), tt.errContains, "error message mismatch")
				assert.Nil(t, device, "device should be nil on error")
				assert.Nil(t, warnings, "warnings should be nil on error")
			} else {
				require.NoError(t, err, "CreateDevice should not return an error")
				assert.NotNil(t, device, "device should not be nil on success")
			}
		})
	}
}
