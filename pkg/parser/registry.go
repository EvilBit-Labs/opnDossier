// Package parser provides the factory for creating device-specific parsers that
// transform vendor configuration files into the platform-agnostic CommonDevice
// model (pkg/model.CommonDevice).
//
// # Public API Surface
//
// This package is part of opnDossier's public API, intended for consumption
// by other Go modules. It has no internal/ dependencies in production code.
//
// Top-level types a consumer interacts with:
//
//   - Factory and its constructors [NewFactory] / [NewFactoryWithRegistry]
//   - OPNsenseXMLDecoder (dependency injected at construction; opnDossier's
//     CLI wires internal/cfgparser.NewXMLParser, external consumers provide
//     their own)
//   - DeviceParser (the device-specific parser contract)
//   - DeviceParserRegistry and the package-level [Register] / [DefaultRegistry]
//
// # Registration Contract (blank imports)
//
// Device-specific parsers register themselves with [DefaultRegistry] from an
// init() function. Because Go only runs init() when a package is imported,
// consumers MUST add a blank import for each parser they want available:
//
//	import (
//	    "github.com/EvilBit-Labs/opnDossier/pkg/parser"
//
//	    _ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // registers "opnsense"
//	    _ "github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"  // registers "pfsense"
//	)
//
// This follows the database/sql driver registration pattern. If no parser
// packages are imported, [Factory.CreateDevice] returns an error whose
// "supported:" section shows the actionable hint
// "(none registered -- ensure parser packages are imported)". The trailing
// substring "ensure parser packages are imported" is considered a stable
// signal — it is covered by a regression test and safe for tooling to detect,
// though the full wording may be refined.
//
// External consumers who implement a parser for a new device type can register
// it the same way by calling [Register] from their own package's init().
package parser

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

// ConstructorFunc is the factory function signature for creating DeviceParser
// instances. The OPNsenseXMLDecoder parameter allows injection of the XML
// parsing backend. The parameter is consumed by the OPNsense parser; non-
// OPNsense parsers accept it for signature compatibility but must manage
// their own XML decoding.
type ConstructorFunc = func(OPNsenseXMLDecoder) DeviceParser

// DeviceParserRegistry manages registered DeviceParser constructors, keyed by
// the lowercase XML root element name of the device type they handle.
// It is safe for concurrent use.
type DeviceParserRegistry struct {
	mu      sync.RWMutex
	parsers map[string]ConstructorFunc
}

// NewDeviceParserRegistry returns a new, empty DeviceParserRegistry.
// Use this constructor in tests to create isolated registry instances
// that do not pollute the global singleton.
func NewDeviceParserRegistry() *DeviceParserRegistry {
	return &DeviceParserRegistry{parsers: make(map[string]ConstructorFunc)}
}

// Register adds a constructor for the given device type name.
// deviceType is normalized to lowercase with whitespace trimmed.
// Panics on duplicate registration, nil factory, or empty device type
// to surface wiring conflicts at startup (mirrors FormatRegistry and
// database/sql.Register contracts). Should only be called from init().
func (r *DeviceParserRegistry) Register(deviceType string, fn ConstructorFunc) {
	if fn == nil {
		panic(fmt.Sprintf("parser: cannot register nil factory for device type %q", deviceType))
	}

	key := strings.ToLower(strings.TrimSpace(deviceType))
	if key == "" {
		panic("parser: device type name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.parsers[key]; exists {
		panic(fmt.Sprintf("parser: duplicate registration for device type %q", key))
	}

	r.parsers[key] = fn
}

// Get returns the constructor for the given device type, or (nil, false)
// if no parser is registered for it. deviceType is normalized to lowercase
// with whitespace trimmed, matching the normalization applied by Register.
func (r *DeviceParserRegistry) Get(deviceType string) (ConstructorFunc, bool) {
	key := strings.ToLower(strings.TrimSpace(deviceType))

	r.mu.RLock()
	defer r.mu.RUnlock()

	fn, ok := r.parsers[key]
	return fn, ok
}

// List returns a sorted slice of all registered device type names.
// The returned slice is a copy and safe to modify.
func (r *DeviceParserRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.parsers))
	for k := range r.parsers {
		names = append(names, k)
	}

	slices.Sort(names)
	return names
}

// SupportedDevices returns a formatted string listing all registered device
// type names, suitable for error messages. When the registry is empty, it
// returns an actionable hint about missing blank imports. This is the single
// source of truth for supported-device messaging across factory errors and
// CLI validation.
func (r *DeviceParserRegistry) SupportedDevices() string {
	devices := r.List()
	if len(devices) == 0 {
		return "(none registered -- ensure parser packages are imported)"
	}

	return strings.Join(devices, ", ")
}

// defaultRegistry and defaultRegistryOnce implement the global singleton,
// following the database/sql driver registration pattern.
var ( //nolint:gochecknoglobals // package-level singleton is the standard Go registry pattern (database/sql, image)
	defaultRegistry     *DeviceParserRegistry
	defaultRegistryOnce sync.Once
)

// DefaultRegistry returns the package-level DeviceParserRegistry singleton.
// External parsers call Register() on this instance from init().
func DefaultRegistry() *DeviceParserRegistry {
	defaultRegistryOnce.Do(func() {
		defaultRegistry = NewDeviceParserRegistry()
	})

	return defaultRegistry
}

// Register is a package-level convenience wrapper around DefaultRegistry().Register().
// It follows the database/sql.Register() pattern for use in init() functions.
func Register(deviceType string, fn ConstructorFunc) {
	DefaultRegistry().Register(deviceType, fn)
}
