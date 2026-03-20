// Package parser provides the factory for creating device-specific parsers that
// transform vendor configuration files into the platform-agnostic CommonDevice model.
//
// External consumers register custom DeviceParser implementations via init()
// and blank imports, following the database/sql driver registration pattern.
package parser

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

// ConstructorFunc is the factory function signature for creating DeviceParser
// instances. The XMLDecoder parameter allows injection of the XML parsing
// backend. External parsers that manage their own XML decoding may ignore it.
type ConstructorFunc = func(XMLDecoder) DeviceParser

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

// Global singleton — follows database/sql driver registration pattern.
//
//nolint:gochecknoglobals // package-level singleton is the standard Go registry pattern (database/sql, image)
var (
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
