package converter

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

// FormatHandler defines the interface for format-specific generation logic.
// Each handler encapsulates the generation, streaming, and metadata for a single
// output format, allowing the FormatRegistry to dispatch by format name.
type FormatHandler interface {
	// FileExtension returns the file extension for this format (e.g., ".md", ".json").
	FileExtension() string

	// Aliases returns alternative names for this format (e.g., "md" for markdown).
	Aliases() []string
}

// FormatRegistry centralises format dispatch by mapping canonical format names
// and aliases to FormatHandler implementations. It replaces scattered switch
// statements with a single source of truth for supported formats.
type FormatRegistry struct {
	mu       sync.RWMutex
	handlers map[string]FormatHandler
	aliases  map[string]string
}

// NewFormatRegistry creates an empty FormatRegistry.
func NewFormatRegistry() *FormatRegistry {
	return &FormatRegistry{
		handlers: make(map[string]FormatHandler),
		aliases:  make(map[string]string),
	}
}

// Register adds a handler for the given canonical format name. It also registers
// all aliases returned by handler.Aliases(). Panics on duplicate registration,
// consistent with the database/sql driver pattern.
func (r *FormatRegistry) Register(format string, handler FormatHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := strings.ToLower(format)
	if _, exists := r.handlers[key]; exists {
		panic(fmt.Sprintf("converter: format %q already registered", key))
	}

	r.handlers[key] = handler

	for _, alias := range handler.Aliases() {
		aliasKey := strings.ToLower(alias)
		if _, exists := r.aliases[aliasKey]; exists {
			panic(fmt.Sprintf("converter: alias %q already registered", aliasKey))
		}
		if _, exists := r.handlers[aliasKey]; exists {
			panic(fmt.Sprintf("converter: alias %q conflicts with canonical format", aliasKey))
		}

		r.aliases[aliasKey] = key
	}
}

// Get returns the handler for the given format name (canonical or alias).
// Returns ErrUnsupportedFormat if no handler matches.
func (r *FormatRegistry) Get(format string) (FormatHandler, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := strings.ToLower(format)

	if h, ok := r.handlers[key]; ok {
		return h, nil
	}

	if canonical, ok := r.aliases[key]; ok {
		return r.handlers[canonical], nil
	}

	return nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, format)
}

// Canonical returns the canonical format name for the given format string,
// resolving aliases. Returns the lowercased input if not found.
func (r *FormatRegistry) Canonical(format string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := strings.ToLower(format)

	if _, ok := r.handlers[key]; ok {
		return key
	}

	if canonical, ok := r.aliases[key]; ok {
		return canonical
	}

	return key
}

// Extensions returns a map of canonical format name to file extension.
func (r *FormatRegistry) Extensions() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	exts := make(map[string]string, len(r.handlers))
	for name, h := range r.handlers {
		exts[name] = h.FileExtension()
	}

	return exts
}

// ValidFormats returns a sorted slice of canonical format names.
func (r *FormatRegistry) ValidFormats() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	formats := make([]string, 0, len(r.handlers))
	for name := range r.handlers {
		formats = append(formats, name)
	}

	slices.Sort(formats)

	return formats
}

// ValidFormatsWithAliases returns a sorted slice of all accepted format strings,
// including both canonical names and aliases.
func (r *FormatRegistry) ValidFormatsWithAliases() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	all := make([]string, 0, len(r.handlers)+len(r.aliases))
	for name := range r.handlers {
		all = append(all, name)
	}
	for alias := range r.aliases {
		all = append(all, alias)
	}

	slices.Sort(all)

	return all
}

// DefaultRegistry is the package-level registry pre-populated with all built-in
// format handlers. It is the single source of truth for supported formats.
var DefaultRegistry = newDefaultRegistry() //nolint:gochecknoglobals // package-level singleton

// newDefaultRegistry creates a FormatRegistry populated with all built-in handlers.
func newDefaultRegistry() *FormatRegistry {
	r := NewFormatRegistry()
	r.Register("markdown", &markdownHandler{})
	r.Register("json", &jsonHandler{})
	r.Register("yaml", &yamlHandler{})
	r.Register("text", &textHandler{})
	r.Register("html", &htmlHandler{})

	return r
}

// markdownHandler handles markdown format output.
type markdownHandler struct{}

func (h *markdownHandler) FileExtension() string { return ".md" }
func (h *markdownHandler) Aliases() []string     { return []string{"md"} }

// jsonHandler handles JSON format output.
type jsonHandler struct{}

func (h *jsonHandler) FileExtension() string { return ".json" }
func (h *jsonHandler) Aliases() []string     { return nil }

// yamlHandler handles YAML format output.
type yamlHandler struct{}

func (h *yamlHandler) FileExtension() string { return ".yaml" }
func (h *yamlHandler) Aliases() []string     { return []string{"yml"} }

// textHandler handles plain text format output.
type textHandler struct{}

func (h *textHandler) FileExtension() string { return ".txt" }
func (h *textHandler) Aliases() []string     { return []string{"txt"} }

// htmlHandler handles HTML format output.
type htmlHandler struct{}

func (h *htmlHandler) FileExtension() string { return ".html" }
func (h *htmlHandler) Aliases() []string     { return []string{"htm"} }
