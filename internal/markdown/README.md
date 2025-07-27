# Markdown Package (Extended Converter API)

The `internal/markdown` package provides an extended API for generating documentation from OPNsense configurations with configurable options and pluggable templates.

## Overview

This package implements TASK-011 by providing:

- **Options struct** with comprehensive configuration (Format, Template, Sections, Theme, WrapWidth, etc.)
- **Generator interface** for pluggable generation strategies
- **Default implementation** that wraps existing converter logic
- **Support stubs** for JSON/YAML output
- **Template management** for pluggable Go `text/template` templates
- **Backward compatibility** through adapter pattern

## Key Components

### Generator Interface

```go
type Generator interface {
    Generate(ctx context.Context, cfg *model.Opnsense, opts Options) (string, error)
}
```

### Options Configuration

```go
type Options struct {
    Format          Format                 // markdown, json, yaml
    Template        *template.Template     // Custom template
    TemplateName    string                 // Built-in template name
    Sections        []string              // Sections to include
    Theme           Theme                 // Terminal theme
    WrapWidth       int                   // Text wrapping
    EnableTables    bool                  // Table rendering
    EnableColors    bool                  // Colored output
    EnableEmojis    bool                  // Emoji icons
    Compact         bool                  // Compact format
    IncludeMetadata bool                  // Generation metadata
    CustomFields    map[string]interface{} // Template fields
}
```

## Usage Examples

### Basic Usage

```go
// Create generator with default options
generator := markdown.NewMarkdownGenerator()
opts := markdown.DefaultOptions()

// Generate markdown
result, err := generator.Generate(ctx, cfg, opts)
```

### Custom Configuration

```go
// Configure options with fluent interface
opts := markdown.DefaultOptions().
    WithFormat(markdown.FormatJSON).
    WithTheme(markdown.ThemeDark).
    WithWrapWidth(80).
    WithTables(false).
    WithCustomField("version", "1.0.0")

result, err := generator.Generate(ctx, cfg, opts)
```

### Backward Compatibility

```go
// Use adapter for backward compatibility with existing Converter interface
adapter := markdown.NewConverterAdapter()
result, err := adapter.ToMarkdown(ctx, cfg)

// Or with custom options
customOpts := markdown.DefaultOptions().WithFormat(markdown.FormatMarkdown)
adapter := markdown.NewConverterAdapterWithOptions(customOpts)
result, err := adapter.ToMarkdown(ctx, cfg)
```

## Supported Formats

- **Markdown** - Rich terminal-rendered markdown with themes
- **JSON** - Structured JSON output
- **YAML** - Human-readable YAML format

## Template System

The package supports pluggable Go `text/template` templates:

- Built-in templates in `internal/templates/`
- Custom template registration via `RegisterCustomTemplate()`
- Template loading via `LoadBuiltinTemplate()`

## Migration from Old API

The old `converter.MarkdownConverter` is now deprecated. Use the new API:

```go
// Old way (deprecated)
converter := converter.NewMarkdownConverter()
result, err := converter.ToMarkdown(ctx, cfg)

// New way
generator := markdown.NewMarkdownGenerator()
opts := markdown.DefaultOptions()
result, err := generator.Generate(ctx, cfg, opts)

// Or use adapter for drop-in replacement
adapter := markdown.NewConverterAdapter()
result, err := adapter.ToMarkdown(ctx, cfg)
```

## Testing

The package includes comprehensive tests:

```bash
go test ./internal/markdown/...
```

## Future Enhancements

- Template embedding from `internal/templates/`
- Section-specific filtering
- Theme customization
- Performance optimizations
- Additional output formats
