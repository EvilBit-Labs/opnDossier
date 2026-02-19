# Theme System Usage

This document describes how to use the comprehensive theme system in opndossier.

## Theme Configuration

The theme system supports multiple configuration methods with the following precedence:

1. **CLI flag** (highest priority): `--theme auto|light|dark|none`
2. **Environment variable**: `OPNDOSSIER_THEME=auto|light|dark|none`
3. **YAML configuration file**: `theme: auto|light|dark|none`
4. **Auto-detection** (lowest priority): Based on terminal capabilities

## Usage Examples

### CLI Flag Override

```bash
# Force light theme
opndossier --theme light display config.xml

# Force dark theme
opndossier --theme dark display config.xml

# Use auto-detection
opndossier --theme auto display config.xml

# Disable theming
opndossier --theme none display config.xml
```

### Environment Variable

```bash
# Set theme via environment variable
export OPNDOSSIER_THEME=dark
opndossier display config.xml

# One-time override
OPNDOSSIER_THEME=light opndossier display config.xml
```

### YAML Configuration

```yaml
# ~/.opnDossier.yaml
theme: dark
```

### Auto-Detection

When no theme is explicitly set, the system automatically detects the appropriate theme based on:

- `COLORTERM` environment variable (truecolor, 24bit)
- `TERM` environment variable (256color, dark variants)
- `TERM_PROGRAM` environment variable (dark variants)

## Theme Properties

### Light Theme

- Background: `#FFFFFF` (white)
- Foreground: `#000000` (black)
- Primary: `#007ACC` (blue)
- Error: `#DC3545` (red)
- Warning: `#FFC107` (yellow)
- Success: `#28A745` (green)

### Dark Theme

- Background: `#1E1E1E` (dark grey)
- Foreground: `#FFFFFF` (white)
- Primary: `#4FC3F7` (light blue)
- Error: `#F44336` (red)
- Warning: `#FF9800` (orange)
- Success: `#4CAF50` (green)

### None Theme

The `none` theme disables all theming and renders plain, unstyled output. This is useful for piping output to other tools or for terminals with limited capabilities.

## Integration with Glamour

The theme system integrates with Glamour for markdown rendering:

- Light theme uses Glamour's "light" style
- Dark theme uses Glamour's "dark" style
- Auto theme uses Glamour's "auto" style (detects terminal capabilities)
- None theme disables Glamour styling

## Terminal Compatibility

The theme system respects terminal capabilities:

- Basic terminals (xterm): Default to light theme
- Modern terminals (256color, truecolor): Prefer dark theme
- Terminal programs with dark variants: Automatically use dark theme

This ensures optimal display across different terminal environments.
