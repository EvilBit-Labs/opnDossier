# Theme System Usage

This document describes how to use the comprehensive theme system in opnDossier.

## Theme Configuration

The theme system supports multiple configuration methods with the following precedence:

1. **CLI flag** (highest priority): `--theme light|dark|custom`
2. **Environment variable**: `OPNDOSSIER_THEME=light|dark|custom`
3. **YAML configuration file**: `theme: light|dark|custom`
4. **Auto-detection** (lowest priority): Based on terminal capabilities

## Usage Examples

### CLI Flag Override

```bash
# Force light theme
opnDossier --theme light convert config.xml

# Force dark theme
opnDossier --theme dark convert config.xml

# Use custom theme
opnDossier --theme custom convert config.xml
```

### Environment Variable

```bash
# Set theme via environment variable
export OPNDOSSIER_THEME=dark
opnDossier convert config.xml

# One-time override
OPNDOSSIER_THEME=light opnDossier convert config.xml
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

### Custom Theme

The custom theme allows for user-defined color schemes (implementation depends on specific requirements).

## Integration with Glamour

The theme system integrates with Glamour for markdown rendering:

- Light theme uses Glamour's "light" style
- Dark theme uses Glamour's "dark" style
- Custom theme uses Glamour's "auto" style

## Terminal Compatibility

The theme system respects terminal capabilities:

- Basic terminals (xterm): Default to light theme
- Modern terminals (256color, truecolor): Prefer dark theme
- Terminal programs with dark variants: Automatically use dark theme

This ensures optimal display across different terminal environments.
