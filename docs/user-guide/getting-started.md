# Getting Started with opnDossier

By the end of this tutorial, you will have installed opnDossier and generated your first configuration report.

## Prerequisites

- An OPNsense `config.xml` file (exported from your firewall via **System > Configuration > Backups**)

## 1. Install opnDossier

Pick the method that fits your platform:

**macOS (Homebrew):**

```bash
brew install EvilBit-Labs/tap/opndossier
```

**Go (any platform with Go 1.26+):**

```bash
go install github.com/EvilBit-Labs/opnDossier@latest
```

**Linux packages, Docker, and pre-built binaries** are also available -- see the [Installation Guide](installation.md) for all options.

**Expected result:** the `opndossier` command is now available in your shell.

## 2. Verify the Installation

```bash
opndossier version
```

**Expected result:** a version string such as `opnDossier v0.9.0`.

If you see `command not found`, ensure the Go bin directory (typically `$HOME/go/bin`) is in your `PATH`.

## 3. Convert a Config to Markdown

Generate a Markdown report from your OPNsense configuration:

```bash
opndossier convert config.xml
```

**Expected result:** Markdown output printed to your terminal, including sections for interfaces, firewall rules, VPN tunnels, and other configured services.

## 4. Save the Report to a File

Write the report directly to a file instead of stdout:

```bash
opndossier convert config.xml -o report.md
```

**Expected result:** opnDossier writes the report without any terminal output. Open `report.md` in any Markdown viewer to browse the full report.

## 5. View in the Terminal

Display the configuration with terminal styling and syntax highlighting:

```bash
opndossier display config.xml
```

**Expected result:** a styled, color-highlighted overview of your configuration rendered directly in the terminal.

## 6. Validate a Config

Check your configuration for structural issues:

```bash
opndossier validate config.xml
```

**Expected result:** a validation summary. If the configuration is well-formed, you will see a message confirming validation passed.

## Next Steps

You now have the basics down. Explore further:

- [Installation Guide](installation.md) -- additional installation methods and platform-specific instructions
- [Commands Overview](commands/overview.md) -- the full command reference
- [Common Workflows](workflows.md) -- real-world patterns for auditing, diffing, and reporting
- [Configuration Guide](configuration.md) -- customize opnDossier to fit your workflow
