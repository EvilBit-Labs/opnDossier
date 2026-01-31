// Package main generates model reference documentation from Go types.
//
//go:build ignore

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

const (
	defaultOutputFile = "docs/templates/model-reference.md"
)

func main() {
	outputFile := flag.String("output", defaultOutputFile, "Output file path")
	timestamp := flag.String("timestamp", "", "Override timestamp (use 'none' to omit, empty for current time)")
	flag.Parse()

	content := generateModelReference(*timestamp)

	// Ensure output directory exists
	dir := filepath.Dir(*outputFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating directory %s: %v\n", dir, err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outputFile, []byte(content), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file %s: %v\n", *outputFile, err)
		os.Exit(1)
	}

	fmt.Printf("Generated model reference: %s\n", *outputFile)
}

func generateModelReference(timestamp string) string {
	var sb strings.Builder

	// Header
	sb.WriteString("# Model Reference\n\n")
	sb.WriteString("> **Auto-generated documentation** - Do not edit manually.\n")
	if timestamp != "none" {
		if timestamp == "" {
			timestamp = time.Now().Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(&sb, "> Generated: %s\n\n", timestamp)
	} else {
		sb.WriteString("\n")
	}

	sb.WriteString("This document provides a complete reference of all data fields ")
	sb.WriteString("available in the opnDossier configuration model. Use this reference ")
	sb.WriteString("when working with JSON/YAML exports or building custom integrations.\n\n")

	sb.WriteString("## Table of Contents\n\n")
	sb.WriteString("- [OpnSenseDocument (Root)](#opnsensedocument-root)\n")
	sb.WriteString("- [System Configuration](#system-configuration)\n")
	sb.WriteString("- [Network Interfaces](#network-interfaces)\n")
	sb.WriteString("- [Firewall & Security](#firewall--security)\n")
	sb.WriteString("- [Services](#services)\n")
	sb.WriteString("- [VPN Configuration](#vpn-configuration)\n\n")

	// OpnSenseDocument root
	sb.WriteString("---\n\n")
	sb.WriteString("## OpnSenseDocument (Root)\n\n")
	sb.WriteString("The root configuration object parsed from OPNsense XML.\n\n")
	generateStructTable(&sb, reflect.TypeFor[schema.OpnSenseDocument](), "")

	// System section
	sb.WriteString("\n---\n\n")
	sb.WriteString("## System Configuration\n\n")
	sb.WriteString("Core system settings including hostname, users, and SSH configuration.\n\n")
	sb.WriteString("### System\n\n")
	generateStructTable(&sb, reflect.TypeFor[schema.System](), "system")

	sb.WriteString("\n### User\n\n")
	generateStructTable(&sb, reflect.TypeFor[schema.User](), "system.users[]")

	sb.WriteString("\n### Group\n\n")
	generateStructTable(&sb, reflect.TypeFor[schema.Group](), "system.groups[]")

	// Network section
	sb.WriteString("\n---\n\n")
	sb.WriteString("## Network Interfaces\n\n")
	sb.WriteString("Network interface configuration including VLANs and gateways.\n\n")
	sb.WriteString("### Interface\n\n")
	generateStructTable(&sb, reflect.TypeFor[schema.Interface](), "interfaces.<name>")

	sb.WriteString("\n### Gateway\n\n")
	generateStructTable(&sb, reflect.TypeFor[schema.Gateway](), "gateways.item[]")

	// Firewall section
	sb.WriteString("\n---\n\n")
	sb.WriteString("## Firewall & Security\n\n")
	sb.WriteString("Firewall rules and NAT configuration.\n\n")
	sb.WriteString("### Rule (Firewall)\n\n")
	generateStructTable(&sb, reflect.TypeFor[schema.Rule](), "filter.rule[]")

	sb.WriteString("\n### NATRule (Outbound)\n\n")
	generateStructTable(&sb, reflect.TypeFor[schema.NATRule](), "nat.outbound.rule[]")

	// Services section
	sb.WriteString("\n---\n\n")
	sb.WriteString("## Services\n\n")
	sb.WriteString("System services configuration.\n\n")
	sb.WriteString("### Unbound (DNS)\n\n")
	generateStructTable(&sb, reflect.TypeFor[schema.Unbound](), "unbound")

	sb.WriteString("\n### DHCP Interface\n\n")
	generateStructTable(&sb, reflect.TypeFor[schema.DhcpdInterface](), "dhcpd.<interface>")

	// VPN section
	sb.WriteString("\n---\n\n")
	sb.WriteString("## VPN Configuration\n\n")
	sb.WriteString("VPN service configuration including OpenVPN and WireGuard.\n\n")
	sb.WriteString("### OpenVPN Server\n\n")
	generateStructTable(&sb, reflect.TypeFor[schema.OpenVPNServer](), "openvpn.server[]")

	sb.WriteString("\n### OpenVPN Client\n\n")
	generateStructTable(&sb, reflect.TypeFor[schema.OpenVPNClient](), "openvpn.client[]")

	// Footer
	sb.WriteString("\n---\n\n")
	sb.WriteString("## Usage Examples\n\n")
	sb.WriteString("### Accessing Fields in JSON Export\n\n")
	sb.WriteString("```bash\n")
	sb.WriteString("# Export configuration to JSON\n")
	sb.WriteString("opndossier convert config.xml --format json -o config.json\n\n")
	sb.WriteString("# Extract hostname using jq\n")
	sb.WriteString("jq '.system.hostname' config.json\n\n")
	sb.WriteString("# List all interfaces\n")
	sb.WriteString("jq '.interfaces | keys' config.json\n\n")
	sb.WriteString("# Get firewall rules\n")
	sb.WriteString("jq '.filter.rule[]' config.json\n")
	sb.WriteString("```\n\n")

	sb.WriteString("### Accessing Fields in YAML Export\n\n")
	sb.WriteString("```bash\n")
	sb.WriteString("# Export configuration to YAML\n")
	sb.WriteString("opndossier convert config.xml --format yaml -o config.yaml\n\n")
	sb.WriteString("# Extract hostname using yq\n")
	sb.WriteString("yq '.system.hostname' config.yaml\n")
	sb.WriteString("```\n")

	return sb.String()
}

func generateStructTable(sb *strings.Builder, t reflect.Type, prefix string) {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		sb.WriteString("*Not a struct type*\n")
		return
	}

	// Count exportable fields
	exportedCount := 0
	for i := range t.NumField() {
		if t.Field(i).IsExported() {
			exportedCount++
		}
	}

	if exportedCount == 0 {
		sb.WriteString("*No exported fields*\n")
		return
	}

	// Table header
	sb.WriteString("| Field | Type | JSON Path | Description |\n")
	sb.WriteString("|-------|------|-----------|-------------|\n")

	for i := range t.NumField() {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}

		jsonTag := extractTag(field.Tag, "json")
		if jsonTag == "-" {
			continue // Skip fields marked as json:"-"
		}

		path := jsonTag
		if prefix != "" && jsonTag != "" {
			path = prefix + "." + jsonTag
		} else if prefix != "" {
			path = prefix + "." + strings.ToLower(field.Name)
		}

		typeName := formatTypeName(field.Type)
		desc := extractDescription(field)

		fmt.Fprintf(sb, "| `%s` | `%s` | `%s` | %s |\n",
			field.Name, typeName, path, desc)
	}
}

func extractTag(tag reflect.StructTag, key string) string {
	value := tag.Get(key)
	if value == "" {
		return ""
	}
	if before, _, found := strings.Cut(value, ","); found {
		return before
	}
	return value
}

func formatTypeName(t reflect.Type) string {
	switch t.Kind() {
	case reflect.Ptr:
		return "*" + formatTypeName(t.Elem())
	case reflect.Slice:
		return "[]" + formatTypeName(t.Elem())
	case reflect.Map:
		keyName := t.Key().Name()
		if keyName == "" {
			keyName = t.Key().Kind().String()
		}
		return fmt.Sprintf("map[%s]%s", keyName, formatTypeName(t.Elem()))
	case reflect.Struct:
		name := t.Name()
		if name == "" {
			return "struct"
		}
		return name
	case reflect.Interface:
		name := t.Name()
		if name == "" {
			return "interface{}"
		}
		return name
	default:
		name := t.Name()
		if name == "" {
			return t.Kind().String()
		}
		return name
	}
}

func extractDescription(field reflect.StructField) string {
	var parts []string

	// Check for validate tag to infer constraints
	validate := field.Tag.Get("validate")
	if validate != "" {
		if strings.Contains(validate, "required") {
			parts = append(parts, "Required")
		}
		if strings.Contains(validate, "oneof=") {
			start := strings.Index(validate, "oneof=") + 6
			end := strings.Index(validate[start:], " ")
			if end == -1 {
				end = len(validate) - start
			}
			options := validate[start : start+end]
			parts = append(parts, fmt.Sprintf("Options: %s", strings.ReplaceAll(options, " ", ", ")))
		}
		// Additional validation constraints
		if strings.Contains(validate, "ip") {
			parts = append(parts, "IP address")
		}
		if strings.Contains(validate, "cidr") {
			parts = append(parts, "CIDR notation")
		}
		if strings.Contains(validate, "url") {
			parts = append(parts, "URL")
		}
		if strings.Contains(validate, "email") {
			parts = append(parts, "Email")
		}
	}

	if len(parts) > 0 {
		return strings.Join(parts, "; ")
	}

	// Check for omitempty
	json := field.Tag.Get("json")
	if strings.Contains(json, "omitempty") {
		return "Optional"
	}

	return "-"
}
