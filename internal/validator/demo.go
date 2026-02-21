// Package validator provides demo validation functionality for OPNsense configurations.
package validator

import (
	"fmt"

	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// DemoValidation runs example validations of OPNsense configuration data, printing results for valid, invalid, and cross-field error scenarios.
//
// DemoValidation demonstrates the validation of OPNsense configuration documents using sample data.
// It constructs valid, invalid, and cross-field error examples, runs validation on each, and prints the resulting validation messages.
func DemoValidation() {
	fmt.Println("=== OPNsense Configuration Validator Demo ===")

	// Example 1: Valid configuration
	fmt.Println("1. Valid Configuration:")

	validConfig := &schema.OpnSenseDocument{
		System: schema.System{
			Hostname: "OPNsense",
			Domain:   "localdomain",
			Timezone: "America/New_York",
			Group: []schema.Group{
				{Name: "admins", Gid: "1999", Scope: "system"},
			},
			User: []schema.User{
				{Name: "root", UID: "0", Groupname: "admins", Scope: "system"},
			},
		},
		Filter: schema.Filter{
			Rule: []schema.Rule{
				{Type: "pass", IPProtocol: "inet", Interface: schema.InterfaceList{"lan"}},
			},
		},
	}

	errors := ValidateOpnSenseDocument(validConfig)
	if len(errors) == 0 {
		fmt.Println("✓ Configuration is valid!")
	} else {
		fmt.Printf("✗ Found %d validation errors:\n", len(errors))

		for _, err := range errors {
			fmt.Printf("  - %s\n", err.Error())
		}

		fmt.Println()
	}

	// Example 2: Invalid configuration
	fmt.Println("2. Invalid Configuration:")

	invalidConfig := &schema.OpnSenseDocument{
		System: schema.System{
			// Missing required hostname
			Domain:       "example.com",
			Timezone:     "Invalid/Timezone", // Invalid timezone
			Optimization: "invalid",          // Invalid optimization
			Group: []schema.Group{
				{Name: "admins", Gid: "abc", Scope: "invalid"}, // Invalid GID and scope
				{Name: "admins", Gid: "1999", Scope: "system"}, // Duplicate name
			},
			User: []schema.User{
				{Name: "root", UID: "-1", Groupname: "nonexistent", Scope: "system"}, // Negative UID, invalid group
			},
		},
		Interfaces: schema.Interfaces{
			Items: map[string]schema.Interface{
				"lan": {
					IPAddr:   "invalid-ip", // Invalid IP
					Subnet:   "35",         // Invalid subnet
					IPAddrv6: "track6",     // Missing required track6 fields
				},
			},
		},
		Dhcpd: schema.Dhcpd{
			Items: map[string]schema.DhcpdInterface{
				"lan": {
					Range: schema.Range{
						From: "192.168.1.200",
						To:   "192.168.1.100", // Invalid range order
					},
				},
			},
		},
		Filter: schema.Filter{
			Rule: []schema.Rule{
				{Type: "invalid", IPProtocol: "ipv4", Interface: schema.InterfaceList{"invalid"}}, // All invalid
			},
		},
	}

	errors = ValidateOpnSenseDocument(invalidConfig)
	fmt.Printf("✗ Found %d validation errors:\n", len(errors))

	for _, err := range errors {
		fmt.Printf("  - %s\n", err.Error())
	}

	fmt.Println()

	// Example 3: Cross-field validation
	fmt.Println("3. Cross-field Validation Example:")

	crossFieldConfig := &schema.OpnSenseDocument{
		System: schema.System{
			Hostname: "test",
			Domain:   "example.com",
			User: []schema.User{
				{
					Name:      "user1",
					UID:       "1000",
					Groupname: "nonexistent",
					Scope:     "system",
				}, // References non-existent group
			},
		},
		Interfaces: schema.Interfaces{
			Items: map[string]schema.Interface{
				"lan": {
					IPAddrv6: "track6", // Missing track6-interface and track6-prefix-id
				},
			},
		},
	}

	errors = ValidateOpnSenseDocument(crossFieldConfig)
	fmt.Printf("✗ Found %d cross-field validation errors:\n", len(errors))

	for _, err := range errors {
		fmt.Printf("  - %s\n", err.Error())
	}
}
