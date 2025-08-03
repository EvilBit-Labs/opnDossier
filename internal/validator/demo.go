// Package validator provides demo validation functionality for OPNsense configurations.
package validator

import (
	"fmt"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// DemoValidation runs example validations of OPNsense configuration data, printing results for valid, invalid, and cross-field error scenarios.
//
// DemoValidation demonstrates the validation of OPNsense configuration documents using sample data.
// It constructs valid, invalid, and cross-field error examples, runs validation on each, and prints the resulting validation messages.
func DemoValidation() {
	fmt.Println("=== OPNsense Configuration Validator Demo ===")

	// Example 1: Valid configuration
	fmt.Println("1. Valid Configuration:")

	validConfig := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "OPNsense",
			Domain:   "localdomain",
			Timezone: "America/New_York",
			Group: []model.Group{
				{Name: "admins", Gid: "1999", Scope: "system"},
			},
			User: []model.User{
				{Name: "root", UID: "0", Groupname: "admins", Scope: "system"},
			},
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				{Type: "pass", IPProtocol: "inet", Interface: "lan"},
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

	invalidConfig := &model.OpnSenseDocument{
		System: model.System{
			// Missing required hostname
			Domain:       "example.com",
			Timezone:     "Invalid/Timezone", // Invalid timezone
			Optimization: "invalid",          // Invalid optimization
			Group: []model.Group{
				{Name: "admins", Gid: "abc", Scope: "invalid"}, // Invalid GID and scope
				{Name: "admins", Gid: "1999", Scope: "system"}, // Duplicate name
			},
			User: []model.User{
				{Name: "root", UID: "-1", Groupname: "nonexistent", Scope: "system"}, // Negative UID, invalid group
			},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"lan": {
					IPAddr:   "invalid-ip", // Invalid IP
					Subnet:   "35",         // Invalid subnet
					IPAddrv6: "track6",     // Missing required track6 fields
				},
			},
		},
		Dhcpd: model.Dhcpd{
			Items: map[string]model.DhcpdInterface{
				"lan": {
					Range: model.Range{
						From: "192.168.1.200",
						To:   "192.168.1.100", // Invalid range order
					},
				},
			},
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				{Type: "invalid", IPProtocol: "ipv4", Interface: "invalid"}, // All invalid
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

	crossFieldConfig := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test",
			Domain:   "example.com",
			User: []model.User{
				{
					Name:      "user1",
					UID:       "1000",
					Groupname: "nonexistent",
					Scope:     "system",
				}, // References non-existent group
			},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
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
