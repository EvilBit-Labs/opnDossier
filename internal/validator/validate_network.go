package validator

import (
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// collectInterfaceNames returns every key from the interfaces map as a set.
func collectInterfaceNames(ifaces *schema.Interfaces) map[string]struct{} {
	interfaceNames := make(map[string]struct{})

	if ifaces != nil && ifaces.Items != nil {
		for name := range ifaces.Items {
			interfaceNames[name] = struct{}{}
		}
	}

	return interfaceNames
}

// validateInterfaces validates all configured network interfaces and returns any validation errors found.
func validateInterfaces(interfaces *schema.Interfaces) []ValidationError {
	var errors []ValidationError

	if interfaces == nil || interfaces.Items == nil {
		return errors
	}

	// Pre-compute interface names once to avoid O(N^2) recomputation per interface
	validInterfaceNames := collectInterfaceNames(interfaces)

	// Validate each configured interface
	for name, iface := range interfaces.Items {
		ifaceCopy := iface // Create a copy to get a pointer
		errors = append(errors, validateInterface(&ifaceCopy, name, validInterfaceNames)...)
	}

	return errors
}

// validateInterface checks a single network interface configuration for valid IP address types and formats, subnet masks, MTU range, and required fields for track6 IPv6 addressing.
// It returns a slice of ValidationError for any invalid or missing configuration fields.
func validateInterface(
	iface *schema.Interface,
	name string,
	validInterfaceNames map[string]struct{},
) []ValidationError {
	var errors []ValidationError

	if iface == nil {
		return errors
	}

	errors = append(errors, validateIPAddress(iface, name)...)                   // IP Address Validation
	errors = append(errors, validateIPv6Address(iface, name)...)                 // IPv6 Address Validation
	errors = append(errors, validateSubnet(iface, name)...)                      // Subnet Mask Validation
	errors = append(errors, validateMTU(iface, name)...)                         // MTU Validation
	errors = append(errors, validateTrack6(iface, validInterfaceNames, name)...) // Track6 Specific Validation

	return errors
}

// validateIPAddress validates the IP address of an interface.
func validateIPAddress(iface *schema.Interface, name string) []ValidationError {
	var errors []ValidationError
	if iface.IPAddr != "" {
		validIPTypes := []string{"dhcp", "none"}
		if !contains(validIPTypes, iface.IPAddr) && !isValidIP(iface.IPAddr) {
			errors = append(errors, ValidationError{
				Field: fmt.Sprintf("interfaces.%s.ipaddr", name),
				Message: fmt.Sprintf(
					"IP address '%s' must be a valid IP address or one of: %v",
					iface.IPAddr,
					validIPTypes,
				),
			})
		}
	}
	return errors
}

// validateIPv6Address validates the IPv6 address of an interface.
func validateIPv6Address(iface *schema.Interface, name string) []ValidationError {
	var errors []ValidationError
	if iface.IPAddrv6 != "" {
		validIPv6Types := []string{"dhcp6", "slaac", "track6", "none"}
		if !contains(validIPv6Types, iface.IPAddrv6) && !isValidIPv6(iface.IPAddrv6) {
			errors = append(errors, ValidationError{
				Field: fmt.Sprintf("interfaces.%s.ipaddrv6", name),
				Message: fmt.Sprintf(
					"IPv6 address '%s' must be a valid IPv6 address or one of: %v",
					iface.IPAddrv6,
					validIPv6Types,
				),
			})
		}
	}
	return errors
}

// validateSubnet validates the subnet mask of an interface.
func validateSubnet(iface *schema.Interface, name string) []ValidationError {
	var errors []ValidationError
	if iface.Subnet != "" {
		if subnet, err := strconv.Atoi(iface.Subnet); err != nil || subnet < 0 || subnet > 32 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.subnet", name),
				Message: fmt.Sprintf("subnet mask '%s' must be a valid subnet mask (0-32)", iface.Subnet),
			})
		}
	}
	if iface.Subnetv6 != "" {
		if subnet, err := strconv.Atoi(iface.Subnetv6); err != nil || subnet < 0 || subnet > 128 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.subnetv6", name),
				Message: fmt.Sprintf("IPv6 subnet mask '%s' must be a valid IPv6 subnet mask (0-128)", iface.Subnetv6),
			})
		}
	}
	return errors
}

// validateMTU validates the MTU of an interface.
func validateMTU(iface *schema.Interface, name string) []ValidationError {
	var errors []ValidationError
	if iface.MTU != "" {
		if mtu, err := strconv.Atoi(iface.MTU); err != nil || mtu < constants.MinMTU || mtu > constants.MaxMTU {
			errors = append(errors, ValidationError{
				Field: fmt.Sprintf("interfaces.%s.mtu", name),
				Message: fmt.Sprintf(
					"MTU '%s' must be a valid MTU (%d-%d)",
					iface.MTU,
					constants.MinMTU,
					constants.MaxMTU,
				),
			})
		}
	}
	return errors
}

// validateTrack6 performs cross-field validation for track6 configurations.
func validateTrack6(iface *schema.Interface, validInterfaceNames map[string]struct{}, name string) []ValidationError {
	var errors []ValidationError
	if iface.IPAddrv6 == "track6" {
		if iface.Track6Interface == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.track6-interface", name),
				Message: "track6-interface is required when using track6 IPv6 addressing",
			})
		} else {
			// Validate that the referenced interface exists
			if _, exists := validInterfaceNames[iface.Track6Interface]; !exists {
				// Create a sorted slice of interface names for error message
				interfaceList := slices.Sorted(maps.Keys(validInterfaceNames))

				errors = append(errors, ValidationError{
					Field: fmt.Sprintf("interfaces.%s.track6-interface", name),
					Message: fmt.Sprintf(
						"track6-interface '%s' must reference a configured interface: %v",
						iface.Track6Interface,
						interfaceList,
					),
				})
			}
		}

		if iface.Track6PrefixID == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.track6-prefix-id", name),
				Message: "track6-prefix-id is required when using track6 IPv6 addressing",
			})
		}
	}
	return errors
}

// validateDhcpd iterates over the interface map and validates each DHCP block that exists in the dhcpd section.
// It returns a slice of ValidationError for any invalid or inconsistent DHCP configuration fields.
func validateDhcpd(dhcpd *schema.Dhcpd, interfaces *schema.Interfaces) []ValidationError {
	var errors []ValidationError

	if dhcpd == nil || dhcpd.Items == nil {
		return errors
	}

	// Get valid interface names for cross-validation
	ifaceSet := collectInterfaceNames(interfaces)

	// Validate each DHCP interface configuration
	for name, cfg := range dhcpd.Items {
		errors = append(errors, validateDhcpdInterface(name, cfg, ifaceSet)...)
	}

	return errors
}

// validateDhcpdInterface checks a DHCP interface configuration for validity, ensuring the referenced interface exists and that any specified DHCP range addresses are valid IPs with the 'from' address less than the 'to' address.
//
// Returns a slice of ValidationError for any detected issues.
func validateDhcpdInterface(name string, cfg schema.DhcpdInterface, ifaceSet map[string]struct{}) []ValidationError {
	var errors []ValidationError

	// Validate that the interface exists in the configuration
	if _, exists := ifaceSet[name]; !exists {
		// Create a sorted slice of interface names for error message
		interfaceList := slices.Sorted(maps.Keys(ifaceSet))

		errors = append(errors, ValidationError{
			Field:   "dhcpd." + name,
			Message: fmt.Sprintf("DHCP interface '%s' must reference a configured interface: %v", name, interfaceList),
		})
	}

	// Validate DHCP range if either from or to is set
	if cfg.Range.From != "" || cfg.Range.To != "" {
		if cfg.Range.From != "" && !isValidIP(cfg.Range.From) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("dhcpd.%s.range.from", name),
				Message: fmt.Sprintf("DHCP range 'from' address '%s' must be a valid IP address", cfg.Range.From),
			})
		}

		if cfg.Range.To != "" && !isValidIP(cfg.Range.To) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("dhcpd.%s.range.to", name),
				Message: fmt.Sprintf("DHCP range 'to' address '%s' must be a valid IP address", cfg.Range.To),
			})
		}

		// Cross-validation: from address should be less than to address
		if isValidIP(cfg.Range.From) && isValidIP(cfg.Range.To) {
			fromIP := net.ParseIP(cfg.Range.From).To4()

			toIP := net.ParseIP(cfg.Range.To).To4()
			if fromIP != nil && toIP != nil {
				// Compare byte by byte
				for i := range 4 {
					if fromIP[i] > toIP[i] {
						errors = append(errors, ValidationError{
							Field: fmt.Sprintf("dhcpd.%s.range", name),
							Message: fmt.Sprintf(
								"DHCP range 'from' address (%s) must be less than 'to' address (%s)",
								cfg.Range.From,
								cfg.Range.To,
							),
						})

						break
					} else if fromIP[i] < toIP[i] {
						break
					}
				}
			}
		}
	}

	return errors
}
