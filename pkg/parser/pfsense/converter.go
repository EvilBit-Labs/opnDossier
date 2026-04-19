package pfsense

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
)

// ErrNilDocument is returned when ToCommonDevice receives a nil document.
var ErrNilDocument = errors.New("pfsense converter: received nil document")

// PfsenseKnownGapMessage is the stable message text emitted for every
// CommonDevice subsystem listed in [pfsenseKnownGaps]. Consumers (compliance
// plugins, audit filters) can match on this exact substring to identify
// warnings that report "this subsystem is not yet implemented by the pfSense
// converter" rather than "the XML configuration omits the subsystem". The
// wording is part of the public contract and will remain stable across minor
// releases.
const PfsenseKnownGapMessage = "not yet implemented in pfSense converter"

// pfsenseKnownGaps is the single source of truth for CommonDevice subsystems
// that OPNsense's converter populates but the pfSense converter does not yet.
// Each entry yields one [common.ConversionWarning] at [common.SeverityMedium]
// during [converter.ToCommonDevice], so downstream consumers can distinguish
// "feature absent in config" from "converter gap" without inspecting code.
//
// The list is consumed by:
//   - [converter.emitKnownGapWarnings]: emits one warning per entry.
//   - [IsKnownGap]: the public accessor used by the cross-device parity test
//     in pkg/parser/parity_test.go to whitelist expected drops.
//   - docs/user-guide/device-support-matrix.md: the user-facing coverage table.
//
// When a subsystem lands in the pfSense converter, remove its entry here in
// the same change that populates the field. The parity test fails loudly if
// the allowlist diverges from the actual converter output.
var pfsenseKnownGaps = []string{
	"Theme",
	"Bridges",
	"GIFs",
	"GREs",
	"LAGGs",
	"VirtualIPs",
	"InterfaceGroups",
	"NTP",
	"HighAvailability",
	"IDS",
	"Sysctl",
	"Packages",
	"Monit",
	"Netflow",
	"TrafficShaper",
	"CaptivePortal",
	"Trust",
	"KeaDHCP",
}

// IsKnownGap reports whether field names a CommonDevice subsystem that the
// pfSense converter knowingly does not populate. The comparison is
// case-sensitive and matches the exact CommonDevice field name (e.g.
// "HighAvailability", "KeaDHCP"). Callers outside the parser use this to
// avoid false-PASS results when reasoning about pfSense coverage — see
// docs/user-guide/device-support-matrix.md for the human-readable table.
//
// IsKnownGap is safe for concurrent use; the underlying slice is never
// mutated after package init.
func IsKnownGap(field string) bool {
	return slices.Contains(pfsenseKnownGaps, field)
}

// KnownGaps returns a fresh copy of [pfsenseKnownGaps] so callers can
// iterate the full list (e.g. in tests that assert one warning per gap)
// without risking mutation of the package-level slice.
func KnownGaps() []string {
	out := make([]string, len(pfsenseKnownGaps))
	copy(out, pfsenseKnownGaps)
	return out
}

// converter transforms a pfsense.Document into a common.CommonDevice.
// A converter is stateful (it accumulates warnings) and is NOT safe for
// concurrent use. Create a new instance per conversion via newConverter().
type converter struct {
	warnings []common.ConversionWarning
}

// newConverter returns a new converter.
func newConverter() *converter {
	return &converter{}
}

// ConvertDocument transforms a parsed pfSense Document into a platform-agnostic
// CommonDevice along with any non-fatal conversion warnings. This is a
// convenience function that creates a fresh converter internally.
func ConvertDocument(doc *pfsense.Document) (*common.CommonDevice, []common.ConversionWarning, error) {
	return newConverter().ToCommonDevice(doc)
}

// addWarning records a non-fatal conversion issue.
func (c *converter) addWarning(field, value, message string, severity common.Severity) {
	c.warnings = append(c.warnings, common.ConversionWarning{
		Field:    field,
		Value:    value,
		Message:  message,
		Severity: severity,
	})
}

// emitKnownGapWarnings emits one SeverityMedium ConversionWarning for every
// subsystem in pfsenseKnownGaps, using the stable PfsenseKnownGapMessage so
// downstream consumers can filter. Callers can match on the exact message
// substring to distinguish "converter gap" from "XML omits the subsystem".
func (c *converter) emitKnownGapWarnings() {
	for _, gap := range pfsenseKnownGaps {
		c.addWarning(gap, "", PfsenseKnownGapMessage, common.SeverityMedium)
	}
}

// ToCommonDevice converts a pfSense document into a platform-agnostic CommonDevice.
// Returns ErrNilDocument if doc is nil.
func (c *converter) ToCommonDevice(
	doc *pfsense.Document,
) (*common.CommonDevice, []common.ConversionWarning, error) {
	c.warnings = nil

	if doc == nil {
		return nil, nil, fmt.Errorf("ToCommonDevice: %w", ErrNilDocument)
	}

	c.emitKnownGapWarnings()

	device := &common.CommonDevice{
		DeviceType:    common.DeviceTypePfSense,
		Version:       doc.Version,
		System:        c.convertSystem(doc),
		Interfaces:    c.convertInterfaces(doc),
		VLANs:         c.convertVLANs(doc),
		PPPs:          c.convertPPPs(doc),
		FirewallRules: c.convertFirewallRules(doc),
		NAT:           c.convertNAT(doc),
		DHCP:          c.convertDHCP(doc),
		DNS:           c.convertDNS(doc),
		SNMP:          c.convertSNMP(doc),
		LoadBalancer:  c.convertLoadBalancer(doc),
		VPN:           c.convertVPN(doc),
		Routing:       c.convertRouting(doc),
		Syslog:        c.convertSyslog(doc),
		Users:         c.convertUsers(doc),
		Groups:        c.convertGroups(doc),
		Revision:      c.convertRevision(doc),
		Certificates:  c.convertCertificates(doc),
		CAs:           c.convertCAs(doc),
		Cron:          c.convertCron(doc),
	}

	return device, c.warnings, nil
}

// convertSystem maps doc.System to common.System.
func (c *converter) convertSystem(doc *pfsense.Document) common.System {
	sys := doc.System

	return common.System{
		Hostname:                      sys.Hostname,
		Domain:                        sys.Domain,
		Firmware:                      common.Firmware{Version: doc.Version},
		Optimization:                  sys.Optimization,
		Language:                      sys.Language,
		Timezone:                      sys.Timezone,
		DNSServers:                    sys.DNSServers,
		TimeServers:                   strings.Fields(sys.TimeServers),
		DNSAllowOverride:              bool(sys.DNSAllowOverride),
		DisableNATReflection:          strings.EqualFold(sys.DisableNATReflection, xmlBoolYes),
		DisableSegmentationOffloading: bool(sys.DisableSegmentationOffloading),
		DisableLargeReceiveOffloading: bool(sys.DisableLargeReceiveOffloading),
		IPv6Allow:                     sys.IPv6Allow != "",
		NextUID:                       sys.NextUID,
		NextGID:                       sys.NextGID,
		PowerdACMode:                  sys.PowerdACMode,
		PowerdBatteryMode:             sys.PowerdBatteryMode,
		PowerdNormalMode:              sys.PowerdNormalMode,
		Bogons:                        common.Bogons{Interval: sys.Bogons.Interval},
		WebGUI: common.WebGUI{
			Protocol:          sys.WebGUI.Protocol,
			SSLCertRef:        sys.WebGUI.SSLCertRef,
			LoginAutocomplete: bool(sys.WebGUI.LoginAutocomplete),
			MaxProcesses:      sys.WebGUI.MaxProcesses,
		},
		SSH: common.SSH{
			Enabled: bool(sys.SSH.Enabled),
			Port:    sys.SSH.Port,
			Group:   sys.SSH.Group,
		},
	}
}

// convertUsers maps doc.System.User to []common.User.
func (c *converter) convertUsers(doc *pfsense.Document) []common.User {
	if len(doc.System.User) == 0 {
		return nil
	}

	result := make([]common.User, 0, len(doc.System.User))
	for i, u := range doc.System.User {
		if u.Name == "" {
			c.addWarning(fmt.Sprintf("Users[%d].Name", i), u.UID, "user has empty name", common.SeverityHigh)
		}
		if u.UID == "" {
			c.addWarning(fmt.Sprintf("Users[%d].UID", i), u.Name, "user has no UID", common.SeverityHigh)
		}

		result = append(result, common.User{
			Name:        u.Name,
			Disabled:    bool(u.Disabled),
			Description: u.Descr,
			Scope:       u.Scope,
			GroupName:   u.Groupname,
			UID:         u.UID,
		})
	}

	return result
}

// convertGroups maps doc.System.Group to []common.Group.
func (c *converter) convertGroups(doc *pfsense.Document) []common.Group {
	if len(doc.System.Group) == 0 {
		return nil
	}

	result := make([]common.Group, 0, len(doc.System.Group))
	for _, g := range doc.System.Group {
		result = append(result, common.Group{
			Name:        g.Name,
			Description: g.Description,
			Scope:       g.Scope,
			GID:         g.Gid,
			Member:      strings.Join(g.Member, ", "),
			Privileges:  strings.Join(g.Priv, ", "),
		})
	}

	return result
}
