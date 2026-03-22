package pfsense

import (
	"errors"
	"fmt"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
)

// ErrNilDocument is returned when ToCommonDevice receives a nil document.
var ErrNilDocument = errors.New("pfsense converter: received nil document")

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

// ToCommonDevice converts a pfSense document into a platform-agnostic CommonDevice.
// Returns ErrNilDocument if doc is nil.
func (c *converter) ToCommonDevice(
	doc *pfsense.Document,
) (*common.CommonDevice, []common.ConversionWarning, error) {
	c.warnings = nil

	if doc == nil {
		return nil, nil, fmt.Errorf("ToCommonDevice: %w", ErrNilDocument)
	}

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
		DNSAllowOverride:              sys.DNSAllowOverride != 0,
		DisableNATReflection:          strings.EqualFold(sys.DisableNATReflection, xmlBoolYes),
		DisableSegmentationOffloading: sys.DisableSegmentationOffloading != 0,
		DisableLargeReceiveOffloading: sys.DisableLargeReceiveOffloading != 0,
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
			Member:      strings.Join(g.Member, ","),
			Privileges:  strings.Join(g.Priv, ", "),
		})
	}

	return result
}
