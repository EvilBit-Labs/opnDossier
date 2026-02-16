package schema

import (
	"testing"
)

// Network Constructor Tests

func TestNewNetworkConfig(t *testing.T) {
	t.Parallel()

	config := NewNetworkConfig()

	// Check that VLANs slice is initialized and empty
	if config.VLANs == nil {
		t.Error("VLANs should be initialized")
	}
	if len(config.VLANs) != 0 {
		t.Errorf("VLANs should be empty, got %d items", len(config.VLANs))
	}

	// Check that Gateways slice is initialized and empty
	if config.Gateways == nil {
		t.Error("Gateways should be initialized")
	}
	if len(config.Gateways) != 0 {
		t.Errorf("Gateways should be empty, got %d items", len(config.Gateways))
	}

	// Check that Interfaces map is initialized and empty
	if config.Interfaces.Items == nil {
		t.Error("Interfaces.Items should be initialized")
	}
	if len(config.Interfaces.Items) != 0 {
		t.Errorf("Interfaces.Items should be empty, got %d items", len(config.Interfaces.Items))
	}
}

func TestNewVLANs(t *testing.T) {
	t.Parallel()

	vlans := NewVLANs()

	if vlans == nil {
		t.Fatal("NewVLANs() returned nil")
	}

	// Check that VLAN slice is initialized and empty
	if vlans.VLAN == nil {
		t.Error("VLAN slice should be initialized")
	}
	if len(vlans.VLAN) != 0 {
		t.Errorf("VLAN slice should be empty, got %d items", len(vlans.VLAN))
	}
}

func TestNewBridges(t *testing.T) {
	t.Parallel()

	bridges := NewBridges()

	if bridges == nil {
		t.Fatal("NewBridges() returned nil")
	}

	// Check that Bridge slice is initialized and empty
	if bridges.Bridge == nil {
		t.Error("Bridge slice should be initialized")
	}
	if len(bridges.Bridge) != 0 {
		t.Errorf("Bridge slice should be empty, got %d items", len(bridges.Bridge))
	}
}

func TestNewGateways(t *testing.T) {
	t.Parallel()

	gateways := NewGateways()

	if gateways == nil {
		t.Fatal("NewGateways() returned nil")
	}

	// Check that Gateway slice is initialized and empty
	if gateways.Gateway == nil {
		t.Error("Gateway slice should be initialized")
	}
	if len(gateways.Gateway) != 0 {
		t.Errorf("Gateway slice should be empty, got %d items", len(gateways.Gateway))
	}

	// Check that Groups slice is initialized and empty
	if gateways.Groups == nil {
		t.Error("Groups slice should be initialized")
	}
	if len(gateways.Groups) != 0 {
		t.Errorf("Groups slice should be empty, got %d items", len(gateways.Groups))
	}
}

func TestNewGatewayGroup(t *testing.T) {
	t.Parallel()

	group := NewGatewayGroup()

	// Check that Item slice is initialized and empty
	if group.Item == nil {
		t.Error("Item slice should be initialized")
	}
	if len(group.Item) != 0 {
		t.Errorf("Item slice should be empty, got %d items", len(group.Item))
	}

	// Other fields should be zero values
	if group.Name != "" {
		t.Errorf("Name should be empty, got %q", group.Name)
	}
	if group.Trigger != "" {
		t.Errorf("Trigger should be empty, got %q", group.Trigger)
	}
	if group.Descr != "" {
		t.Errorf("Descr should be empty, got %q", group.Descr)
	}
}

func TestNewStaticRoutes(t *testing.T) {
	t.Parallel()

	routes := NewStaticRoutes()

	if routes == nil {
		t.Fatal("NewStaticRoutes() returned nil")
	}

	// Check that Route slice is initialized and empty
	if routes.Route == nil {
		t.Error("Route slice should be initialized")
	}
	if len(routes.Route) != 0 {
		t.Errorf("Route slice should be empty, got %d items", len(routes.Route))
	}
}

// Package Constructor Tests

func TestNewPackage(t *testing.T) {
	t.Parallel()

	pkg := NewPackage()

	// Check default values
	if pkg.Installed {
		t.Error("Installed should be false by default")
	}
	if pkg.Locked {
		t.Error("Locked should be false by default")
	}
	if pkg.Automatic {
		t.Error("Automatic should be false by default")
	}

	// Other fields should be zero values
	if pkg.Name != "" {
		t.Errorf("Name should be empty, got %q", pkg.Name)
	}
	if pkg.Version != "" {
		t.Errorf("Version should be empty, got %q", pkg.Version)
	}
	if pkg.Descr != "" {
		t.Errorf("Descr should be empty, got %q", pkg.Descr)
	}
}

func TestNewService(t *testing.T) {
	t.Parallel()

	service := NewService()

	// Check default values
	if service.Status != "stopped" {
		t.Errorf("Status should be 'stopped' by default, got %q", service.Status)
	}
	if service.Enabled {
		t.Error("Enabled should be false by default")
	}
	if service.PID != 0 {
		t.Errorf("PID should be 0 by default, got %d", service.PID)
	}

	// Other fields should be zero values
	if service.Name != "" {
		t.Errorf("Name should be empty, got %q", service.Name)
	}
	if service.Description != "" {
		t.Errorf("Description should be empty, got %q", service.Description)
	}
}

// System Constructor Tests

func TestNewSystemConfig(t *testing.T) {
	t.Parallel()

	config := NewSystemConfig()

	// Check that Sysctl slice is initialized and empty
	if config.Sysctl == nil {
		t.Error("Sysctl slice should be initialized")
	}
	if len(config.Sysctl) != 0 {
		t.Errorf("Sysctl slice should be empty, got %d items", len(config.Sysctl))
	}
}

func TestNewUser(t *testing.T) {
	t.Parallel()

	user := NewUser()

	// Check that APIKeys slice is initialized and empty
	if user.APIKeys == nil {
		t.Error("APIKeys slice should be initialized")
	}
	if len(user.APIKeys) != 0 {
		t.Errorf("APIKeys slice should be empty, got %d items", len(user.APIKeys))
	}

	// Other fields should be zero values
	if user.Name != "" {
		t.Errorf("Name should be empty, got %q", user.Name)
	}
	if user.Descr != "" {
		t.Errorf("Descr should be empty, got %q", user.Descr)
	}
	if user.Password != "" {
		t.Errorf("Password should be empty, got %q", user.Password)
	}
}

// VPN Constructor Tests

func TestNewOpenVPN(t *testing.T) {
	t.Parallel()

	ovpn := NewOpenVPN()

	if ovpn == nil {
		t.Fatal("NewOpenVPN() returned nil")
	}

	// Check that Servers slice is initialized and empty
	if ovpn.Servers == nil {
		t.Error("Servers slice should be initialized")
	}
	if len(ovpn.Servers) != 0 {
		t.Errorf("Servers slice should be empty, got %d items", len(ovpn.Servers))
	}

	// Check that Clients slice is initialized and empty
	if ovpn.Clients == nil {
		t.Error("Clients slice should be initialized")
	}
	if len(ovpn.Clients) != 0 {
		t.Errorf("Clients slice should be empty, got %d items", len(ovpn.Clients))
	}

	// Check that CSC slice is initialized and empty
	if ovpn.CSC == nil {
		t.Error("CSC slice should be initialized")
	}
	if len(ovpn.CSC) != 0 {
		t.Errorf("CSC slice should be empty, got %d items", len(ovpn.CSC))
	}
}

func TestNewClientExport(t *testing.T) {
	t.Parallel()

	export := NewClientExport()

	if export == nil {
		t.Fatal("NewClientExport() returned nil")
	}

	// Check that Server_list slice is initialized and empty
	if export.Server_list == nil {
		t.Error("Server_list slice should be initialized")
	}
	if len(export.Server_list) != 0 {
		t.Errorf("Server_list slice should be empty, got %d items", len(export.Server_list))
	}
}

func TestNewOpenVPNExport(t *testing.T) {
	t.Parallel()

	export := NewOpenVPNExport()

	if export == nil {
		t.Fatal("NewOpenVPNExport() returned nil")
	}

	// NewOpenVPNExport returns an empty struct, so verify it's not nil
	// and has expected zero values (no specific initialization)
}

func TestNewOpenVPNSystem(t *testing.T) {
	t.Parallel()

	system := NewOpenVPNSystem()

	if system == nil {
		t.Fatal("NewOpenVPNSystem() returned nil")
	}

	// NewOpenVPNSystem returns an empty struct, so verify it's not nil
	// and has expected zero values (no specific initialization)
}

func TestNewWireGuard(t *testing.T) {
	t.Parallel()

	wg := NewWireGuard()

	if wg == nil {
		t.Fatal("NewWireGuard() returned nil")
	}

	// NewWireGuard returns an empty struct, so verify it's not nil
	// and has expected zero values (no specific initialization)
}

// Service Constructor Tests

func TestNewDNSMasq(t *testing.T) {
	t.Parallel()

	dnsmasq := NewDNSMasq()

	if dnsmasq == nil {
		t.Fatal("NewDNSMasq() returned nil")
	}

	// Check that Forwarders slice is initialized and empty
	if dnsmasq.Forwarders == nil {
		t.Error("Forwarders slice should be initialized")
	}
	if len(dnsmasq.Forwarders) != 0 {
		t.Errorf("Forwarders slice should be empty, got %d items", len(dnsmasq.Forwarders))
	}

	// Check that Hosts slice is initialized and empty
	if dnsmasq.Hosts == nil {
		t.Error("Hosts slice should be initialized")
	}
	if len(dnsmasq.Hosts) != 0 {
		t.Errorf("Hosts slice should be empty, got %d items", len(dnsmasq.Hosts))
	}

	// Check that DomainOverrides slice is initialized and empty
	if dnsmasq.DomainOverrides == nil {
		t.Error("DomainOverrides slice should be initialized")
	}
	if len(dnsmasq.DomainOverrides) != 0 {
		t.Errorf("DomainOverrides slice should be empty, got %d items", len(dnsmasq.DomainOverrides))
	}
}

func TestNewDNSMasqHost(t *testing.T) {
	t.Parallel()

	host := NewDNSMasqHost()

	// Check that Aliases slice is initialized and empty
	if host.Aliases == nil {
		t.Error("Aliases slice should be initialized")
	}
	if len(host.Aliases) != 0 {
		t.Errorf("Aliases slice should be empty, got %d items", len(host.Aliases))
	}

	// Other fields should be zero values
	if host.Host != "" {
		t.Errorf("Host should be empty, got %q", host.Host)
	}
	if host.Domain != "" {
		t.Errorf("Domain should be empty, got %q", host.Domain)
	}
	if host.IP != "" {
		t.Errorf("IP should be empty, got %q", host.IP)
	}
}

func TestNewSyslog(t *testing.T) {
	t.Parallel()

	syslog := NewSyslog()

	if syslog == nil {
		t.Fatal("NewSyslog() returned nil")
	}

	// Check that Reverse slice is initialized and empty
	if syslog.Reverse == nil {
		t.Error("Reverse slice should be initialized")
	}
	if len(syslog.Reverse) != 0 {
		t.Errorf("Reverse slice should be empty, got %d items", len(syslog.Reverse))
	}
}

func TestNewMonit(t *testing.T) {
	t.Parallel()

	monit := NewMonit()

	if monit == nil {
		t.Fatal("NewMonit() returned nil")
	}

	// Check that Service slice is initialized and empty
	if monit.Service == nil {
		t.Error("Service slice should be initialized")
	}
	if len(monit.Service) != 0 {
		t.Errorf("Service slice should be empty, got %d items", len(monit.Service))
	}

	// Check that Test slice is initialized and empty
	if monit.Test == nil {
		t.Error("Test slice should be initialized")
	}
	if len(monit.Test) != 0 {
		t.Errorf("Test slice should be empty, got %d items", len(monit.Test))
	}
}

// Security Constructor Tests

func TestNewSecurityConfig(t *testing.T) {
	t.Parallel()

	config := NewSecurityConfig()

	// Check that Filter.Rule slice is initialized and empty
	if config.Filter.Rule == nil {
		t.Error("Filter.Rule slice should be initialized")
	}
	if len(config.Filter.Rule) != 0 {
		t.Errorf("Filter.Rule slice should be empty, got %d items", len(config.Filter.Rule))
	}

	// NewSecurityConfig only initializes Filter.Rule, not other fields
	// Nat.Outbound.Rule is not initialized by the constructor
}

func TestNewFirewall(t *testing.T) {
	t.Parallel()

	firewall := NewFirewall()

	if firewall == nil {
		t.Fatal("NewFirewall() returned nil")
	}

	// NewFirewall returns an empty struct, so verify it's not nil
	// and has expected zero values (no specific initialization)
}

func TestNewIPsec(t *testing.T) {
	t.Parallel()

	ipsec := NewIPsec()

	if ipsec == nil {
		t.Fatal("NewIPsec() returned nil")
	}

	// NewIPsec returns an empty struct, so verify it's not nil
	// and has expected zero values (no specific initialization)
}

func TestNewSwanctl(t *testing.T) {
	t.Parallel()

	swanctl := NewSwanctl()

	if swanctl == nil {
		t.Fatal("NewSwanctl() returned nil")
	}

	// NewSwanctl returns an empty struct, so verify it's not nil
	// and has expected zero values (no specific initialization)
}

func TestNewIDS(t *testing.T) {
	t.Parallel()

	ids := NewIDS()

	if ids == nil {
		t.Fatal("NewIDS() returned nil")
	}

	// NewIDS returns an empty struct, so verify it's not nil
	// and has expected zero values (these are strings, not slices)
	if ids.Rules != "" {
		t.Errorf("Rules should be empty, got %q", ids.Rules)
	}
	if ids.Policies != "" {
		t.Errorf("Policies should be empty, got %q", ids.Policies)
	}
	if ids.UserDefinedRules != "" {
		t.Errorf("UserDefinedRules should be empty, got %q", ids.UserDefinedRules)
	}
	if ids.Files != "" {
		t.Errorf("Files should be empty, got %q", ids.Files)
	}
	if ids.FileTags != "" {
		t.Errorf("FileTags should be empty, got %q", ids.FileTags)
	}
}
