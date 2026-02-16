package schema

import (
	"testing"
)

func TestNewOpnSenseDocument(t *testing.T) {
	doc := NewOpnSenseDocument()

	if doc == nil {
		t.Fatal("NewOpnSenseDocument returned nil")
	}

	// Verify slices are initialized (not nil)
	if doc.Sysctl == nil {
		t.Error("Sysctl slice should be initialized")
	}
	if doc.Filter.Rule == nil {
		t.Error("Filter.Rule slice should be initialized")
	}
	if doc.LoadBalancer.MonitorType == nil {
		t.Error("LoadBalancer.MonitorType slice should be initialized")
	}
	if doc.System.Group == nil {
		t.Error("System.Group slice should be initialized")
	}
	if doc.System.User == nil {
		t.Error("System.User slice should be initialized")
	}

	// Verify maps are initialized (not nil)
	if doc.Interfaces.Items == nil {
		t.Error("Interfaces.Items map should be initialized")
	}
	if doc.Dhcpd.Items == nil {
		t.Error("Dhcpd.Items map should be initialized")
	}
}

func TestNewOpnSenseDocument_SlicesAreEmpty(t *testing.T) {
	doc := NewOpnSenseDocument()

	if len(doc.Sysctl) != 0 {
		t.Errorf("Sysctl should be empty, got %d elements", len(doc.Sysctl))
	}
	if len(doc.Filter.Rule) != 0 {
		t.Errorf("Filter.Rule should be empty, got %d elements", len(doc.Filter.Rule))
	}
	if len(doc.LoadBalancer.MonitorType) != 0 {
		t.Errorf("LoadBalancer.MonitorType should be empty, got %d elements", len(doc.LoadBalancer.MonitorType))
	}
	if len(doc.System.Group) != 0 {
		t.Errorf("System.Group should be empty, got %d elements", len(doc.System.Group))
	}
	if len(doc.System.User) != 0 {
		t.Errorf("System.User should be empty, got %d elements", len(doc.System.User))
	}
}

func TestNewOpnSenseDocument_MapsAreEmpty(t *testing.T) {
	doc := NewOpnSenseDocument()

	if len(doc.Interfaces.Items) != 0 {
		t.Errorf("Interfaces.Items should be empty, got %d elements", len(doc.Interfaces.Items))
	}
	if len(doc.Dhcpd.Items) != 0 {
		t.Errorf("Dhcpd.Items should be empty, got %d elements", len(doc.Dhcpd.Items))
	}
}

func TestOpnSenseDocument_Hostname(t *testing.T) {
	doc := NewOpnSenseDocument()

	// Empty hostname initially
	if doc.Hostname() != "" {
		t.Errorf("Hostname should be empty initially, got %q", doc.Hostname())
	}

	// Set hostname
	doc.System.Hostname = "firewall.example.com"
	if doc.Hostname() != "firewall.example.com" {
		t.Errorf("Hostname = %q, want %q", doc.Hostname(), "firewall.example.com")
	}
}

func TestOpnSenseDocument_InterfaceByName(t *testing.T) {
	doc := NewOpnSenseDocument()

	// No interface found initially
	iface := doc.InterfaceByName("em0")
	if iface != nil {
		t.Error("InterfaceByName should return nil for non-existent interface")
	}

	// Add an interface
	doc.Interfaces.Items["wan"] = Interface{
		If:     "em0",
		Enable: "1",
		Descr:  "WAN Interface",
	}

	// Find interface by name
	iface = doc.InterfaceByName("em0")
	if iface == nil {
		t.Fatal("InterfaceByName should find em0 interface")
	}
	if iface.If != "em0" {
		t.Errorf("Interface.If = %q, want %q", iface.If, "em0")
	}
	if iface.Descr != "WAN Interface" {
		t.Errorf("Interface.Descr = %q, want %q", iface.Descr, "WAN Interface")
	}
}

func TestOpnSenseDocument_InterfaceByName_MultipleInterfaces(t *testing.T) {
	doc := NewOpnSenseDocument()

	doc.Interfaces.Items["wan"] = Interface{If: "em0", Descr: "WAN"}
	doc.Interfaces.Items["lan"] = Interface{If: "em1", Descr: "LAN"}
	doc.Interfaces.Items["opt1"] = Interface{If: "em2", Descr: "OPT1"}

	tests := []struct {
		name     string
		ifName   string
		wantDesc string
	}{
		{"WAN", "em0", "WAN"},
		{"LAN", "em1", "LAN"},
		{"OPT1", "em2", "OPT1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface := doc.InterfaceByName(tt.ifName)
			if iface == nil {
				t.Fatalf("InterfaceByName(%q) returned nil", tt.ifName)
			}
			if iface.Descr != tt.wantDesc {
				t.Errorf("Interface.Descr = %q, want %q", iface.Descr, tt.wantDesc)
			}
		})
	}
}

func TestOpnSenseDocument_FilterRules(t *testing.T) {
	doc := NewOpnSenseDocument()

	// Empty rules initially
	rules := doc.FilterRules()
	if len(rules) != 0 {
		t.Errorf("FilterRules should be empty initially, got %d rules", len(rules))
	}

	// Add some rules
	doc.Filter.Rule = []Rule{
		{Type: "pass", Interface: InterfaceList{"wan"}, Source: Source{Any: new("any")}},
		{Type: "block", Interface: InterfaceList{"lan"}, Destination: Destination{Any: new("any")}},
	}

	rules = doc.FilterRules()
	if len(rules) != 2 {
		t.Errorf("FilterRules should return 2 rules, got %d", len(rules))
	}
}

func TestOpnSenseDocument_SystemConfig(t *testing.T) {
	doc := NewOpnSenseDocument()

	doc.System.Hostname = "test-firewall"
	doc.System.Domain = "example.com"
	doc.Sysctl = []SysctlItem{
		{Tunable: "net.inet.tcp.recvbuf_auto", Value: "1"},
	}

	sysConfig := doc.SystemConfig()

	if sysConfig.System.Hostname != "test-firewall" {
		t.Errorf("SystemConfig.System.Hostname = %q, want %q", sysConfig.System.Hostname, "test-firewall")
	}
	if sysConfig.System.Domain != "example.com" {
		t.Errorf("SystemConfig.System.Domain = %q, want %q", sysConfig.System.Domain, "example.com")
	}
	if len(sysConfig.Sysctl) != 1 {
		t.Errorf("SystemConfig.Sysctl should have 1 item, got %d", len(sysConfig.Sysctl))
	}
}

func TestOpnSenseDocument_NetworkConfig(t *testing.T) {
	doc := NewOpnSenseDocument()

	doc.Interfaces.Items["wan"] = Interface{If: "em0", Enable: "1"}

	netConfig := doc.NetworkConfig()

	if len(netConfig.Interfaces.Items) != 1 {
		t.Errorf("NetworkConfig.Interfaces.Items should have 1 item, got %d", len(netConfig.Interfaces.Items))
	}
	if _, ok := netConfig.Interfaces.Items["wan"]; !ok {
		t.Error("NetworkConfig.Interfaces.Items should contain 'wan'")
	}
}

func TestOpnSenseDocument_SecurityConfig(t *testing.T) {
	doc := NewOpnSenseDocument()

	doc.Nat.Outbound.Mode = "automatic"
	doc.Filter.Rule = []Rule{
		{Type: "pass", Interface: InterfaceList{"wan"}},
	}

	secConfig := doc.SecurityConfig()

	if secConfig.Nat.Outbound.Mode != "automatic" {
		t.Errorf("SecurityConfig.Nat.Outbound.Mode = %q, want %q", secConfig.Nat.Outbound.Mode, "automatic")
	}
	if len(secConfig.Filter.Rule) != 1 {
		t.Errorf("SecurityConfig.Filter.Rule should have 1 rule, got %d", len(secConfig.Filter.Rule))
	}
}

func TestOpnSenseDocument_ServiceConfig(t *testing.T) {
	doc := NewOpnSenseDocument()

	doc.Unbound.Enable = "1"
	doc.Snmpd.SysLocation = "Test Location"
	doc.Ntpd.Prefer = "pool.ntp.org"

	svcConfig := doc.ServiceConfig()

	if svcConfig.Unbound.Enable != "1" {
		t.Errorf("ServiceConfig.Unbound.Enable = %q, want %q", svcConfig.Unbound.Enable, "1")
	}
	if svcConfig.Snmpd.SysLocation != "Test Location" {
		t.Errorf("ServiceConfig.Snmpd.SysLocation = %q, want %q", svcConfig.Snmpd.SysLocation, "Test Location")
	}
	if svcConfig.Ntpd.Prefer != "pool.ntp.org" {
		t.Errorf("ServiceConfig.Ntpd.Prefer = %q, want %q", svcConfig.Ntpd.Prefer, "pool.ntp.org")
	}
}

func TestOpnSenseDocument_NATSummary(t *testing.T) {
	doc := NewOpnSenseDocument()

	// Default values
	summary := doc.NATSummary()
	if summary.Mode != "" {
		t.Errorf("NATSummary.Mode should be empty initially, got %q", summary.Mode)
	}
	if summary.ReflectionDisabled {
		t.Error("NATSummary.ReflectionDisabled should be false initially")
	}
	if summary.PfShareForward {
		t.Error("NATSummary.PfShareForward should be false initially")
	}
}

func TestOpnSenseDocument_NATSummary_WithValues(t *testing.T) {
	doc := NewOpnSenseDocument()

	doc.System.DisableNATReflection = "yes"
	doc.System.PfShareForward = 1
	doc.Nat.Outbound.Mode = "hybrid"
	doc.Nat.Outbound.Rule = []NATRule{
		{Source: Source{Network: "192.168.1.0/24"}},
	}

	summary := doc.NATSummary()

	if summary.Mode != "hybrid" {
		t.Errorf("NATSummary.Mode = %q, want %q", summary.Mode, "hybrid")
	}
	if !summary.ReflectionDisabled {
		t.Error("NATSummary.ReflectionDisabled should be true")
	}
	if !summary.PfShareForward {
		t.Error("NATSummary.PfShareForward should be true")
	}
	if len(summary.OutboundRules) != 1 {
		t.Errorf("NATSummary.OutboundRules should have 1 rule, got %d", len(summary.OutboundRules))
	}
}

func TestOpnSenseDocument_NATSummary_ReflectionNotDisabled(t *testing.T) {
	doc := NewOpnSenseDocument()

	doc.System.DisableNATReflection = "no"

	summary := doc.NATSummary()

	if summary.ReflectionDisabled {
		t.Error("NATSummary.ReflectionDisabled should be false when set to 'no'")
	}
}

func TestOpnSenseDocument_NATSummary_PfShareForwardZero(t *testing.T) {
	doc := NewOpnSenseDocument()

	doc.System.PfShareForward = 0

	summary := doc.NATSummary()

	if summary.PfShareForward {
		t.Error("NATSummary.PfShareForward should be false when set to 0")
	}
}

func TestInterfaceList_String(t *testing.T) {
	tests := []struct {
		name string
		il   InterfaceList
		want string
	}{
		{"empty", InterfaceList{}, ""},
		{"single", InterfaceList{"wan"}, "wan"},
		{"multiple", InterfaceList{"wan", "lan", "opt1"}, "wan,lan,opt1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.il.String(); got != tt.want {
				t.Errorf("InterfaceList.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInterfaceList_Contains(t *testing.T) {
	il := InterfaceList{"wan", "lan", "opt1"}

	if !il.Contains("wan") {
		t.Error("InterfaceList should contain 'wan'")
	}
	if !il.Contains("lan") {
		t.Error("InterfaceList should contain 'lan'")
	}
	if il.Contains("opt2") {
		t.Error("InterfaceList should not contain 'opt2'")
	}
}

func TestInterfaceList_IsEmpty(t *testing.T) {
	empty := InterfaceList{}
	nonEmpty := InterfaceList{"wan"}

	if !empty.IsEmpty() {
		t.Error("Empty InterfaceList should return true for IsEmpty()")
	}
	if nonEmpty.IsEmpty() {
		t.Error("Non-empty InterfaceList should return false for IsEmpty()")
	}
}

func TestInterfaces_Get(t *testing.T) {
	ifaces := Interfaces{
		Items: map[string]Interface{
			"wan": {If: "em0", Descr: "WAN"},
			"lan": {If: "em1", Descr: "LAN"},
		},
	}

	// Existing interface
	wan, ok := ifaces.Get("wan")
	if !ok {
		t.Error("Get('wan') should return ok=true")
	}
	if wan.If != "em0" {
		t.Errorf("wan.If = %q, want %q", wan.If, "em0")
	}

	// Non-existing interface
	_, ok = ifaces.Get("opt1")
	if ok {
		t.Error("Get('opt1') should return ok=false for non-existing interface")
	}
}

func TestInterfaces_Get_NilMap(t *testing.T) {
	ifaces := Interfaces{Items: nil}

	_, ok := ifaces.Get("wan")
	if ok {
		t.Error("Get() on nil map should return ok=false")
	}
}

func TestInterfaces_Names(t *testing.T) {
	ifaces := Interfaces{
		Items: map[string]Interface{
			"wan":  {If: "em0"},
			"lan":  {If: "em1"},
			"opt1": {If: "em2"},
		},
	}

	names := ifaces.Names()
	if len(names) != 3 {
		t.Errorf("Names() should return 3 names, got %d", len(names))
	}

	// Verify all expected names are present (order is not guaranteed)
	nameSet := make(map[string]bool)
	for _, name := range names {
		nameSet[name] = true
	}
	for _, expected := range []string{"wan", "lan", "opt1"} {
		if !nameSet[expected] {
			t.Errorf("Names() should contain %q", expected)
		}
	}
}

func TestInterfaces_Names_NilMap(t *testing.T) {
	ifaces := Interfaces{Items: nil}

	names := ifaces.Names()
	if len(names) != 0 {
		t.Errorf("Names() on nil map should return empty slice, got %d items", len(names))
	}
}

func TestInterfaces_Wan(t *testing.T) {
	ifaces := Interfaces{
		Items: map[string]Interface{
			"wan": {If: "em0", Descr: "WAN Interface"},
		},
	}

	wan, ok := ifaces.Wan()
	if !ok {
		t.Error("Wan() should return ok=true when wan exists")
	}
	if wan.Descr != "WAN Interface" {
		t.Errorf("wan.Descr = %q, want %q", wan.Descr, "WAN Interface")
	}
}

func TestInterfaces_Lan(t *testing.T) {
	ifaces := Interfaces{
		Items: map[string]Interface{
			"lan": {If: "em1", Descr: "LAN Interface"},
		},
	}

	lan, ok := ifaces.Lan()
	if !ok {
		t.Error("Lan() should return ok=true when lan exists")
	}
	if lan.Descr != "LAN Interface" {
		t.Errorf("lan.Descr = %q, want %q", lan.Descr, "LAN Interface")
	}
}
