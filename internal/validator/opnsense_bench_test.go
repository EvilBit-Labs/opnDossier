package validator

import (
	"fmt"
	"strconv"
	"testing"

	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

func BenchmarkValidateOpnSenseDocument(b *testing.B) {
	for _, ruleCount := range []int{100, 1_000, 10_000} {
		doc := benchmarkOpnSenseDocument(ruleCount)
		if errs := ValidateOpnSenseDocument(doc); len(errs) != 0 {
			b.Fatalf("benchmark fixture with %d rules produced validation errors: %v", ruleCount, errs)
		}

		b.Run(strconv.Itoa(ruleCount)+"Rules", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if errs := ValidateOpnSenseDocument(doc); len(errs) != 0 {
					b.Fatalf("ValidateOpnSenseDocument returned %d errors", len(errs))
				}
			}
		})
	}
}

func benchmarkOpnSenseDocument(ruleCount int) *schema.OpnSenseDocument {
	doc := schema.NewOpnSenseDocument()
	doc.System.Hostname = "bench-fw"
	doc.System.Domain = "benchmark.local"
	doc.System.Timezone = "Etc/UTC"
	doc.System.Optimization = "normal"
	doc.System.WebGUI.Protocol = "https"
	doc.System.Group = []schema.Group{
		{Name: "admins", Gid: "0", Scope: "system"},
		{Name: "operators", Gid: "1001", Scope: "local"},
	}
	doc.System.User = []schema.User{
		{Name: "root", UID: "0", Scope: "system", Groupname: "admins", Password: "x"},
		{Name: "operator", UID: "1001", Scope: "local", Groupname: "operators", Password: "x"},
	}

	doc.Interfaces.Items = map[string]schema.Interface{
		"wan": {IPAddr: "dhcp", Subnet: "24", MTU: "1500"},
		"lan": {IPAddr: "192.168.1.1", Subnet: "24", MTU: "1500"},
	}
	for i := range 8 {
		doc.Interfaces.Items[fmt.Sprintf("opt%d", i)] = schema.Interface{
			IPAddr: fmt.Sprintf("10.%d.0.1", i),
			Subnet: "24",
			MTU:    "1500",
		}
	}

	doc.Dhcpd.Items = map[string]schema.DhcpdInterface{
		"lan": {Range: schema.Range{From: "192.168.1.100", To: "192.168.1.200"}},
	}

	anyPresent := ""
	doc.Filter.Rule = make([]schema.Rule, 0, ruleCount)
	for i := range ruleCount {
		doc.Filter.Rule = append(doc.Filter.Rule, schema.Rule{
			Type:       []string{"pass", "block", "reject"}[i%3],
			IPProtocol: []string{"inet", "inet6"}[i%2],
			Protocol:   []string{"tcp", "udp"}[i%2],
			Interface:  schema.InterfaceList{fmt.Sprintf("opt%d", i%8)},
			Source: schema.Source{
				Network: fmt.Sprintf("10.%d.%d.0/24", (i/256)%256, i%256),
				Port:    "1024:65535",
			},
			Destination: schema.Destination{
				Any:  &anyPresent,
				Port: "443",
			},
			Direction: "in",
			StateType: "keep state",
			Descr:     fmt.Sprintf("benchmark validation rule %05d", i),
			UUID:      fmt.Sprintf("bench-rule-%05d", i),
		})
	}

	doc.Nat.Outbound.Mode = "hybrid"
	doc.Nat.Inbound = []schema.InboundRule{
		{NATReflection: "enable", Protocol: "tcp", InternalIP: "192.168.1.10", InternalPort: "443"},
	}
	doc.Sysctl = []schema.SysctlItem{
		{Tunable: "net.inet.ip.forwarding", Value: "1", Descr: "forwarding"},
	}

	return doc
}
