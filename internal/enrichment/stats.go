package enrichment

// ConfigItemCounts holds counts of each configuration item type for total calculation.
type ConfigItemCounts struct {
	Interfaces     int
	FirewallRules  int
	Users          int
	Groups         int
	Services       int
	Gateways       int
	GatewayGroups  int
	SysctlSettings int
	DHCPScopes     int
	LBMonitors     int
}

// CalculateTotalConfigItems calculates the total number of configuration items
// by summing all relevant components. This ensures consistency across different packages.
func CalculateTotalConfigItems(c ConfigItemCounts) int {
	return c.Interfaces + c.FirewallRules + c.Users + c.Groups +
		c.Services + c.Gateways + c.GatewayGroups + c.SysctlSettings +
		c.DHCPScopes + c.LBMonitors
}
