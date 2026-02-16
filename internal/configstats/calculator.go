// Package configstats provides shared calculation functions for configuration statistics.
package configstats

// CalculateTotalConfigItems calculates the total number of configuration items
// by summing all relevant components including interfaces, firewall rules, users,
// groups, services, gateways, gateway groups, sysctl settings, DHCP scopes,
// and load balancer monitors. This ensures consistency across different packages.
func CalculateTotalConfigItems(
	totalInterfaces int,
	totalFirewallRules int,
	totalUsers int,
	totalGroups int,
	totalServices int,
	totalGateways int,
	totalGatewayGroups int,
	sysctlSettings int,
	dhcpScopes int,
	loadBalancerMonitors int,
) int {
	return totalInterfaces + totalFirewallRules + totalUsers + totalGroups +
		totalServices + totalGateways + totalGatewayGroups + sysctlSettings +
		dhcpScopes + loadBalancerMonitors
}
