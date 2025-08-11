package metrics

import "testing"

func TestCalculateTotalConfigItems(t *testing.T) {
	tests := []struct {
		name                     string
		totalInterfaces          int
		totalFirewallRules       int
		totalUsers               int
		totalGroups              int
		totalServices            int
		totalGateways            int
		totalGatewayGroups       int
		sysctlSettings           int
		dhcpScopes               int
		loadBalancerMonitors     int
		expectedTotalConfigItems int
	}{
		{
			name:                     "zero values",
			totalInterfaces:          0,
			totalFirewallRules:       0,
			totalUsers:               0,
			totalGroups:              0,
			totalServices:            0,
			totalGateways:            0,
			totalGatewayGroups:       0,
			sysctlSettings:           0,
			dhcpScopes:               0,
			loadBalancerMonitors:     0,
			expectedTotalConfigItems: 0,
		},
		{
			name:                     "all ones",
			totalInterfaces:          1,
			totalFirewallRules:       1,
			totalUsers:               1,
			totalGroups:              1,
			totalServices:            1,
			totalGateways:            1,
			totalGatewayGroups:       1,
			sysctlSettings:           1,
			dhcpScopes:               1,
			loadBalancerMonitors:     1,
			expectedTotalConfigItems: 10,
		},
		{
			name:                     "typical configuration",
			totalInterfaces:          2,
			totalFirewallRules:       15,
			totalUsers:               3,
			totalGroups:              2,
			totalServices:            5,
			totalGateways:            2,
			totalGatewayGroups:       1,
			sysctlSettings:           8,
			dhcpScopes:               2,
			loadBalancerMonitors:     0,
			expectedTotalConfigItems: 40,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateTotalConfigItems(
				tt.totalInterfaces,
				tt.totalFirewallRules,
				tt.totalUsers,
				tt.totalGroups,
				tt.totalServices,
				tt.totalGateways,
				tt.totalGatewayGroups,
				tt.sysctlSettings,
				tt.dhcpScopes,
				tt.loadBalancerMonitors,
			)

			if result != tt.expectedTotalConfigItems {
				t.Errorf("CalculateTotalConfigItems() = %v, want %v", result, tt.expectedTotalConfigItems)
			}
		})
	}
}
