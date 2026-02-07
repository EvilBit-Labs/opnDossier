package constants

import (
	"testing"
	"time"
)

func TestVersionIsSet(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestAppNameConstant(t *testing.T) {
	if AppName != "opnDossier" {
		t.Errorf("AppName = %q, want %q", AppName, "opnDossier")
	}
}

func TestDefaultFormatConstant(t *testing.T) {
	if DefaultFormat != "markdown" {
		t.Errorf("DefaultFormat = %q, want %q", DefaultFormat, "markdown")
	}
}

func TestDefaultModeConstant(t *testing.T) {
	if DefaultMode != "standard" {
		t.Errorf("DefaultMode = %q, want %q", DefaultMode, "standard")
	}
}

func TestConfigFileNameConstant(t *testing.T) {
	if ConfigFileName != "opndossier.yaml" {
		t.Errorf("ConfigFileName = %q, want %q", ConfigFileName, "opndossier.yaml")
	}
}

func TestNetworkConstant(t *testing.T) {
	if NetworkAny != "any" {
		t.Errorf("NetworkAny = %q, want %q", NetworkAny, "any")
	}
}

func TestProtocolConstant(t *testing.T) {
	if ProtocolHTTPS != "https" {
		t.Errorf("ProtocolHTTPS = %q, want %q", ProtocolHTTPS, "https")
	}
}

func TestRuleTypeConstant(t *testing.T) {
	if RuleTypePass != "pass" {
		t.Errorf("RuleTypePass = %q, want %q", RuleTypePass, "pass")
	}
}

func TestFindingTypeConstant(t *testing.T) {
	if FindingTypeSecurity != "security" {
		t.Errorf("FindingTypeSecurity = %q, want %q", FindingTypeSecurity, "security")
	}
}

func TestThemeConstants(t *testing.T) {
	tests := []struct {
		name     string
		got      string
		expected string
	}{
		{"ThemeLight", ThemeLight, "light"},
		{"ThemeDark", ThemeDark, "dark"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestStatusDisplayConstants(t *testing.T) {
	if StatusNotEnabled == "" {
		t.Error("StatusNotEnabled should not be empty")
	}
	if StatusEnabled == "" {
		t.Error("StatusEnabled should not be empty")
	}
}

func TestNoConfigAvailableConstant(t *testing.T) {
	if NoConfigAvailable != "*No configuration available*" {
		t.Errorf("NoConfigAvailable = %q, want %q", NoConfigAvailable, "*No configuration available*")
	}
}

func TestProgressRenderingMarkdownConstant(t *testing.T) {
	if ProgressRenderingMarkdown != 0.5 {
		t.Errorf("ProgressRenderingMarkdown = %v, want %v", ProgressRenderingMarkdown, 0.5)
	}
}

func TestConfigThresholdConstant(t *testing.T) {
	if ConfigThreshold != 0.3 {
		t.Errorf("ConfigThreshold = %v, want %v", ConfigThreshold, 0.3)
	}
}

func TestTimeoutConstants(t *testing.T) {
	if DefaultProcessingTimeout != 5*time.Minute {
		t.Errorf("DefaultProcessingTimeout = %v, want %v", DefaultProcessingTimeout, 5*time.Minute)
	}
	if QuickProcessingTimeout != 10*time.Second {
		t.Errorf("QuickProcessingTimeout = %v, want %v", QuickProcessingTimeout, 10*time.Second)
	}
}

func TestScoringConstants(t *testing.T) {
	tests := []struct {
		name     string
		got      int
		expected int
	}{
		{"SecurityFeatureMultiplier", SecurityFeatureMultiplier, 10},
		{"MaxSecurityScore", MaxSecurityScore, 100},
		{"MaxComplexityScore", MaxComplexityScore, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestComplexityWeightConstants(t *testing.T) {
	tests := []struct {
		name     string
		got      int
		expected int
	}{
		{"InterfaceComplexityWeight", InterfaceComplexityWeight, 5},
		{"FirewallRuleComplexityWeight", FirewallRuleComplexityWeight, 2},
		{"UserComplexityWeight", UserComplexityWeight, 3},
		{"GroupComplexityWeight", GroupComplexityWeight, 3},
		{"SysctlComplexityWeight", SysctlComplexityWeight, 4},
		{"ServiceComplexityWeight", ServiceComplexityWeight, 6},
		{"DHCPComplexityWeight", DHCPComplexityWeight, 4},
		{"LoadBalancerComplexityWeight", LoadBalancerComplexityWeight, 8},
		{"GatewayComplexityWeight", GatewayComplexityWeight, 3},
		{"GatewayGroupComplexityWeight", GatewayGroupComplexityWeight, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestThresholdConstants(t *testing.T) {
	if LargeRuleCountThreshold != 100 {
		t.Errorf("LargeRuleCountThreshold = %d, want %d", LargeRuleCountThreshold, 100)
	}
	if MaxReasonableComplexity != 1000 {
		t.Errorf("MaxReasonableComplexity = %d, want %d", MaxReasonableComplexity, 1000)
	}
}

func TestComplexityWeightsArePositive(t *testing.T) {
	weights := []struct {
		name  string
		value int
	}{
		{"InterfaceComplexityWeight", InterfaceComplexityWeight},
		{"FirewallRuleComplexityWeight", FirewallRuleComplexityWeight},
		{"UserComplexityWeight", UserComplexityWeight},
		{"GroupComplexityWeight", GroupComplexityWeight},
		{"SysctlComplexityWeight", SysctlComplexityWeight},
		{"ServiceComplexityWeight", ServiceComplexityWeight},
		{"DHCPComplexityWeight", DHCPComplexityWeight},
		{"LoadBalancerComplexityWeight", LoadBalancerComplexityWeight},
		{"GatewayComplexityWeight", GatewayComplexityWeight},
		{"GatewayGroupComplexityWeight", GatewayGroupComplexityWeight},
	}

	for _, w := range weights {
		t.Run(w.name, func(t *testing.T) {
			if w.value <= 0 {
				t.Errorf("%s should be positive, got %d", w.name, w.value)
			}
		})
	}
}
