package sanitizer

import (
	"testing"
)

func TestIsIPv4(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"255.255.255.255", true},
		{"0.0.0.0", true},
		{"172.16.0.1", true},
		{"256.1.1.1", false},
		{"192.168.1", false},
		{"not-an-ip", false},
		{"", false},
		{"::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsIPv4(tt.input); got != tt.want {
				t.Errorf("IsIPv4(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsIP(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.1.1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"fe80::1", true},
		{"not-an-ip", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsIP(tt.input); got != tt.want {
				t.Errorf("IsIP(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		// RFC 1918 private ranges
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		// Public IPs
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.1", false},
		// Edge cases
		{"172.15.0.1", false}, // Just below 172.16
		{"172.32.0.1", false}, // Just above 172.31
		{"not-an-ip", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsPrivateIP(tt.input); got != tt.want {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		// Public IPs
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"203.0.113.1", true},
		// Private IPs
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		// Loopback
		{"127.0.0.1", false},
		// Link-local
		{"169.254.1.1", false},
		// Invalid
		{"not-an-ip", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsPublicIP(tt.input); got != tt.want {
				t.Errorf("IsPublicIP(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsMAC(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"00:11:22:33:44:55", true},
		{"AA:BB:CC:DD:EE:FF", true},
		{"aa:bb:cc:dd:ee:ff", true},
		{"00-11-22-33-44-55", true},
		{"001122334455", false},
		{"00:11:22:33:44", false},
		{"not-a-mac", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsMAC(tt.input); got != tt.want {
				t.Errorf("IsMAC(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsEmail(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"user@example.com", true},
		{"user.name@example.co.uk", true},
		{"user+tag@example.com", true},
		{"not-an-email", false},
		{"@example.com", false},
		{"user@", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsEmail(tt.input); got != tt.want {
				t.Errorf("IsEmail(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsHostname(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"host-01.domain.local", true},
		{"192.168.1.1", false}, // IP, not hostname
		{"localhost", false},   // No dot
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsHostname(tt.input); got != tt.want {
				t.Errorf("IsHostname(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsBase64(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid base64", "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IHN0cmluZyB0aGF0IGlzIGxvbmcgZW5vdWdo", true},
		{"too short", "SGVsbG8=", false},
		{"not base64", "This is not base64 encoded text at all", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsBase64(tt.input); got != tt.want {
				t.Errorf("IsBase64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPEM(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			"valid certificate",
			"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHBfpE=\n-----END CERTIFICATE-----",
			true,
		},
		{
			"valid private key",
			"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg=\n-----END PRIVATE KEY-----",
			true,
		},
		{"not PEM", "This is not PEM encoded", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPEM(tt.input); got != tt.want {
				t.Errorf("IsPEM() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLooksLikePassword(t *testing.T) {
	tests := []struct {
		fieldName string
		want      bool
	}{
		{"password", true},
		{"Password", true},
		{"userPassword", true},
		{"secret", true},
		{"secretKey", true},
		{"apiToken", true},
		{"authKey", true},
		{"privateKey", true},
		{"username", false},
		{"hostname", false},
		{"description", false},
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			if got := LooksLikePassword(tt.fieldName); got != tt.want {
				t.Errorf("LooksLikePassword(%q) = %v, want %v", tt.fieldName, got, tt.want)
			}
		})
	}
}

func TestLooksLikeAPIKey(t *testing.T) {
	tests := []struct {
		fieldName string
		want      bool
	}{
		{"apikey", true},
		{"api_key", true},
		{"api-key", true},
		{"accesskey", true},
		{"secretkey", true},
		{"username", false},
		{"password", false},
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			if got := LooksLikeAPIKey(tt.fieldName); got != tt.want {
				t.Errorf("LooksLikeAPIKey(%q) = %v, want %v", tt.fieldName, got, tt.want)
			}
		})
	}
}

func TestLooksLikePSK(t *testing.T) {
	tests := []struct {
		fieldName string
		want      bool
	}{
		{"psk", true},
		{"ipsecpsk", true},
		{"presharedkey", true},
		{"pre-shared-key", true},
		{"password", false},
		{"key", false},
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			if got := LooksLikePSK(tt.fieldName); got != tt.want {
				t.Errorf("LooksLikePSK(%q) = %v, want %v", tt.fieldName, got, tt.want)
			}
		})
	}
}

func TestLooksLikeSNMPCommunity(t *testing.T) {
	tests := []struct {
		fieldName string
		want      bool
	}{
		{"community", true},
		{"rocommunity", true},
		{"snmpcommunity", true},
		{"password", false},
		{"secret", false},
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			if got := LooksLikeSNMPCommunity(tt.fieldName); got != tt.want {
				t.Errorf("LooksLikeSNMPCommunity(%q) = %v, want %v", tt.fieldName, got, tt.want)
			}
		})
	}
}

func TestExtractIPv4Addresses(t *testing.T) {
	input := "Server at 192.168.1.1 connects to 10.0.0.1 and 8.8.8.8"
	got := ExtractIPv4Addresses(input)
	want := []string{"192.168.1.1", "10.0.0.1", "8.8.8.8"}

	if len(got) != len(want) {
		t.Errorf("ExtractIPv4Addresses() returned %d IPs, want %d", len(got), len(want))
		return
	}

	for i, ip := range got {
		if ip != want[i] {
			t.Errorf("ExtractIPv4Addresses()[%d] = %q, want %q", i, ip, want[i])
		}
	}
}

func TestExtractEmails(t *testing.T) {
	input := "Contact admin@example.com or support@test.org for help"
	got := ExtractEmails(input)
	want := []string{"admin@example.com", "support@test.org"}

	if len(got) != len(want) {
		t.Errorf("ExtractEmails() returned %d emails, want %d", len(got), len(want))
		return
	}

	for i, email := range got {
		if email != want[i] {
			t.Errorf("ExtractEmails()[%d] = %q, want %q", i, email, want[i])
		}
	}
}
