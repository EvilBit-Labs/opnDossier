package analyzers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizer_NormalizeIP(t *testing.T) {
	t.Parallel()
	n := NewNormalizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard IPv4", "192.168.1.1", "192.168.1.1"},
		{"leading zeros", "192.168.001.001", "192.168.1.1"},
		{"all zeros", "000.000.000.000", "0.0.0.0"},
		{"CIDR notation", "192.168.1.0/24", "192.168.1.0/24"},
		{"CIDR with leading zeros", "010.000.000.000/8", "10.0.0.0/8"},
		{"IPv6 loopback", "::1", "::1"},
		{"full IPv6", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"IPv6 CIDR", "2001:db8::/32", "2001:db8::/32"},
		{"invalid CIDR prefix", "192.168.1.1/33", "192.168.1.1/33"},
		{"invalid stays unchanged", "not-an-ip", "not-an-ip"},
		{"empty stays empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, n.NormalizeIP(tt.input))
		})
	}
}

func TestNormalizer_NormalizeWhitespace(t *testing.T) {
	n := NewNormalizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no change needed", "hello world", "hello world"},
		{"multiple spaces", "hello   world", "hello world"},
		{"leading trailing", "  hello  ", "hello"},
		{"tabs and newlines", "hello\t\nworld", "hello world"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, n.NormalizeWhitespace(tt.input))
		})
	}
}

func TestNormalizer_NormalizePort(t *testing.T) {
	n := NewNormalizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard port", "80", "80"},
		{"leading zeros", "0080", "80"},
		{"port range dash", "80-443", "80-443"},
		{"port range colon", "80:443", "80:443"},
		{"leading zeros in range", "0080-0443", "80-443"},
		{"zero", "0", "0"},
		{"empty", "", ""},
		{"non-port text unchanged", "Label: Value", "Label: Value"},
		{"text with dash unchanged", "some-text", "some-text"},
		{"description unchanged", "Allow SSH access", "Allow SSH access"},
		{"mixed digits text unchanged", "rule 001", "rule 001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, n.NormalizePort(tt.input))
		})
	}
}

func TestNormalizer_NormalizeProtocol(t *testing.T) {
	n := NewNormalizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"lowercase", "tcp", "tcp"},
		{"uppercase", "TCP", "tcp"},
		{"mixed case", "Tcp", "tcp"},
		{"with spaces", " tcp ", "tcp"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, n.NormalizeProtocol(tt.input))
		})
	}
}

func TestNormalizer_NormalizePath(t *testing.T) {
	n := NewNormalizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no change", "/etc/config", "/etc/config"},
		{"trailing slash", "/etc/config/", "/etc/config"},
		{"double slashes", "/etc//config", "/etc/config"},
		{"multiple trailing", "/etc/config///", "/etc/config"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, n.NormalizePath(tt.input))
		})
	}
}
