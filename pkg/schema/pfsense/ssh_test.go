package pfsense

import (
	"encoding/xml"
	"strings"
	"testing"
)

// TestSystem_SSHSwitchRoundTrip pins the presence semantics of the pfSense SSH
// switch (standards.md "Adding New XML Fields" step 3). The page writes
// <ssh><enable>enabled</enable>, and sshd tests it with isset(), so an empty
// element and a false-looking body are kept as present. Configs older than
// version 18.9 keep the switch in <system><enablesshd>, tested the same way.
// <enabled> is the OPNsense spelling, which pfSense does not read, so it must
// not decode into the switch.
func TestSystem_SSHSwitchRoundTrip(t *testing.T) {
	t.Parallel()

	empty, enabled, zero := "", "enabled", "0"

	tests := []struct {
		name       string
		in         string
		enable     *string
		enableSSHD *string
	}{
		{name: "absent", in: "<system><ssh><group>admins</group></ssh></system>"},
		{name: "empty element", in: "<system><ssh><enable/></ssh></system>", enable: &empty},
		{name: "page value", in: "<system><ssh><enable>enabled</enable></ssh></system>", enable: &enabled},
		{name: "false-looking body", in: "<system><ssh><enable>0</enable></ssh></system>", enable: &zero},
		{name: "OPNsense spelling alone", in: "<system><ssh><enabled/><group>admins</group></ssh></system>"},
		{name: "legacy empty element", in: "<system><enablesshd/></system>", enableSSHD: &empty},
		{name: "legacy with a body", in: "<system><enablesshd>enabled</enablesshd></system>", enableSSHD: &enabled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var sys System
			if err := xml.Unmarshal([]byte(tt.in), &sys); err != nil {
				t.Fatal(err)
			}

			checkPresence(t, "decoded Enable", sys.SSH.Enable, tt.enable)
			checkPresence(t, "decoded EnableSSHD", sys.EnableSSHD, tt.enableSSHD)

			out, err := xml.Marshal(&sys)
			if err != nil {
				t.Fatal(err)
			}

			var again System
			if err := xml.Unmarshal(out, &again); err != nil {
				t.Fatal(err)
			}

			checkPresence(t, "round-tripped Enable", again.SSH.Enable, tt.enable)
			checkPresence(t, "round-tripped EnableSSHD", again.EnableSSHD, tt.enableSSHD)

			if tt.enable == nil && strings.Contains(string(out), "<enable>") {
				t.Errorf("absent <enable> written back: %s", out)
			}

			if tt.enableSSHD == nil && strings.Contains(string(out), "<enablesshd>") {
				t.Errorf("absent <enablesshd> written back: %s", out)
			}
		})
	}
}

// TestSSHConfig_PortAndGroupRoundTrip checks that forking SSHConfig kept the
// port and group pfSense writes beside the switch.
func TestSSHConfig_PortAndGroupRoundTrip(t *testing.T) {
	t.Parallel()

	in := "<ssh><enable>enabled</enable><port>2222</port><group>admins</group></ssh>"

	var cfg SSHConfig
	if err := xml.Unmarshal([]byte(in), &cfg); err != nil {
		t.Fatal(err)
	}

	out, err := xml.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	var again SSHConfig
	if err := xml.Unmarshal(out, &again); err != nil {
		t.Fatal(err)
	}

	if again.Port != "2222" || again.Group != "admins" || again.Enable == nil {
		t.Errorf("round trip lost a field: %s", out)
	}
}

// checkPresence fails unless got and want are both nil or hold the same body.
func checkPresence(t *testing.T, field string, got, want *string) {
	t.Helper()

	switch {
	case want == nil && got != nil:
		t.Errorf("%s = %q, want nil", field, *got)
	case want != nil && got == nil:
		t.Errorf("%s = nil, want %q", field, *want)
	case want != nil && *got != *want:
		t.Errorf("%s = %q, want %q", field, *got, *want)
	}
}
