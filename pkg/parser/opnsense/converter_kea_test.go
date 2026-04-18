package opnsense_test

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_KeaDHCP4_Gotchas18_HappyPath locks in the canonical happy path:
// one subnet + one pool + one valid reservation → populated DHCPScope with the
// reservation attached as a static lease and zero warnings.
//
// This is the GOTCHAS §18 baseline: if future refactors break the
// subnet4/reservation element shape, pool parsing, or reservation→subnet UUID
// matching, this test is the first to fail.
func TestConverter_KeaDHCP4_Gotchas18_HappyPath(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.OPNsense.Kea.Dhcp4.General.Enabled = "1"
	doc.OPNsense.Kea.Dhcp4.Subnets = []schema.KeaSubnet{
		{
			UUID:        "subnet-happy",
			Subnet:      "192.168.10.0/24",
			Pools:       "192.168.10.100-192.168.10.150",
			Description: "Happy path subnet",
		},
	}
	doc.OPNsense.Kea.Dhcp4.Reservations = []schema.KeaReservation{
		{
			UUID:      "res-happy",
			Subnet:    "subnet-happy",
			IPAddress: "192.168.10.50",
			HWAddress: "aa:bb:cc:dd:ee:ff",
			Hostname:  "happy-host",
		},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings, "happy path must produce zero warnings")

	keaScope := findKeaScope(t, device.DHCP, "Happy path subnet")
	assert.Equal(t, "192.168.10.100", keaScope.Range.From)
	assert.Equal(t, "192.168.10.150", keaScope.Range.To)
	require.Len(t, keaScope.StaticLeases, 1)
	assert.Equal(t, "192.168.10.50", keaScope.StaticLeases[0].IPAddress)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", keaScope.StaticLeases[0].MAC)
	assert.Equal(t, "happy-host", keaScope.StaticLeases[0].Hostname)
}

// TestConverter_KeaDHCP4_Gotchas18_MultiPoolFirstWins locks in GOTCHAS §18.2:
// Kea pools are newline-separated strings on the subnet. Only the first pool
// is represented in the unified DHCPScope; additional pools produce an info
// warning so consumers can surface the truncation.
func TestConverter_KeaDHCP4_Gotchas18_MultiPoolFirstWins(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.OPNsense.Kea.Dhcp4.General.Enabled = "1"
	doc.OPNsense.Kea.Dhcp4.Subnets = []schema.KeaSubnet{
		{
			UUID:        "subnet-multipool",
			Subnet:      "10.20.0.0/24",
			Pools:       "10.20.0.100-10.20.0.150\n10.20.0.200-10.20.0.250",
			Description: "Multipool subnet",
		},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)

	keaScope := findKeaScope(t, device.DHCP, "Multipool subnet")
	assert.Equal(t, "10.20.0.100", keaScope.Range.From, "first pool start retained")
	assert.Equal(t, "10.20.0.150", keaScope.Range.To, "first pool end retained")

	poolWarning := findWarning(warnings, "kea.dhcp4.subnets.subnet4.pools",
		"10.20.0.100-10.20.0.150\n10.20.0.200-10.20.0.250")
	require.NotNil(t, poolWarning, "expected multi-pool warning")
	assert.Contains(t, poolWarning.Message, "2 pools")
	assert.Equal(t, common.SeverityInfo, poolWarning.Severity)
}

// TestConverter_KeaDHCP4_Gotchas18_OrphanReservation locks in GOTCHAS §18.3:
// reservations reference their parent subnet by UUID. A reservation pointing
// at a nonexistent subnet UUID must emit a warning and must NOT appear in any
// scope's static leases.
func TestConverter_KeaDHCP4_Gotchas18_OrphanReservation(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.OPNsense.Kea.Dhcp4.General.Enabled = "1"
	doc.OPNsense.Kea.Dhcp4.Subnets = []schema.KeaSubnet{
		{UUID: "subnet-real", Subnet: "10.30.0.0/24", Description: "Real subnet"},
	}
	doc.OPNsense.Kea.Dhcp4.Reservations = []schema.KeaReservation{
		{UUID: "res-real", Subnet: "subnet-real", IPAddress: "10.30.0.50", HWAddress: "aa:aa:aa:aa:aa:aa"},
		{UUID: "res-orphan", Subnet: "subnet-missing", IPAddress: "10.30.0.99", HWAddress: "bb:bb:bb:bb:bb:bb"},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)

	orphanWarning := findWarning(warnings, "kea.dhcp4.reservations", "subnet-missing")
	require.NotNil(t, orphanWarning, "expected orphan-reservation warning")
	assert.Contains(t, orphanWarning.Message, "nonexistent subnet UUID")
	assert.Equal(t, common.SeverityMedium, orphanWarning.Severity)

	keaScope := findKeaScope(t, device.DHCP, "Real subnet")
	require.Len(t, keaScope.StaticLeases, 1, "orphan reservation must not leak into any scope")
	assert.Equal(t, "10.30.0.50", keaScope.StaticLeases[0].IPAddress)
}

// TestConverter_KeaDHCP4_Gotchas18_SubnetMissingUUID locks in the companion
// invariant: a subnet without a UUID attribute can still produce a scope but
// must emit a warning because reservation matching cannot function without it.
func TestConverter_KeaDHCP4_Gotchas18_SubnetMissingUUID(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.OPNsense.Kea.Dhcp4.General.Enabled = "1"
	doc.OPNsense.Kea.Dhcp4.Subnets = []schema.KeaSubnet{
		{UUID: "", Subnet: "10.40.0.0/24", Description: "UUIDless subnet"},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	// The UUID-less subnet must still produce a scope — reservation matching
	// is broken but the scope itself is valid config data. findKeaScope calls
	// t.Fatalf when the named scope is absent, so the return value is
	// deliberately discarded; we only need the side effect.
	_ = findKeaScope(t, device.DHCP, "UUIDless subnet")

	uuidWarning := findWarning(warnings, "kea.dhcp4.subnets.subnet4", "10.40.0.0/24")
	require.NotNil(t, uuidWarning, "expected UUID-missing warning on subnet")
	assert.Contains(t, uuidWarning.Message, "reservation matching")
	assert.Equal(t, common.SeverityMedium, uuidWarning.Severity)
}

// TestConverter_KeaDHCP4_Gotchas18_ReservationMissingSubnet locks in the
// reservation-side partner: a reservation with no parent subnet reference is
// orphaned and must emit a warning.
func TestConverter_KeaDHCP4_Gotchas18_ReservationMissingSubnet(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.OPNsense.Kea.Dhcp4.General.Enabled = "1"
	// Include a subnet so convertKeaDHCPScopes executes at all; the reservation
	// that follows has an empty Subnet field, which the converter must treat
	// as orphaned regardless of whether any subnets are present.
	doc.OPNsense.Kea.Dhcp4.Subnets = []schema.KeaSubnet{
		{UUID: "subnet-any", Subnet: "10.50.0.0/24", Description: "Filler"},
	}
	doc.OPNsense.Kea.Dhcp4.Reservations = []schema.KeaReservation{
		{UUID: "res-floating", Subnet: "", IPAddress: "10.50.0.50", HWAddress: "cc:cc:cc:cc:cc:cc"},
	}

	_, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)

	floatWarning := findWarning(warnings, "kea.dhcp4.reservations.reservation.subnet", "res-floating")
	require.NotNil(t, floatWarning, "expected warning for reservation with blank subnet reference")
	assert.Contains(t, floatWarning.Message, "orphaned")
	assert.Equal(t, common.SeverityMedium, floatWarning.Severity)
}
