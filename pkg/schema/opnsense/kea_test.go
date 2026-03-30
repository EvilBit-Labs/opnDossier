package opnsense

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeaDhcp4_UnmarshalXML(t *testing.T) {
	t.Parallel()

	input := `<dhcp4 version="1.0.4">
		<general>
			<enabled>1</enabled>
			<interfaces>lan,opt1</interfaces>
			<valid_lifetime>4000</valid_lifetime>
			<fwrules>1</fwrules>
		</general>
		<ha>
			<enabled>0</enabled>
			<this_server_name/>
			<max_unacked_clients>2</max_unacked_clients>
		</ha>
		<subnets>
			<subnet4 uuid="sub-1">
				<subnet>192.168.1.0/24</subnet>
				<option_data_autocollect>1</option_data_autocollect>
				<option_data>
					<routers>192.168.1.1</routers>
					<domain_name_servers>192.168.1.1,8.8.8.8</domain_name_servers>
					<ntp_servers>192.168.1.1</ntp_servers>
					<domain_name>example.local</domain_name>
				</option_data>
				<pools>192.168.1.100-192.168.1.200
192.168.1.210-192.168.1.250</pools>
				<description>LAN subnet</description>
			</subnet4>
			<subnet4 uuid="sub-2">
				<subnet>10.0.0.0/24</subnet>
				<option_data>
					<routers>10.0.0.1</routers>
				</option_data>
				<pools>10.0.0.50-10.0.0.100</pools>
				<description>Server VLAN</description>
			</subnet4>
		</subnets>
		<reservations>
			<reservation uuid="res-x">
				<subnet>sub-1</subnet>
				<ip_address>192.168.1.50</ip_address>
				<hw_address>aa:bb:cc:dd:ee:ff</hw_address>
				<hostname>myhost</hostname>
				<description>Dev workstation</description>
			</reservation>
		</reservations>
		<ha_peers/>
	</dhcp4>`

	var dhcp4 KeaDhcp4
	err := xml.Unmarshal([]byte(input), &dhcp4)
	require.NoError(t, err)

	// General
	assert.Equal(t, "1", dhcp4.General.Enabled)
	assert.Equal(t, "lan,opt1", dhcp4.General.Interfaces)
	assert.Equal(t, "4000", dhcp4.General.ValidLifetime)
	assert.Equal(t, "1", dhcp4.General.FirewallRules)

	// HA
	assert.Equal(t, "0", dhcp4.HighAvailability.Enabled)
	assert.Equal(t, "2", dhcp4.HighAvailability.MaxUnackedClients)

	// Subnets
	require.Len(t, dhcp4.Subnets, 2)
	assert.Equal(t, "sub-1", dhcp4.Subnets[0].UUID)
	assert.Equal(t, "192.168.1.0/24", dhcp4.Subnets[0].Subnet)
	assert.Contains(t, dhcp4.Subnets[0].Pools, "192.168.1.100-192.168.1.200")
	assert.Contains(t, dhcp4.Subnets[0].Pools, "192.168.1.210-192.168.1.250")
	assert.Equal(t, "LAN subnet", dhcp4.Subnets[0].Description)

	// Second subnet
	assert.Equal(t, "sub-2", dhcp4.Subnets[1].UUID)
	assert.Equal(t, "10.0.0.0/24", dhcp4.Subnets[1].Subnet)
	assert.Equal(t, "10.0.0.50-10.0.0.100", dhcp4.Subnets[1].Pools)

	// Subnet option_data
	assert.Equal(t, "192.168.1.1", dhcp4.Subnets[0].OptionData.Routers)
	assert.Equal(t, "192.168.1.1,8.8.8.8", dhcp4.Subnets[0].OptionData.DomainNameServers)
	assert.Equal(t, "192.168.1.1", dhcp4.Subnets[0].OptionData.NTPServers)
	assert.Equal(t, "example.local", dhcp4.Subnets[0].OptionData.DomainName)

	// Reservations (reference parent subnet by UUID)
	require.Len(t, dhcp4.Reservations, 1)
	assert.Equal(t, "res-x", dhcp4.Reservations[0].UUID)
	assert.Equal(t, "sub-1", dhcp4.Reservations[0].Subnet)
	assert.Equal(t, "192.168.1.50", dhcp4.Reservations[0].IPAddress)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", dhcp4.Reservations[0].HWAddress)
	assert.Equal(t, "myhost", dhcp4.Reservations[0].Hostname)
	assert.Equal(t, "Dev workstation", dhcp4.Reservations[0].Description)
}

func TestKeaDhcp4_EmptySubnets(t *testing.T) {
	t.Parallel()

	input := `<dhcp4 version="1.0.4">
		<general>
			<enabled>0</enabled>
			<interfaces/>
			<valid_lifetime>4000</valid_lifetime>
			<fwrules>1</fwrules>
		</general>
		<ha>
			<enabled>0</enabled>
			<this_server_name/>
			<max_unacked_clients>2</max_unacked_clients>
		</ha>
		<subnets/>
		<reservations/>
		<ha_peers/>
	</dhcp4>`

	var dhcp4 KeaDhcp4
	err := xml.Unmarshal([]byte(input), &dhcp4)
	require.NoError(t, err)

	assert.Empty(t, dhcp4.Subnets)
	assert.Empty(t, dhcp4.Reservations)
}
