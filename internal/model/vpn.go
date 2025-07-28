// Package model defines the data structures for OPNsense configurations.
package model

import "encoding/xml"

// OpenVPN represents OpenVPN configuration.
type OpenVPN struct {
	XMLName      xml.Name        `xml:"openvpn"`
	Servers      []OpenVPNServer `xml:"openvpn-server,omitempty"`
	Clients      []OpenVPNClient `xml:"openvpn-client,omitempty"`
	ClientExport *ClientExport   `xml:"openvpn-client-export,omitempty"`
	CSC          []OpenVPNCSC    `xml:"openvpn-csc,omitempty"`
	Created      string          `xml:"created,omitempty"`
	Updated      string          `xml:"updated,omitempty"`
}

// OpenVPNServer represents an OpenVPN server configuration.
type OpenVPNServer struct {
	XMLName           xml.Name `xml:"openvpn-server"`
	VPN_ID            string   `xml:"vpnid,omitempty"` //nolint:revive // XML field name requires underscore
	Mode              string   `xml:"mode,omitempty"`
	Protocol          string   `xml:"protocol,omitempty"`
	Dev_mode          string   `xml:"dev_mode,omitempty"` //nolint:revive // XML field name requires underscore
	Interface         string   `xml:"interface,omitempty"`
	Local_port        string   `xml:"local_port,omitempty"` //nolint:revive // XML field name requires underscore
	Description       string   `xml:"description,omitempty"`
	Custom_options    string   `xml:"custom_options,omitempty"` //nolint:revive // XML field name requires underscore
	TLS               string   `xml:"tls,omitempty"`
	TLS_type          string   `xml:"tls_type,omitempty"`   //nolint:revive // XML field name requires underscore
	Cert_ref          string   `xml:"certref,omitempty"`    //nolint:revive // XML field name requires underscore
	CA_ref            string   `xml:"caref,omitempty"`      //nolint:revive // XML field name requires underscore
	CRL_ref           string   `xml:"crlref,omitempty"`     //nolint:revive // XML field name requires underscore
	DH_length         string   `xml:"dh_length,omitempty"`  //nolint:revive // XML field name requires underscore
	Ecdh_curve        string   `xml:"ecdh_curve,omitempty"` //nolint:revive // XML field name requires underscore
	Cert_depth        string   `xml:"cert_depth,omitempty"` //nolint:revive // XML field name requires underscore
	Strictusercn      BoolFlag `xml:"strictusercn,omitempty"`
	Tunnel_network    string   `xml:"tunnel_network,omitempty"`   //nolint:revive // XML field name requires underscore
	Tunnel_networkv6  string   `xml:"tunnel_networkv6,omitempty"` //nolint:revive // XML field name requires underscore
	Remote_network    string   `xml:"remote_network,omitempty"`   //nolint:revive // XML field name requires underscore
	Remote_networkv6  string   `xml:"remote_networkv6,omitempty"` //nolint:revive // XML field name requires underscore
	Gwredir           BoolFlag `xml:"gwredir,omitempty"`
	Local_network     string   `xml:"local_network,omitempty"`   //nolint:revive // XML field name requires underscore
	Local_networkv6   string   `xml:"local_networkv6,omitempty"` //nolint:revive // XML field name requires underscore
	Maxclients        string   `xml:"maxclients,omitempty"`
	Compression       string   `xml:"compression,omitempty"`
	Passtos           BoolFlag `xml:"passtos,omitempty"`
	Client2client     BoolFlag `xml:"client2client,omitempty"`
	Dynamic_ip        BoolFlag `xml:"dynamic_ip,omitempty"` //nolint:revive // XML field name requires underscore
	Topology          string   `xml:"topology,omitempty"`
	Serverbridge_dhcp BoolFlag `xml:"serverbridge_dhcp,omitempty"` //nolint:revive // XML field name requires underscore
	DNS_domain        string   `xml:"dns_domain,omitempty"`        //nolint:revive // XML field name requires underscore
	DNS_server1       string   `xml:"dns_server1,omitempty"`       //nolint:revive // XML field name requires underscore
	DNS_server2       string   `xml:"dns_server2,omitempty"`       //nolint:revive // XML field name requires underscore
	DNS_server3       string   `xml:"dns_server3,omitempty"`       //nolint:revive // XML field name requires underscore
	DNS_server4       string   `xml:"dns_server4,omitempty"`       //nolint:revive // XML field name requires underscore
	Push_register_dns BoolFlag `xml:"push_register_dns,omitempty"` //nolint:revive // XML field name requires underscore
	NTP_server1       string   `xml:"ntp_server1,omitempty"`       //nolint:revive // XML field name requires underscore
	NTP_server2       string   `xml:"ntp_server2,omitempty"`       //nolint:revive // XML field name requires underscore
	Netbios_enable    BoolFlag `xml:"netbios_enable,omitempty"`    //nolint:revive // XML field name requires underscore
	Netbios_ntype     string   `xml:"netbios_ntype,omitempty"`     //nolint:revive // XML field name requires underscore
	Netbios_scope     string   `xml:"netbios_scope,omitempty"`     //nolint:revive // XML field name requires underscore
	Verbosity_level   string   `xml:"verbosity_level,omitempty"`   //nolint:revive // XML field name requires underscore
	Created           string   `xml:"created,omitempty"`
	Updated           string   `xml:"updated,omitempty"`
}

// OpenVPNClient represents an OpenVPN client configuration.
type OpenVPNClient struct {
	XMLName         xml.Name `xml:"openvpn-client"`
	VPN_ID          string   `xml:"vpnid,omitempty"` //nolint:revive // XML field name requires underscore
	Mode            string   `xml:"mode,omitempty"`
	Protocol        string   `xml:"protocol,omitempty"`
	Dev_mode        string   `xml:"dev_mode,omitempty"` //nolint:revive // XML field name requires underscore
	Interface       string   `xml:"interface,omitempty"`
	Server_addr     string   `xml:"server_addr,omitempty"` //nolint:revive // XML field name requires underscore
	Server_port     string   `xml:"server_port,omitempty"` //nolint:revive // XML field name requires underscore
	Description     string   `xml:"description,omitempty"`
	Custom_options  string   `xml:"custom_options,omitempty"` //nolint:revive // XML field name requires underscore
	Cert_ref        string   `xml:"certref,omitempty"`        //nolint:revive // XML field name requires underscore
	CA_ref          string   `xml:"caref,omitempty"`          //nolint:revive // XML field name requires underscore
	Compression     string   `xml:"compression,omitempty"`
	Verbosity_level string   `xml:"verbosity_level,omitempty"` //nolint:revive // XML field name requires underscore
	Created         string   `xml:"created,omitempty"`
	Updated         string   `xml:"updated,omitempty"`
}

// ClientExport represents client export options for OpenVPN.
type ClientExport struct {
	XMLName           xml.Name `xml:"openvpn-client-export"`
	Server_list       []string `xml:"server_list,omitempty"` //nolint:revive // XML field name requires underscore
	Hostname          string   `xml:"hostname,omitempty"`
	Random_local_port BoolFlag `xml:"random_local_port,omitempty"` //nolint:revive // XML field name requires underscore
	Silent_install    BoolFlag `xml:"silent_install,omitempty"`    //nolint:revive // XML field name requires underscore
	Use_token         BoolFlag `xml:"use_token,omitempty"`         //nolint:revive // XML field name requires underscore
}

// OpenVPNCSC represents client-specific configurations for OpenVPN.
type OpenVPNCSC struct {
	XMLName          xml.Name `xml:"openvpn-csc"`
	Common_name      string   `xml:"common_name,omitempty"` //nolint:revive // XML field name requires underscore
	Description      string   `xml:"description,omitempty"`
	Block            BoolFlag `xml:"block,omitempty"`
	Tunnel_network   string   `xml:"tunnel_network,omitempty"`   //nolint:revive // XML field name requires underscore
	Tunnel_networkv6 string   `xml:"tunnel_networkv6,omitempty"` //nolint:revive // XML field name requires underscore
	Local_network    string   `xml:"local_network,omitempty"`    //nolint:revive // XML field name requires underscore
	Local_networkv6  string   `xml:"local_networkv6,omitempty"`  //nolint:revive // XML field name requires underscore
	Remote_network   string   `xml:"remote_network,omitempty"`   //nolint:revive // XML field name requires underscore
	Remote_networkv6 string   `xml:"remote_networkv6,omitempty"` //nolint:revive // XML field name requires underscore
	Gwredir          BoolFlag `xml:"gwredir,omitempty"`
	Push_reset       BoolFlag `xml:"push_reset,omitempty"`     //nolint:revive // XML field name requires underscore
	Remove_route     BoolFlag `xml:"remove_route,omitempty"`   //nolint:revive // XML field name requires underscore
	DNS_domain       string   `xml:"dns_domain,omitempty"`     //nolint:revive // XML field name requires underscore
	DNS_server1      string   `xml:"dns_server1,omitempty"`    //nolint:revive // XML field name requires underscore
	DNS_server2      string   `xml:"dns_server2,omitempty"`    //nolint:revive // XML field name requires underscore
	DNS_server3      string   `xml:"dns_server3,omitempty"`    //nolint:revive // XML field name requires underscore
	DNS_server4      string   `xml:"dns_server4,omitempty"`    //nolint:revive // XML field name requires underscore
	NTP_server1      string   `xml:"ntp_server1,omitempty"`    //nolint:revive // XML field name requires underscore
	NTP_server2      string   `xml:"ntp_server2,omitempty"`    //nolint:revive // XML field name requires underscore
	Custom_options   string   `xml:"custom_options,omitempty"` //nolint:revive // XML field name requires underscore
	Created          string   `xml:"created,omitempty"`
	Updated          string   `xml:"updated,omitempty"`
}

// Constructor functions for VPN models

// NewOpenVPN creates a new OpenVPN configuration with properly initialized slices.
func NewOpenVPN() *OpenVPN {
	return &OpenVPN{
		Servers: make([]OpenVPNServer, 0),
		Clients: make([]OpenVPNClient, 0),
		CSC:     make([]OpenVPNCSC, 0),
	}
}

// NewClientExport creates a new ClientExport with properly initialized slices.
func NewClientExport() *ClientExport {
	return &ClientExport{
		Server_list: make([]string, 0),
	}
}
