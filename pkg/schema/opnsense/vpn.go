// Package opnsense defines the data structures for OPNsense configurations.
package opnsense

import "encoding/xml"

// OpenVPN represents the legacy OpenVPN configuration container, holding server instances,
// client instances, client-specific configurations (CSC), and client export settings.
type OpenVPN struct {
	XMLName      xml.Name        `xml:"openvpn"`
	Servers      []OpenVPNServer `xml:"openvpn-server,omitempty"`
	Clients      []OpenVPNClient `xml:"openvpn-client,omitempty"`
	ClientExport *ClientExport   `xml:"openvpn-client-export,omitempty"`
	CSC          []OpenVPNCSC    `xml:"openvpn-csc,omitempty"`
	Created      string          `xml:"created,omitempty"`
	Updated      string          `xml:"updated,omitempty"`
}

// OpenVPNServer represents a single OpenVPN server instance with TLS settings, tunnel networks,
// client routing, DNS push options, compression, and topology configuration.
type OpenVPNServer struct {
	XMLName           xml.Name `xml:"openvpn-server"`
	VPN_ID            string   `xml:"vpnid,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Mode              string   `xml:"mode,omitempty"`
	Protocol          string   `xml:"protocol,omitempty"`
	Dev_mode          string   `xml:"dev_mode,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Interface         string   `xml:"interface,omitempty"`
	Local_port        string   `xml:"local_port,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Description       string   `xml:"description,omitempty"`
	Custom_options    string   `xml:"custom_options,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	TLS               string   `xml:"tls,omitempty"`
	TLS_type          string   `xml:"tls_type,omitempty"`   //nolint:revive,staticcheck // XML field name requires underscore
	Cert_ref          string   `xml:"certref,omitempty"`    //nolint:revive,staticcheck // XML field name requires underscore
	CA_ref            string   `xml:"caref,omitempty"`      //nolint:revive,staticcheck // XML field name requires underscore
	CRL_ref           string   `xml:"crlref,omitempty"`     //nolint:revive,staticcheck // XML field name requires underscore
	DH_length         string   `xml:"dh_length,omitempty"`  //nolint:revive,staticcheck // XML field name requires underscore
	Ecdh_curve        string   `xml:"ecdh_curve,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Cert_depth        string   `xml:"cert_depth,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Strictusercn      BoolFlag `xml:"strictusercn,omitempty"`
	Tunnel_network    string   `xml:"tunnel_network,omitempty"`   //nolint:revive,staticcheck // XML field name requires underscore
	Tunnel_networkv6  string   `xml:"tunnel_networkv6,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Remote_network    string   `xml:"remote_network,omitempty"`   //nolint:revive,staticcheck // XML field name requires underscore
	Remote_networkv6  string   `xml:"remote_networkv6,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Gwredir           BoolFlag `xml:"gwredir,omitempty"`
	Local_network     string   `xml:"local_network,omitempty"`   //nolint:revive,staticcheck // XML field name requires underscore
	Local_networkv6   string   `xml:"local_networkv6,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Maxclients        string   `xml:"maxclients,omitempty"`
	Compression       string   `xml:"compression,omitempty"`
	Passtos           BoolFlag `xml:"passtos,omitempty"`
	Client2client     BoolFlag `xml:"client2client,omitempty"`
	Dynamic_ip        BoolFlag `xml:"dynamic_ip,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Topology          string   `xml:"topology,omitempty"`
	Serverbridge_dhcp BoolFlag `xml:"serverbridge_dhcp,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	DNS_domain        string   `xml:"dns_domain,omitempty"`        //nolint:revive,staticcheck // XML field name requires underscore
	DNS_server1       string   `xml:"dns_server1,omitempty"`       //nolint:revive,staticcheck // XML field name requires underscore
	DNS_server2       string   `xml:"dns_server2,omitempty"`       //nolint:revive,staticcheck // XML field name requires underscore
	DNS_server3       string   `xml:"dns_server3,omitempty"`       //nolint:revive,staticcheck // XML field name requires underscore
	DNS_server4       string   `xml:"dns_server4,omitempty"`       //nolint:revive,staticcheck // XML field name requires underscore
	Push_register_dns BoolFlag `xml:"push_register_dns,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	NTP_server1       string   `xml:"ntp_server1,omitempty"`       //nolint:revive,staticcheck // XML field name requires underscore
	NTP_server2       string   `xml:"ntp_server2,omitempty"`       //nolint:revive,staticcheck // XML field name requires underscore
	Netbios_enable    BoolFlag `xml:"netbios_enable,omitempty"`    //nolint:revive,staticcheck // XML field name requires underscore
	Netbios_ntype     string   `xml:"netbios_ntype,omitempty"`     //nolint:revive,staticcheck // XML field name requires underscore
	Netbios_scope     string   `xml:"netbios_scope,omitempty"`     //nolint:revive,staticcheck // XML field name requires underscore
	Verbosity_level   string   `xml:"verbosity_level,omitempty"`   //nolint:revive,staticcheck // XML field name requires underscore
	Created           string   `xml:"created,omitempty"`
	Updated           string   `xml:"updated,omitempty"`
}

// OpenVPNClient represents a single OpenVPN client instance with server address,
// TLS settings, compression, and custom options.
type OpenVPNClient struct {
	XMLName         xml.Name `xml:"openvpn-client"`
	VPN_ID          string   `xml:"vpnid,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Mode            string   `xml:"mode,omitempty"`
	Protocol        string   `xml:"protocol,omitempty"`
	Dev_mode        string   `xml:"dev_mode,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Interface       string   `xml:"interface,omitempty"`
	Server_addr     string   `xml:"server_addr,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Server_port     string   `xml:"server_port,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Description     string   `xml:"description,omitempty"`
	Custom_options  string   `xml:"custom_options,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Cert_ref        string   `xml:"certref,omitempty"`        //nolint:revive,staticcheck // XML field name requires underscore
	CA_ref          string   `xml:"caref,omitempty"`          //nolint:revive,staticcheck // XML field name requires underscore
	Compression     string   `xml:"compression,omitempty"`
	Verbosity_level string   `xml:"verbosity_level,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Created         string   `xml:"created,omitempty"`
	Updated         string   `xml:"updated,omitempty"`
}

// ClientExport represents client export options for OpenVPN, used to generate
// downloadable client configuration packages.
type ClientExport struct {
	XMLName           xml.Name `xml:"openvpn-client-export"`
	Server_list       []string `xml:"server_list,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Hostname          string   `xml:"hostname,omitempty"`
	Random_local_port BoolFlag `xml:"random_local_port,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Silent_install    BoolFlag `xml:"silent_install,omitempty"`    //nolint:revive,staticcheck // XML field name requires underscore
	Use_token         BoolFlag `xml:"use_token,omitempty"`         //nolint:revive,staticcheck // XML field name requires underscore
}

// OpenVPNCSC represents a client-specific configuration (CSC) override for OpenVPN,
// allowing per-client tunnel networks, DNS settings, and routing overrides.
type OpenVPNCSC struct {
	XMLName          xml.Name `xml:"openvpn-csc"`
	Common_name      string   `xml:"common_name,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Block            BoolFlag `xml:"block,omitempty"`
	Tunnel_network   string   `xml:"tunnel_network,omitempty"`   //nolint:revive,staticcheck // XML field name requires underscore
	Tunnel_networkv6 string   `xml:"tunnel_networkv6,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Local_network    string   `xml:"local_network,omitempty"`    //nolint:revive,staticcheck // XML field name requires underscore
	Local_networkv6  string   `xml:"local_networkv6,omitempty"`  //nolint:revive,staticcheck // XML field name requires underscore
	Remote_network   string   `xml:"remote_network,omitempty"`   //nolint:revive,staticcheck // XML field name requires underscore
	Remote_networkv6 string   `xml:"remote_networkv6,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Gwredir          BoolFlag `xml:"gwredir,omitempty"`
	Push_reset       BoolFlag `xml:"push_reset,omitempty"`     //nolint:revive,staticcheck // XML field name requires underscore
	Remove_route     BoolFlag `xml:"remove_route,omitempty"`   //nolint:revive,staticcheck // XML field name requires underscore
	DNS_domain       string   `xml:"dns_domain,omitempty"`     //nolint:revive,staticcheck // XML field name requires underscore
	DNS_server1      string   `xml:"dns_server1,omitempty"`    //nolint:revive,staticcheck // XML field name requires underscore
	DNS_server2      string   `xml:"dns_server2,omitempty"`    //nolint:revive,staticcheck // XML field name requires underscore
	DNS_server3      string   `xml:"dns_server3,omitempty"`    //nolint:revive,staticcheck // XML field name requires underscore
	DNS_server4      string   `xml:"dns_server4,omitempty"`    //nolint:revive,staticcheck // XML field name requires underscore
	NTP_server1      string   `xml:"ntp_server1,omitempty"`    //nolint:revive,staticcheck // XML field name requires underscore
	NTP_server2      string   `xml:"ntp_server2,omitempty"`    //nolint:revive,staticcheck // XML field name requires underscore
	Custom_options   string   `xml:"custom_options,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Created          string   `xml:"created,omitempty"`
	Updated          string   `xml:"updated,omitempty"`
}

// OpenVPNExport represents the MVC-based OpenVPN export configuration for client package generation.
type OpenVPNExport struct {
	XMLName xml.Name `xml:"OpenVPNExport"`
	Text    string   `xml:",chardata"     json:"text,omitempty"`
	Version string   `xml:"version,attr"  json:"version,omitempty"`
	Servers string   `xml:"servers"`
}

// OpenVPNSystem represents the MVC-based OpenVPN system configuration, including
// instance overwrites, instance definitions, and static key management.
type OpenVPNSystem struct {
	XMLName    xml.Name `xml:"OpenVPN"`
	Text       string   `xml:",chardata"    json:"text,omitempty"`
	Version    string   `xml:"version,attr" json:"version,omitempty"`
	Overwrites string   `xml:"Overwrites"`
	Instances  string   `xml:"Instances"`
	StaticKeys string   `xml:"StaticKeys"`
}

// WireGuard represents the WireGuard VPN configuration, including global enable state,
// server (local peer) definitions, and client (remote peer) definitions.
type WireGuard struct {
	XMLName xml.Name `xml:"wireguard"`
	Text    string   `xml:",chardata" json:"text,omitempty"`
	General struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Enabled string `xml:"enabled" json:"enabled,omitempty"`
	} `xml:"general"   json:"general"`
	Server struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Servers struct {
			Text   string                `xml:",chardata" json:"text,omitempty"`
			Server []WireGuardServerItem `xml:"server" json:"server,omitempty"`
		} `xml:"servers" json:"servers"`
	} `xml:"server"    json:"server"`
	Client struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Clients struct {
			Text   string                `xml:",chardata" json:"text,omitempty"`
			Client []WireGuardClientItem `xml:"client" json:"client,omitempty"`
		} `xml:"clients" json:"clients"`
	} `xml:"client"    json:"client"`
}

// WireGuardServerItem represents a WireGuard local peer (server) configuration with
// public/private key pair, listen port, tunnel addresses, and assigned peer references.
type WireGuardServerItem struct {
	Text          string `xml:",chardata"     json:"text,omitempty"`
	UUID          string `xml:"uuid,attr"     json:"uuid,omitempty"`
	Version       string `xml:"version,attr"  json:"version,omitempty"`
	Enabled       string `xml:"enabled"       json:"enabled,omitempty"`
	Name          string `xml:"name"          json:"name,omitempty"`
	Instance      string `xml:"instance"      json:"instance,omitempty"`
	Pubkey        string `xml:"pubkey"        json:"pubkey,omitempty"`
	Privkey       string `xml:"privkey"       json:"privkey,omitempty"`
	Port          string `xml:"port"          json:"port,omitempty"`
	MTU           string `xml:"mtu"           json:"mtu,omitempty"`
	DNS           string `xml:"dns"           json:"dns,omitempty"`
	Tunneladdress string `xml:"tunneladdress" json:"tunneladdress,omitempty"`
	Disableroutes string `xml:"disableroutes" json:"disableroutes,omitempty"`
	Gateway       string `xml:"gateway"       json:"gateway,omitempty"`
	Peers         string `xml:"peers"         json:"peers,omitempty"`
}

// WireGuardClientItem represents a WireGuard remote peer (client) configuration with
// public key, optional pre-shared key, allowed tunnel addresses, endpoint, and keepalive interval.
type WireGuardClientItem struct {
	Text          string `xml:",chardata"     json:"text,omitempty"`
	UUID          string `xml:"uuid,attr"     json:"uuid,omitempty"`
	Version       string `xml:"version,attr"  json:"version,omitempty"`
	Enabled       string `xml:"enabled"       json:"enabled,omitempty"`
	Name          string `xml:"name"          json:"name,omitempty"`
	Pubkey        string `xml:"pubkey"        json:"pubkey,omitempty"`
	PSK           string `xml:"psk"           json:"psk,omitempty"`
	Tunneladdress string `xml:"tunneladdress" json:"tunneladdress,omitempty"`
	Serveraddress string `xml:"serveraddress" json:"serveraddress,omitempty"`
	Serverport    string `xml:"serverport"    json:"serverport,omitempty"`
	Keepalive     string `xml:"keepalive"     json:"keepalive,omitempty"`
}

// Constructor functions

// NewOpenVPN returns a new OpenVPN configuration with empty server, client, and client-specific configuration lists.
func NewOpenVPN() *OpenVPN {
	return &OpenVPN{
		Servers: make([]OpenVPNServer, 0),
		Clients: make([]OpenVPNClient, 0),
		CSC:     make([]OpenVPNCSC, 0),
	}
}

// NewClientExport returns a new ClientExport instance with an empty server list.
func NewClientExport() *ClientExport {
	return &ClientExport{
		Server_list: make([]string, 0),
	}
}

// NewOpenVPNExport initializes and returns an empty OpenVPNExport configuration.
func NewOpenVPNExport() *OpenVPNExport {
	return &OpenVPNExport{}
}

// NewOpenVPNSystem returns a new, empty OpenVPNSystem configuration instance.
func NewOpenVPNSystem() *OpenVPNSystem {
	return &OpenVPNSystem{}
}

// NewWireGuard returns a new WireGuard configuration instance with default values.
func NewWireGuard() *WireGuard {
	return &WireGuard{}
}
