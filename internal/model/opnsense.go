// Package model defines the data structures for OPNsense configurations.
package model

import (
	"encoding/xml"
)

// Opnsense is the root of the OPNsense configuration.
type Opnsense struct {
	XMLName              xml.Name     `xml:"opnsense" json:"-" yaml:"-"`
	Version              string       `xml:"version,omitempty" json:"version,omitempty" yaml:"version,omitempty" validate:"omitempty,semver"`
	TriggerInitialWizard struct{}     `xml:"trigger_initial_wizard,omitempty" json:"triggerInitialWizard,omitempty" yaml:"triggerInitialWizard,omitempty"`
	Theme                string       `xml:"theme,omitempty" json:"theme,omitempty" yaml:"theme,omitempty" validate:"omitempty,oneof=opnsense opnsense-ng bootstrap"`
	Sysctl               []SysctlItem `xml:"sysctl,omitempty" json:"sysctl,omitempty" yaml:"sysctl,omitempty" validate:"dive"`
	System               System       `xml:"system,omitempty" json:"system,omitempty" yaml:"system,omitempty" validate:"required"`
	Interfaces           Interfaces   `xml:"interfaces,omitempty" json:"interfaces,omitempty" yaml:"interfaces,omitempty" validate:"required"`
	Dhcpd                Dhcpd        `xml:"dhcpd,omitempty" json:"dhcpd,omitempty" yaml:"dhcpd,omitempty"`
	Unbound              Unbound      `xml:"unbound,omitempty" json:"unbound,omitempty" yaml:"unbound,omitempty"`
	Snmpd                Snmpd        `xml:"snmpd,omitempty" json:"snmpd,omitempty" yaml:"snmpd,omitempty"`
	Nat                  Nat          `xml:"nat,omitempty" json:"nat,omitempty" yaml:"nat,omitempty"`
	Filter               Filter       `xml:"filter,omitempty" json:"filter,omitempty" yaml:"filter,omitempty"`
	Rrd                  Rrd          `xml:"rrd,omitempty" json:"rrd,omitempty" yaml:"rrd,omitempty"`
	LoadBalancer         LoadBalancer `xml:"load_balancer,omitempty" json:"loadBalancer,omitempty" yaml:"loadBalancer,omitempty"`
	Ntpd                 Ntpd         `xml:"ntpd,omitempty" json:"ntpd,omitempty" yaml:"ntpd,omitempty"`
	Widgets              Widgets      `xml:"widgets,omitempty" json:"widgets,omitempty" yaml:"widgets,omitempty"`

	Vlans        *Vlans        `xml:"vlans,omitempty"`
	Bridges      *Bridges      `xml:"bridges,omitempty"`
	Gateways     *Gateways     `xml:"gateways,omitempty"`
	StaticRoutes *StaticRoutes `xml:"staticroutes,omitempty"`
	DNSMasq      *DNSMasq      `xml:"dnsmasq,omitempty"`
	OpenVPN      *OpenVPN      `xml:"openvpn,omitempty"`
	Syslog       *Syslog       `xml:"syslog,omitempty"`
	OPNsense     *OPNsense     `xml:"opnsense,omitempty"`
}

// OPNsense represents the main OPNsense system configuration.
type OPNsense struct {
	XMLName xml.Name `xml:"opnsense"`
	Text    string   `xml:",chardata" json:"text,omitempty"`

	Captiveportal struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Version   string `xml:"version,attr" json:"version,omitempty"`
		Zones     string `xml:"zones"`
		Templates string `xml:"templates"`
	} `xml:"captiveportal" json:"captiveportal,omitempty"`
	Cron struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Jobs    string `xml:"jobs"`
	} `xml:"cron" json:"cron,omitempty"`

	DHCRelay struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
	} `xml:"DHCRelay" json:"dhcrelay,omitempty"`
	Firewall struct {
		Text       string `xml:",chardata" json:"text,omitempty"`
		Lvtemplate struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Version   string `xml:"version,attr" json:"version,omitempty"`
			Templates string `xml:"templates"`
		} `xml:"Lvtemplate" json:"lvtemplate,omitempty"`
		Alias struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
			Geoip   struct {
				Text string `xml:",chardata" json:"text,omitempty"`
				URL  string `xml:"url"`
			} `xml:"geoip" json:"geoip,omitempty"`
			Aliases string `xml:"aliases"`
		} `xml:"Alias" json:"alias,omitempty"`
		Category struct {
			Text       string `xml:",chardata" json:"text,omitempty"`
			Version    string `xml:"version,attr" json:"version,omitempty"`
			Categories string `xml:"categories"`
		} `xml:"Category" json:"category,omitempty"`
		Filter struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Version   string `xml:"version,attr" json:"version,omitempty"`
			Rules     string `xml:"rules"`
			Snatrules string `xml:"snatrules"`
			Npt       string `xml:"npt"`
			Onetoone  string `xml:"onetoone"`
		} `xml:"Filter" json:"filter,omitempty"`
	} `xml:"Firewall" json:"firewall,omitempty"`
	Netflow struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Capture struct {
			Text       string `xml:",chardata" json:"text,omitempty"`
			Interfaces string `xml:"interfaces"`
			EgressOnly string `xml:"egress_only"`
			Version    string `xml:"version"`
			Targets    string `xml:"targets"`
		} `xml:"capture" json:"capture,omitempty"`
		Collect struct {
			Text   string `xml:",chardata" json:"text,omitempty"`
			Enable string `xml:"enable"`
		} `xml:"collect" json:"collect,omitempty"`
		ActiveTimeout   string `xml:"activeTimeout"`
		InactiveTimeout string `xml:"inactiveTimeout"`
	} `xml:"Netflow" json:"netflow,omitempty"`
	IDs struct {
		Text             string `xml:",chardata" json:"text,omitempty"`
		Version          string `xml:"version,attr" json:"version,omitempty"`
		Rules            string `xml:"rules"`
		Policies         string `xml:"policies"`
		UserDefinedRules string `xml:"userDefinedRules"`
		Files            string `xml:"files"`
		FileTags         string `xml:"fileTags"`
		General          struct {
			Text              string `xml:",chardata" json:"text,omitempty"`
			Enabled           string `xml:"enabled"`
			Ips               string `xml:"ips"`
			Promisc           string `xml:"promisc"`
			Interfaces        string `xml:"interfaces"`
			Homenet           string `xml:"homenet"`
			DefaultPacketSize string `xml:"defaultPacketSize"`
			UpdateCron        string `xml:"UpdateCron"`
			AlertLogrotate    string `xml:"AlertLogrotate"`
			AlertSaveLogs     string `xml:"AlertSaveLogs"`
			MPMAlgo           string `xml:"MPMAlgo"`
			Detect            struct {
				Text           string `xml:",chardata" json:"text,omitempty"`
				Profile        string `xml:"Profile"`
				ToclientGroups string `xml:"toclient_groups"`
				ToserverGroups string `xml:"toserver_groups"`
			} `xml:"detect" json:"detect,omitempty"`
			Syslog     string `xml:"syslog"`
			SyslogEve  string `xml:"syslog_eve"`
			LogPayload string `xml:"LogPayload"`
			Verbosity  string `xml:"verbosity"`
			EveLog     struct {
				Text string `xml:",chardata" json:"text,omitempty"`
				HTTP struct {
					Text           string `xml:",chardata" json:"text,omitempty"`
					Enable         string `xml:"enable"`
					Extended       string `xml:"extended"`
					DumpAllHeaders string `xml:"dumpAllHeaders"`
				} `xml:"http" json:"http,omitempty"`
				TLS struct {
					Text              string `xml:",chardata" json:"text,omitempty"`
					Enable            string `xml:"enable"`
					Extended          string `xml:"extended"`
					SessionResumption string `xml:"sessionResumption"`
					Custom            string `xml:"custom"`
				} `xml:"tls" json:"tls,omitempty"`
			} `xml:"eveLog" json:"evelog,omitempty"`
		} `xml:"general" json:"general,omitempty"`
	} `xml:"IDS" json:"ids,omitempty"`
	IPsec struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		General struct {
			Text                string `xml:",chardata" json:"text,omitempty"`
			Enabled             string `xml:"enabled"`
			PreferredOldsa      string `xml:"preferred_oldsa"`
			Disablevpnrules     string `xml:"disablevpnrules"`
			PassthroughNetworks string `xml:"passthrough_networks"`
		} `xml:"general" json:"general,omitempty"`
		Charon struct {
			Text               string `xml:",chardata" json:"text,omitempty"`
			MaxIkev1Exchanges  string `xml:"max_ikev1_exchanges"`
			Threads            string `xml:"threads"`
			IkesaTableSize     string `xml:"ikesa_table_size"`
			IkesaTableSegments string `xml:"ikesa_table_segments"`
			InitLimitHalfOpen  string `xml:"init_limit_half_open"`
			IgnoreAcquireTs    string `xml:"ignore_acquire_ts"`
			MakeBeforeBreak    string `xml:"make_before_break"`
			RetransmitTries    string `xml:"retransmit_tries"`
			RetransmitTimeout  string `xml:"retransmit_timeout"`
			RetransmitBase     string `xml:"retransmit_base"`
			RetransmitJitter   string `xml:"retransmit_jitter"`
			RetransmitLimit    string `xml:"retransmit_limit"`
			Syslog             struct {
				Text   string `xml:",chardata" json:"text,omitempty"`
				Daemon struct {
					Text     string `xml:",chardata" json:"text,omitempty"`
					IkeName  string `xml:"ike_name"`
					LogLevel string `xml:"log_level"`
					App      string `xml:"app"`
					Asn      string `xml:"asn"`
					Cfg      string `xml:"cfg"`
					Chd      string `xml:"chd"`
					Dmn      string `xml:"dmn"`
					Enc      string `xml:"enc"`
					Esp      string `xml:"esp"`
					Ike      string `xml:"ike"`
					Imc      string `xml:"imc"`
					Imv      string `xml:"imv"`
					Job      string `xml:"job"`
					Knl      string `xml:"knl"`
					Lib      string `xml:"lib"`
					Mgr      string `xml:"mgr"`
					Net      string `xml:"net"`
					Pts      string `xml:"pts"`
					TLS      string `xml:"tls"`
					Tnc      string `xml:"tnc"`
				} `xml:"daemon" json:"daemon,omitempty"`
			} `xml:"syslog" json:"syslog,omitempty"`
		} `xml:"charon" json:"charon,omitempty"`
		KeyPairs      string `xml:"keyPairs"`
		PreSharedKeys string `xml:"preSharedKeys"`
	} `xml:"IPsec" json:"ipsec,omitempty"`
	Swanctl struct {
		Text        string `xml:",chardata" json:"text,omitempty"`
		Version     string `xml:"version,attr" json:"version,omitempty"`
		Connections string `xml:"Connections"`
		Locals      string `xml:"locals"`
		Remotes     string `xml:"remotes"`
		Children    string `xml:"children"`
		Pools       string `xml:"Pools"`
		VTIs        string `xml:"VTIs"`
		SPDs        string `xml:"SPDs"`
	} `xml:"Swanctl" json:"swanctl,omitempty"`
	Firmware   *Firmware `xml:"firmware,omitempty"`
	Interfaces struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Loopbacks struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
		} `xml:"loopbacks" json:"loopbacks,omitempty"`
		Neighbors struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
		} `xml:"neighbors" json:"neighbors,omitempty"`
		Vxlans struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
		} `xml:"vxlans" json:"vxlans,omitempty"`
	} `xml:"Interfaces" json:"interfaces,omitempty"`
	Kea struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		CtrlAgent struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
			General struct {
				Text     string `xml:",chardata" json:"text,omitempty"`
				Enabled  string `xml:"enabled"`
				HTTPHost string `xml:"http_host"`
				HTTPPort string `xml:"http_port"`
			} `xml:"general" json:"general,omitempty"`
		} `xml:"ctrl_agent" json:"ctrlAgent,omitempty"`
		Dhcp4 struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
			General struct {
				Text          string `xml:",chardata" json:"text,omitempty"`
				Enabled       string `xml:"enabled"`
				Interfaces    string `xml:"interfaces"`
				ValidLifetime string `xml:"valid_lifetime"`
				Fwrules       string `xml:"fwrules"`
			} `xml:"general" json:"general,omitempty"`
			Ha struct {
				Text              string `xml:",chardata" json:"text,omitempty"`
				Enabled           string `xml:"enabled"`
				ThisServerName    string `xml:"this_server_name"`
				MaxUnackedClients string `xml:"max_unacked_clients"`
			} `xml:"ha" json:"ha,omitempty"`
			Subnets      string `xml:"subnets"`
			Reservations string `xml:"reservations"`
			HaPeers      string `xml:"ha_peers"`
		} `xml:"dhcp4" json:"dhcp4,omitempty"`
	} `xml:"Kea" json:"kea,omitempty"`
	Monit struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		General struct {
			Text                      string `xml:",chardata" json:"text,omitempty"`
			Enabled                   string `xml:"enabled"`
			Interval                  string `xml:"interval"`
			Startdelay                string `xml:"startdelay"`
			Mailserver                string `xml:"mailserver"`
			Port                      string `xml:"port"`
			Username                  string `xml:"username"`
			Password                  string `xml:"password"`
			Ssl                       string `xml:"ssl"`
			Sslversion                string `xml:"sslversion"`
			Sslverify                 string `xml:"sslverify"`
			Logfile                   string `xml:"logfile"`
			Statefile                 string `xml:"statefile"`
			EventqueuePath            string `xml:"eventqueuePath"`
			EventqueueSlots           string `xml:"eventqueueSlots"`
			HttpdEnabled              string `xml:"httpdEnabled"`
			HttpdUsername             string `xml:"httpdUsername"`
			HttpdPassword             string `xml:"httpdPassword"`
			HttpdPort                 string `xml:"httpdPort"`
			HttpdAllow                string `xml:"httpdAllow"`
			MmonitURL                 string `xml:"mmonitUrl"`
			MmonitTimeout             string `xml:"mmonitTimeout"`
			MmonitRegisterCredentials string `xml:"mmonitRegisterCredentials"`
		} `xml:"general" json:"general,omitempty"`
		Alert struct {
			Text        string `xml:",chardata" json:"text,omitempty"`
			UUID        string `xml:"uuid,attr" json:"uuid,omitempty"`
			Enabled     string `xml:"enabled"`
			Recipient   string `xml:"recipient"`
			Noton       string `xml:"noton"`
			Events      string `xml:"events"`
			Format      string `xml:"format"`
			Reminder    string `xml:"reminder"`
			Description string `xml:"description"`
		} `xml:"alert" json:"alert,omitempty"`
		Service []struct {
			Text         string `xml:",chardata" json:"text,omitempty"`
			UUID         string `xml:"uuid,attr" json:"uuid,omitempty"`
			Enabled      string `xml:"enabled"`
			Name         string `xml:"name"`
			Description  string `xml:"description"`
			Type         string `xml:"type"`
			Pidfile      string `xml:"pidfile"`
			Match        string `xml:"match"`
			Path         string `xml:"path"`
			Timeout      string `xml:"timeout"`
			Starttimeout string `xml:"starttimeout"`
			Address      string `xml:"address"`
			Interface    string `xml:"interface"`
			Start        string `xml:"start"`
			Stop         string `xml:"stop"`
			Tests        string `xml:"tests"`
			Depends      string `xml:"depends"`
			Polltime     string `xml:"polltime"`
		} `xml:"service" json:"service,omitempty"`
		Test []struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			UUID      string `xml:"uuid,attr" json:"uuid,omitempty"`
			Name      string `xml:"name"`
			Type      string `xml:"type"`
			Condition string `xml:"condition"`
			Action    string `xml:"action"`
			Path      string `xml:"path"`
		} `xml:"test" json:"test,omitempty"`
	} `xml:"monit" json:"monit,omitempty"`
	OpenVPNExport struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Servers string `xml:"servers"`
	} `xml:"OpenVPNExport" json:"openvpnexport,omitempty"`
	OpenVPN struct {
		Text       string `xml:",chardata" json:"text,omitempty"`
		Version    string `xml:"version,attr" json:"version,omitempty"`
		Overwrites string `xml:"Overwrites"`
		Instances  string `xml:"Instances"`
		StaticKeys string `xml:"StaticKeys"`
	} `xml:"OpenVPN" json:"openvpn,omitempty"`
	Gateways struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
	} `xml:"Gateways" json:"gateways,omitempty"`
	Syslog struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		General struct {
			Text        string `xml:",chardata" json:"text,omitempty"`
			Enabled     string `xml:"enabled"`
			Loglocal    string `xml:"loglocal"`
			Maxpreserve string `xml:"maxpreserve"`
			Maxfilesize string `xml:"maxfilesize"`
		} `xml:"general" json:"general,omitempty"`
		Destinations string `xml:"destinations"`
	} `xml:"Syslog" json:"syslog,omitempty"`
	TrafficShaper struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Pipes   string `xml:"pipes"`
		Queues  string `xml:"queues"`
		Rules   string `xml:"rules"`
	} `xml:"TrafficShaper" json:"trafficshaper,omitempty"`
	Trust struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		General struct {
			Text                    string `xml:",chardata" json:"text,omitempty"`
			Version                 string `xml:"version,attr" json:"version,omitempty"`
			StoreIntermediateCerts  string `xml:"store_intermediate_certs"`
			InstallCrls             string `xml:"install_crls"`
			FetchCrls               string `xml:"fetch_crls"`
			EnableLegacySect        string `xml:"enable_legacy_sect"`
			EnableConfigConstraints string `xml:"enable_config_constraints"`
			CipherString            string `xml:"CipherString"`
			Ciphersuites            string `xml:"Ciphersuites"`
			Groups                  string `xml:"groups"`
			MinProtocol             string `xml:"MinProtocol"`
			MinProtocolDTLS         string `xml:"MinProtocol_DTLS"`
		} `xml:"general" json:"general,omitempty"`
	} `xml:"trust" json:"trust,omitempty"`
	Unboundplus struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		General struct {
			Text              string `xml:",chardata" json:"text,omitempty"`
			Enabled           string `xml:"enabled"`
			Port              string `xml:"port"`
			Stats             string `xml:"stats"`
			ActiveInterface   string `xml:"active_interface"`
			Dnssec            string `xml:"dnssec"`
			DNS64             string `xml:"dns64"`
			DNS64prefix       string `xml:"dns64prefix"`
			Noarecords        string `xml:"noarecords"`
			Regdhcp           string `xml:"regdhcp"`
			Regdhcpdomain     string `xml:"regdhcpdomain"`
			Regdhcpstatic     string `xml:"regdhcpstatic"`
			Noreglladdr6      string `xml:"noreglladdr6"`
			Noregrecords      string `xml:"noregrecords"`
			Txtsupport        string `xml:"txtsupport"`
			Cacheflush        string `xml:"cacheflush"`
			LocalZoneType     string `xml:"local_zone_type"`
			OutgoingInterface string `xml:"outgoing_interface"`
			EnableWpad        string `xml:"enable_wpad"`
		} `xml:"general" json:"general,omitempty"`
		Advanced struct {
			Text                      string `xml:",chardata" json:"text,omitempty"`
			Hideidentity              string `xml:"hideidentity"`
			Hideversion               string `xml:"hideversion"`
			Prefetch                  string `xml:"prefetch"`
			Prefetchkey               string `xml:"prefetchkey"`
			Dnssecstripped            string `xml:"dnssecstripped"`
			Aggressivensec            string `xml:"aggressivensec"`
			Serveexpired              string `xml:"serveexpired"`
			Serveexpiredreplyttl      string `xml:"serveexpiredreplyttl"`
			Serveexpiredttl           string `xml:"serveexpiredttl"`
			Serveexpiredttlreset      string `xml:"serveexpiredttlreset"`
			Serveexpiredclienttimeout string `xml:"serveexpiredclienttimeout"`
			Qnameminstrict            string `xml:"qnameminstrict"`
			Extendedstatistics        string `xml:"extendedstatistics"`
			Logqueries                string `xml:"logqueries"`
			Logreplies                string `xml:"logreplies"`
			Logtagqueryreply          string `xml:"logtagqueryreply"`
			Logservfail               string `xml:"logservfail"`
			Loglocalactions           string `xml:"loglocalactions"`
			Logverbosity              string `xml:"logverbosity"`
			Valloglevel               string `xml:"valloglevel"`
			Privatedomain             string `xml:"privatedomain"`
			Privateaddress            string `xml:"privateaddress"`
			Insecuredomain            string `xml:"insecuredomain"`
			Msgcachesize              string `xml:"msgcachesize"`
			Rrsetcachesize            string `xml:"rrsetcachesize"`
			Outgoingnumtcp            string `xml:"outgoingnumtcp"`
			Incomingnumtcp            string `xml:"incomingnumtcp"`
			Numqueriesperthread       string `xml:"numqueriesperthread"`
			Outgoingrange             string `xml:"outgoingrange"`
			Jostletimeout             string `xml:"jostletimeout"`
			Discardtimeout            string `xml:"discardtimeout"`
			Cachemaxttl               string `xml:"cachemaxttl"`
			Cachemaxnegativettl       string `xml:"cachemaxnegativettl"`
			Cacheminttl               string `xml:"cacheminttl"`
			Infrahostttl              string `xml:"infrahostttl"`
			Infrakeepprobing          string `xml:"infrakeepprobing"`
			Infracachenumhosts        string `xml:"infracachenumhosts"`
			Unwantedreplythreshold    string `xml:"unwantedreplythreshold"`
		} `xml:"advanced" json:"advanced,omitempty"`
		Acls struct {
			Text          string `xml:",chardata" json:"text,omitempty"`
			DefaultAction string `xml:"default_action"`
		} `xml:"acls" json:"acls,omitempty"`
		Dnsbl struct {
			Text       string `xml:",chardata" json:"text,omitempty"`
			Enabled    string `xml:"enabled"`
			Safesearch string `xml:"safesearch"`
			Type       string `xml:"type"`
			Lists      string `xml:"lists"`
			Whitelists string `xml:"whitelists"`
			Blocklists string `xml:"blocklists"`
			Wildcards  string `xml:"wildcards"`
			Address    string `xml:"address"`
			Nxdomain   string `xml:"nxdomain"`
		} `xml:"dnsbl" json:"dnsbl,omitempty"`
		Forwarding struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Enabled string `xml:"enabled"`
		} `xml:"forwarding" json:"forwarding,omitempty"`
		Dots    string `xml:"dots"`
		Hosts   string `xml:"hosts"`
		Aliases string `xml:"aliases"`
		Domains string `xml:"domains"`
	} `xml:"unboundplus" json:"unboundplus,omitempty"`
	Wireguard struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		General struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
			Enabled string `xml:"enabled"`
		} `xml:"general" json:"general,omitempty"`
		Server struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
			Servers struct {
				Text   string `xml:",chardata" json:"text,omitempty"`
				Server struct {
					Text          string `xml:",chardata" json:"text,omitempty"`
					UUID          string `xml:"uuid,attr" json:"uuid,omitempty"`
					Enabled       string `xml:"enabled"`
					Name          string `xml:"name"`
					Instance      string `xml:"instance"`
					Pubkey        string `xml:"pubkey"`
					Privkey       string `xml:"privkey"`
					Port          string `xml:"port"`
					Mtu           string `xml:"mtu"`
					DNS           string `xml:"dns"`
					Tunneladdress string `xml:"tunneladdress"`
					Disableroutes string `xml:"disableroutes"`
					Gateway       string `xml:"gateway"`
					Peers         string `xml:"peers"`
				} `xml:"server" json:"server,omitempty"`
			} `xml:"servers" json:"servers,omitempty"`
		} `xml:"server" json:"server,omitempty"`
		Client struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
			Clients struct {
				Text   string `xml:",chardata" json:"text,omitempty"`
				Client struct {
					Text          string `xml:",chardata" json:"text,omitempty"`
					UUID          string `xml:"uuid,attr" json:"uuid,omitempty"`
					Enabled       string `xml:"enabled"`
					Name          string `xml:"name"`
					Pubkey        string `xml:"pubkey"`
					Psk           string `xml:"psk"`
					Tunneladdress string `xml:"tunneladdress"`
					Serveraddress string `xml:"serveraddress"`
					Serverport    string `xml:"serverport"`
					Keepalive     string `xml:"keepalive"`
				} `xml:"client" json:"client,omitempty"`
			} `xml:"clients" json:"clients,omitempty"`
		} `xml:"client" json:"client,omitempty"`
	} `xml:"wireguard" json:"wireguard,omitempty"`
	Hasync struct {
		Text            string `xml:",chardata" json:"text,omitempty"`
		Version         string `xml:"version,attr" json:"version,omitempty"`
		Disablepreempt  string `xml:"disablepreempt"`
		Disconnectppps  string `xml:"disconnectppps"`
		Pfsyncinterface string `xml:"pfsyncinterface"`
		Pfsyncpeerip    string `xml:"pfsyncpeerip"`
		Pfsyncversion   string `xml:"pfsyncversion"`
		Synchronizetoip string `xml:"synchronizetoip"`
		Username        string `xml:"username"`
		Password        string `xml:"password"`
		Syncitems       string `xml:"syncitems"`
	} `xml:"hasync" json:"hasync,omitempty"`
	Ifgroups struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
	} `xml:"ifgroups" json:"ifgroups,omitempty"`
	Gifs struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Gif     string `xml:"gif"`
	} `xml:"gifs" json:"gifs,omitempty"`
	Gres struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Gre     string `xml:"gre"`
	} `xml:"gres" json:"gres,omitempty"`
	Laggs struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Lagg    string `xml:"lagg"`
	} `xml:"laggs" json:"laggs,omitempty"`
	Virtualip struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Vip     string `xml:"vip"`
	} `xml:"virtualip" json:"virtualip,omitempty"`
	Vlans struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Vlan    string `xml:"vlan"`
	} `xml:"vlans" json:"vlans,omitempty"`
	Openvpn      string `xml:"openvpn"`
	Staticroutes struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Route   string `xml:"route"`
	} `xml:"staticroutes" json:"staticroutes,omitempty"`
	Bridges struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Bridged string `xml:"bridged"`
	} `xml:"bridges" json:"bridges,omitempty"`
	Ppps struct {
		Text string `xml:",chardata" json:"text,omitempty"`
		Ppp  string `xml:"ppp"`
	} `xml:"ppps" json:"ppps,omitempty"`
	Wireless struct {
		Text  string `xml:",chardata" json:"text,omitempty"`
		Clone string `xml:"clone"`
	} `xml:"wireless" json:"wireless,omitempty"`
	Ca      string `xml:"ca"`
	Dhcpdv6 string `xml:"dhcpdv6"`
	Cert    struct {
		Text  string `xml:",chardata" json:"text,omitempty"`
		Refid string `xml:"refid"`
		Descr string `xml:"descr"`
		Crt   string `xml:"crt"`
		Prv   string `xml:"prv"`
	} `xml:"cert" json:"cert,omitempty"`
	Routes struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Route   string `xml:"route"`
	} `xml:"routes" json:"routes,omitempty"`
	UnboundDNS struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Unbound string `xml:"unbound"`
	} `xml:"unbound" json:"unbound,omitempty"`
	Created string `xml:"created,omitempty"`
	Updated string `xml:"updated,omitempty"`
}

// Constructor functions

// NewOpnsense creates a new Opnsense configuration with properly initialized slices.
func NewOpnsense() *Opnsense {
	return &Opnsense{
		Sysctl: make([]SysctlItem, 0),
		Filter: Filter{
			Rule: make([]Rule, 0),
		},
		LoadBalancer: LoadBalancer{
			MonitorType: make([]MonitorType, 0),
		},
		System: System{
			Group: make([]Group, 0),
			User:  make([]User, 0),
		},
		Interfaces: Interfaces{
			Items: make(map[string]Interface),
		},
		Dhcpd: Dhcpd{
			Items: make(map[string]DhcpdInterface),
		},
	}
}

// Helper methods for Opnsense

// Hostname returns the configured hostname from the system configuration.
// This is a convenience method that extracts the hostname field from the nested System struct.
//
// Example:
//
//	hostname := config.Hostname()
//	fmt.Printf("Firewall hostname: %s\n", hostname)
func (o *Opnsense) Hostname() string {
	return o.System.Hostname
}

// InterfaceByName returns a network interface by its interface name (e.g., "em0", "igb0").
// It searches through all interfaces in the map-based Interfaces struct and returns a pointer
// to the matching interface, or nil if no interface with the given name is found.
//
// Parameters:
//   - name: The interface name to search for (e.g., "em0", "igb0", "vtnet0")
//
// Returns:
//   - *Interface: Pointer to the matching interface, or nil if not found
//
// Example:
//
//	iface := config.InterfaceByName("em0")
//	if iface != nil {
//		fmt.Printf("Interface %s has IP: %s\n", iface.If, iface.IPAddr)
//	}
func (o *Opnsense) InterfaceByName(name string) *Interface {
	for _, iface := range o.Interfaces.Items {
		if iface.If == name {
			return &iface
		}
	}
	return nil
}

// FilterRules returns a slice of all firewall filter rules configured in the system.
// This provides direct access to the firewall rules for analysis, processing, or iteration.
//
// Returns:
//   - []Rule: Slice of all firewall rules, may be empty if no rules are configured
//
// Example:
//
//	rules := config.FilterRules()
//	fmt.Printf("Found %d firewall rules\n", len(rules))
//	for i, rule := range rules {
//		fmt.Printf("Rule %d: %s %s on %s\n", i+1, rule.Type, rule.IPProtocol, rule.Interface)
//	}
func (o *Opnsense) FilterRules() []Rule {
	return o.Filter.Rule
}

// SystemConfig returns the system configuration grouped by functionality.
// This groups system-level settings including core system configuration and sysctl tunables
// into a single structured object for easier access and processing.
//
// Returns:
//   - SystemConfig: Grouped system configuration containing System and Sysctl fields
//
// Example:
//
//	sysConfig := config.SystemConfig()
//	fmt.Printf("Hostname: %s\n", sysConfig.System.Hostname)
//	fmt.Printf("Sysctl items: %d\n", len(sysConfig.Sysctl))
func (o *Opnsense) SystemConfig() SystemConfig {
	return SystemConfig{
		System: o.System,
		Sysctl: o.Sysctl,
	}
}

// NetworkConfig returns the network configuration grouped by functionality.
// This provides a focused view of network-related settings including all interface configurations.
//
// Returns:
//   - NetworkConfig: Grouped network configuration containing interface definitions
//
// Example:
//
//	netConfig := config.NetworkConfig()
//	fmt.Printf("WAN IP: %s\n", netConfig.Interfaces.Wan.IPAddr)
//	fmt.Printf("LAN IP: %s\n", netConfig.Interfaces.Lan.IPAddr)
func (o *Opnsense) NetworkConfig() NetworkConfig {
	return NetworkConfig{
		Interfaces: o.Interfaces,
	}
}

// SecurityConfig returns the security configuration grouped by functionality.
// This groups security-related settings including firewall rules and NAT configuration
// into a single structured object for security analysis and processing.
//
// Returns:
//   - SecurityConfig: Grouped security configuration containing NAT and Filter settings
//
// Example:
//
//	secConfig := config.SecurityConfig()
//	fmt.Printf("NAT mode: %s\n", secConfig.Nat.Outbound.Mode)
//	fmt.Printf("Filter rules: %d\n", len(secConfig.Filter.Rule))
func (o *Opnsense) SecurityConfig() SecurityConfig {
	return SecurityConfig{
		Nat:    o.Nat,
		Filter: o.Filter,
	}
}

// ServiceConfig returns the service configuration grouped by functionality.
// This groups all service-related settings including DHCP, DNS, SNMP, monitoring,
// load balancing, and time services into a single structured object.
//
// Returns:
//   - ServiceConfig: Grouped service configuration containing all service settings
//
// Example:
//
//	svcConfig := config.ServiceConfig()
//	if lanDhcp, ok := svcConfig.Dhcpd.Get("lan"); ok && lanDhcp.Range.From != "" {
//		fmt.Printf("DHCP range: %s - %s\n", lanDhcp.Range.From, lanDhcp.Range.To)
//	}
//	fmt.Printf("SNMP community: %s\n", svcConfig.Snmpd.ROCommunity)
func (o *Opnsense) ServiceConfig() ServiceConfig {
	return ServiceConfig{
		Dhcpd:        o.Dhcpd,
		Unbound:      o.Unbound,
		Snmpd:        o.Snmpd,
		Rrd:          o.Rrd,
		LoadBalancer: o.LoadBalancer,
		Ntpd:         o.Ntpd,
		SSH:          o.System.SSH,
	}
}
