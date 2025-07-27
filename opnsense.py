#!/usr/bin/env python3
import re
from datetime import datetime, timezone
from pprint import pformat

from util import DataNode, hasattr_r


class OpnSenseNode(DataNode):
    def __init__(self, parent=None):
        self._parent = parent

    def __getattr__(self, name):
        # This trick hides PyLint error messages...
        return super().__getattribute__(name)

    def __call__(self, content):
        pass # discard content

    def __repr__(self):
        return pformat(self.data)

    def __str__(self):
        return str(self.data)

    @property
    def parents(self):
        obj = self
        while obj._parent:
            yield obj._parent
            obj = obj._parent

    @property
    def rootdoc(self):
        return list(self.parents)[-1]

class OpnSenseString(OpnSenseNode):
    string = None

    def __call__(self, content):
        self.string = str(content)

    @property
    def data(self):
        return self.string

class OpnSenseInteger(OpnSenseNode):
    integer = None

    def __call__(self, content):
        self.integer = int(content)

    @property
    def data(self):
        return self.integer

class OpnSenseTimestamp(OpnSenseNode):
    datetime = None

    def __call__(self, content):
        self.datetime = datetime.fromtimestamp(float(content), timezone.utc)

    @property
    def data(self):
        return self.datetime

class OpnSenseInterfacesNode(OpnSenseNode):
    def __getattr__(self, name):
        if name.startswith('_opt'):
            return self._opt
        return super().__getattribute__(name)

class OpnSenseFlag(OpnSenseNode):
    def __call__(self, content):
        self.value = int(content)
    @property
    def data(self):
        if self.value is 0:
            return None
        else:
            return True

class OpnSenseAliasString(OpnSenseString):
    @property
    def data(self):
        data = super().data
        if hasattr_r(self.rootdoc.opnsense, 'OPNsense.Firewall.Alias.aliases.alias'):
            for alias in self.rootdoc.opnsense.OPNsense.Firewall.Alias.aliases.alias:
                if alias.name.string == data:
                    return {'alias': alias.data}
        return data

class OpnSensePortString(OpnSenseAliasString):
    PORT_STRING = re.compile(r'(\d+((:|-)(\d+))?|[a-zA-Z0-9_]+)')

    def __call__(self, content):
        super().__call__(content)
        if self.PORT_STRING.fullmatch(self.string) is None:
            raise RuntimeError("Invalid port string: {}".format(self.string))

class OpnSenseChange(OpnSenseNode):
    _time = OpnSenseTimestamp
    _username = OpnSenseString

class OpnSenseRange(OpnSenseNode):
    _from = OpnSenseString
    _to = OpnSenseString

class OpnSenseSysCtlItem(OpnSenseNode):
    _tunable = OpnSenseString
    _value = OpnSenseString
    _descr = OpnSenseString

class OpnSenseSysCtl(OpnSenseNode):
    _item = [OpnSenseSysCtlItem]

class OpnSenseStaticMap(OpnSenseNode):
    _mac = OpnSenseString
    _ipaddr = OpnSenseString
    _hostname = OpnSenseString

class OpnSenseDhcpdItem(OpnSenseNode):
    _range = [OpnSenseRange]
    _staticmap = [OpnSenseStaticMap]
    _defaultleasetime = OpnSenseInteger
    _maxleasetime = OpnSenseInteger
    _enable = OpnSenseFlag

class OpnSenseDhcpd(OpnSenseInterfacesNode):
    _wan = OpnSenseDhcpdItem
    _lan = OpnSenseDhcpdItem
    _opt = OpnSenseDhcpdItem

class OpnSenseRuleAlias(OpnSenseString):
    @property
    def data(self):
        data = super().data
        for interface_name, interface_data in self.rootdoc.opnsense.interfaces.data.items():
            alias_name = data
            if alias_name.endswith('ip'):
                alias_name = alias_name[:-2]
            if interface_name == alias_name:
                interface_data['name'] = data
                return {'interface': interface_data}
        if hasattr_r(self.rootdoc.opnsense, 'OPNsense.Firewall.Alias.aliases.alias'):
            for alias in self.rootdoc.opnsense.OPNsense.Firewall.Alias.aliases.alias:
                if alias.name.string == data:
                    return {'alias': alias.data}
        return data

class OpnSenseRuleInterface(OpnSenseString):
    @property
    def data(self):
        data = super().data
        if data is None:
            return data
        data_list = []
        for iface_name in data.split(','):
            found = False
            for interface_name, interface_data in self.rootdoc.opnsense.interfaces.data.items():
                if interface_name == iface_name:
                    interface_data['name'] = iface_name
                    data_list.append({'interface': interface_data})
                    found = True
                    break
            if not found:
                data_list.append(iface_name)
        return data_list

class OpnSenseRuleLocation(OpnSenseNode):
    _any = OpnSenseNode
    _network = OpnSenseRuleAlias
    _address = OpnSenseRuleAlias
    _port = OpnSensePortString
    _not = OpnSenseFlag

class OpnSenseFilterRule(OpnSenseNode):
    _id = OpnSenseString
    _tracker = OpnSenseString
    _type = OpnSenseString
    _interface = OpnSenseRuleInterface
    _ipprotocol = OpnSenseString
    _tag = OpnSenseString
    _tagged = OpnSenseString
    _max = OpnSenseString
    _max_src_nodes = OpnSenseString
    _max_src_conn = OpnSenseString
    _max_src_states = OpnSenseString
    _statetimeout = OpnSenseString
    _statetype = OpnSenseString
    _os = OpnSenseString
    _protocol = OpnSenseString
    _source = OpnSenseRuleLocation
    _destination = OpnSenseRuleLocation
    _descr = OpnSenseString
    _associated_rule_id = OpnSenseString
    _created = OpnSenseChange
    _updated = OpnSenseChange
    _disabled = OpnSenseFlag

class OpnSenseFilter(OpnSenseNode):
    _rule = [OpnSenseFilterRule]

class OpnSenseNatOutboundRule(OpnSenseNode):
    _interface = OpnSenseRuleInterface
    _source = OpnSenseRuleLocation
    _dstport = OpnSensePortString
    _target = OpnSenseString
    _targetip = OpnSenseString
    _targetip_subnet = OpnSenseString
    _destination = OpnSenseRuleLocation
    _natport = OpnSensePortString
    _staticnatport = OpnSensePortString
    _descr = OpnSenseString
    _created = OpnSenseChange
    _updated = OpnSenseChange
    _disabled = OpnSenseFlag

class OpnSenseNatOutbound(OpnSenseNode):
    _mode = OpnSenseString
    _rule = [OpnSenseNatOutboundRule]

class OpnSenseNatRule(OpnSenseNode):
    _source = OpnSenseRuleLocation
    _destination = OpnSenseRuleLocation
    _protocol = OpnSenseString
    _target = OpnSenseRuleAlias
    _local_port = OpnSensePortString
    _interface = OpnSenseRuleInterface
    _descr = OpnSenseString
    _associated_rule_id = OpnSenseString
    _created = OpnSenseChange
    _updated = OpnSenseChange
    _disabled = OpnSenseFlag

class OpnSenseNat(OpnSenseNode):
    _outbound = OpnSenseNatOutbound
    _rule = [OpnSenseNatRule]

class OpnSenseAlias(OpnSenseNode):
    _name = OpnSenseString
    _type = OpnSenseString
    _content = OpnSenseString
    _descr = OpnSenseString
    _detail = OpnSenseString

class OpnSenseAliases(OpnSenseNode):
    _alias = [OpnSenseAlias]

class OpnSenseFirewallAlias(OpnSenseNode):
    _aliases = OpnSenseAliases

class OpnSenseFirewall(OpnSenseNode):
    _Alias = OpnSenseFirewallAlias

class OpnSenseOPNsense(OpnSenseNode):
    _Firewall = OpnSenseFirewall

class OpnSenseDnsMasqDomainOverride(OpnSenseNode):
    _domain = OpnSenseString
    _ip = OpnSenseString
    _idx = OpnSenseInteger
    _descr = OpnSenseString

class OpnSenseDnsMasqHostAliasItem(OpnSenseNode):
    _host = OpnSenseString
    _domain = OpnSenseString
    _description = OpnSenseString

class OpnSenseDnsMasqHostAliases(OpnSenseNode):
    _item = [OpnSenseDnsMasqHostAliasItem]

class OpnSenseDnsMasqHost(OpnSenseNode):
    _host = OpnSenseString
    _domain = OpnSenseString
    _ip = OpnSenseString
    _descr = OpnSenseString
    _aliases = OpnSenseDnsMasqHostAliases

class OpnSenseDnsMasq(OpnSenseNode):
    _enable = OpnSenseFlag
    _reqdhcp = OpnSenseFlag
    _reqdhcpstatic = OpnSenseFlag
    _strict_order = OpnSenseFlag
    _custom_options = OpnSenseString
    _interface = OpnSenseRuleInterface
    _hosts = [OpnSenseDnsMasqHost]
    _domainoverrides = [OpnSenseDnsMasqDomainOverride]

class OpnSenseOpenVpnClient(OpnSenseNode):
    _vpnid = OpnSenseInteger
    _auth_user = OpnSenseString
    _mode = OpnSenseString
    _protocol = OpnSenseString
    _dev_mode = OpnSenseString
    _interface = OpnSenseRuleInterface
    _ipaddr = OpnSenseString
    _local_port = OpnSenseInteger
    _server_addr = OpnSenseString
    _server_port = OpnSenseInteger
    _crypto = OpnSenseString
    _digest = OpnSenseString
    _tunnel_network = OpnSenseString
    _remote_network = OpnSenseString
    _local_network = OpnSenseString
    _topology = OpnSenseString
    _description = OpnSenseString
    _custom_options = OpnSenseString

class OpnSenseOpenVpnServer(OpnSenseNode):
    _vpnid = OpnSenseInteger
    _mode = OpnSenseString
    _authmode = OpnSenseString
    _protocol = OpnSenseString
    _dev_mode = OpnSenseString
    _interface = OpnSenseRuleInterface
    _ipaddr = OpnSenseString
    _local_port = OpnSenseInteger
    _crypto = OpnSenseString
    _digest = OpnSenseString
    _tunnel_network = OpnSenseString
    _remote_network = OpnSenseString
    _local_network = OpnSenseString
    _dynamic_ip = OpnSenseString
    _pool_enable = OpnSenseString
    _topology = OpnSenseString
    _description = OpnSenseString
    _custom_options = OpnSenseString

class OpnSenseOpenVpnCsc(OpnSenseNode):
    _server_list = OpnSenseString
    _common_name = OpnSenseString
    _description = OpnSenseString
    _tunnel_network = OpnSenseString

class OpnSenseOpenVpn(OpnSenseNode):
    _openvpn_server = [OpnSenseOpenVpnServer]
    _openvpn_client = [OpnSenseOpenVpnClient]
    _openvpn_csc = [OpnSenseOpenVpnCsc]

class OpnSenseRoute(OpnSenseNode):
    _network = OpnSenseString
    _gateway = OpnSenseString
    _descr = OpnSenseString
    _disabled = OpnSenseFlag

class OpnSenseStaticRoutes(OpnSenseNode):
    _route = [OpnSenseRoute]

class OpnSenseGatewayItem(OpnSenseNode):
    _interface = OpnSenseRuleInterface
    _gateway = OpnSenseString
    _name = OpnSenseString
    _weight = OpnSenseInteger
    _ipprotocol = OpnSenseString
    _interval = OpnSenseInteger
    _alert_interval = OpnSenseInteger
    _descr = OpnSenseString
    _defaultgw = OpnSenseFlag

class OpnSenseGateways(OpnSenseNode):
    _gateway_item = [OpnSenseGatewayItem]

class OpnSenseVlan(OpnSenseNode):
    _vlanif = OpnSenseString
    _tag = OpnSenseInteger
    _if = OpnSenseString
    _descr = OpnSenseString

class OpnSenseVlans(OpnSenseNode):
    _vlan = [OpnSenseVlan]

class OpnSenseBridged(OpnSenseNode):
    _bridgeif = OpnSenseString
    _members = OpnSenseRuleInterface
    _descr = OpnSenseString

class OpnSenseBridges(OpnSenseNode):
    _bridged = [OpnSenseBridged]

class OpnSenseInterface(OpnSenseNode):
    _if = OpnSenseString
    _descr = OpnSenseString
    _ipaddr = OpnSenseString
    _subnet = OpnSenseString
    _enable = OpnSenseFlag

class OpnSenseInterfaces(OpnSenseInterfacesNode):
    _wan = OpnSenseInterface
    _lan = OpnSenseInterface
    _opt = OpnSenseInterface

class OpnSenseSyslog(OpnSenseNode):
    _nentries = OpnSenseInteger
    _logfilesize = OpnSenseInteger
    _remoteserver = OpnSenseString
    _remoteserver2 = OpnSenseString
    _remoteserver3 = OpnSenseString
    _sourceip = OpnSenseRuleInterface
    _ipproto = OpnSenseString
    _logall = OpnSenseFlag
    _enable = OpnSenseFlag

class OpnSenseSystem(OpnSenseNode):
    _optimization = OpnSenseString
    _hostname = OpnSenseString
    _domain = OpnSenseString
    _timeservers = OpnSenseString
    _timezone = OpnSenseString
    _language = OpnSenseString
    _dnsserver = [OpnSenseString]

class OpnSenseConfig(OpnSenseNode):
    #_version = OpnSenseString
    _system = OpnSenseSystem
    _interfaces = OpnSenseInterfaces
    _vlans = OpnSenseVlans
    _bridges = OpnSenseBridges
    _gateways = OpnSenseGateways
    _staticroutes = OpnSenseStaticRoutes
    _OPNsense = OpnSenseOPNsense
    _nat = OpnSenseNat
    _filter = OpnSenseFilter
    _dnsmasq = OpnSenseDnsMasq
    _dhcpd = OpnSenseDhcpd
    _openvpn = OpnSenseOpenVpn
    _syslog = OpnSenseSyslog
    _sysctl = OpnSenseSysCtl

class OpnSenseDocument(OpnSenseNode):
    _opnsense = OpnSenseConfig
