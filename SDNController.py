from datetime import datetime, timedelta

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet
from ryu.lib.packet import packet, ipv6, ethernet, ether_types, icmpv6, tcp, udp

from controller.Engine import SyntaxAnalyser, TrustLevel, Action, AnalysisResult
from database.domain import Databases

# ###### Database Connections ###### #
from utils.ipv6_utils import generate_random_mac, generate_llu_ipv6

routing = Databases.routing
logs = Databases.logs
flows = Databases.flows
rules = Databases.rules

# ###### Analysing and Normalising Engine ###### #
syn_anal = SyntaxAnalyser()


# ================================================================================================== #
# Janus Controller is a Ryu application and therefor 'ryu.base.app_manager.Ryuapp' is its base class #
# ================================================================================================== #
class JanusController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]  # Use OpenFlow 1.3.x, because most stable OFP with Ryu

    def __init__(self, *args, **kwargs):
        super(JanusController, self).__init__(*args, **kwargs)
        self.wan_port = 1  # This is the port that connects the protected network to the 'internet'
        self.temporary_mac_id = None
        self.hosts = []
        self.mac_to_port = {}
        self.ethertypes_to_discard = [
            ether_types.ETH_TYPE_ARP,
            ether_types.ETH_TYPE_IP,
            ether_types.ETH_TYPE_LLDP
        ]
        self.ndp_messages = [
            icmpv6.ND_NEIGHBOR_ADVERT,
            icmpv6.ND_ROUTER_ADVERT,
            icmpv6.ND_NEIGHBOR_SOLICIT,
            icmpv6.ND_ROUTER_SOLICIT,
            icmpv6.ND_REDIREC
        ]

        logs.clear_table()
        routing.clear_table()
        flows.clear_table()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """ Event called when there are configuration changes. This method will handle them. """

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Will load the 'Blacklist', which is a set of blocking rules
        self.load_blocking_rules(datapath)

        # Will send an ECHO_REQUEST as soon as it connects to ovs. This will trigger NDP NS messages from hosts
        self.ping_connected_hosts(datapath, self.wan_port)

    def ping_connected_hosts(self, datapath, wan_port):
        """
        This function will send an ICMPv6 ECHO REQUEST message to all the nodes of protected network.
        That will in turn, trigger a Neighbor Solicitation message to be received and the IPv6 destination
        address, will be the randomly generated LLU address of Janus.
        :param datapath: The datapath (represents the device used as a traffic normaliser (Janus))
        :param wan_port:  The port to send a message from. Use this as the in_port, to exclude from multicast
        """
        # Construct L2 header
        src_mac = generate_random_mac()  # Generated randomly (can be seen that it is not factory default)
        dst_mac = '33:33:ff:ff:ff:ff'  # This is a multicast L2 address
        self.temporary_mac_id = "33:33:ff" + src_mac[-9:]
        layer2 = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_IPV6)

        # Construct L3 header
        ip6_dst = 'ff02::1'  # well known multicast L3 address, as defined by IANA
        ip6_src = generate_llu_ipv6(src_mac)  # IPv6 Link Local Unicast address
        layer3 = ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6, src=ip6_src, dst=ip6_dst)

        # Construct l4 header
        icmpv6_type = icmpv6.ICMPV6_ECHO_REQUEST
        layer4 = icmpv6.icmpv6(type_=icmpv6_type, code=0, csum=0, data=icmpv6.echo())

        # Create packet
        pkt = packet.Packet()
        # layer 1 is automatically generated when packet.serialize() is called
        pkt.add_protocol(layer2)
        pkt.add_protocol(layer3)
        pkt.add_protocol(layer4)

        # Send packet to multicast addresses in protected network
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  actions=actions, data=data, in_port=wan_port)

        datapath.send_msg(out)

    @staticmethod
    def _validate_rule(**rule):

        existing_fields = rule.keys()

        layer3_fields = ['ipv6_dst', 'ipv6_src']
        layer4_fields = ['tcp_src', 'tcp_dst', 'udp_src', 'udp_dst', 'icmpv6_type', 'icmpv6_code']
        layer3_required = 'eth_type'
        layer4_required = 'ip_proto'

        # Check if there are layer 3 fields. If there are, then check if the ethertype is provided,
        # otherwise this is invalid rule. Network-Layer fields, require the ethertype in the OpenFlow protocol
        for f in layer3_fields:
            if f in existing_fields:
                if layer3_required not in existing_fields:
                    return False

        # Check if there are layer 4 fields. If there are, then check if the associated protocol code is provided,
        # otherwise this is invalid rule. Transport-Layer fields, require the Transport-Layer protocol code.
        for f in layer4_fields:
            if f in existing_fields:
                if layer4_required not in existing_fields or layer3_required not in existing_fields:
                    return False

        return True

    def block_flow(self, datapath, match, idle_timeout=0, hard_timeout=0, **record_dict):
        priority = 10
        actions = ''  # empty string means drop packet
        self.add_flow(datapath, priority, match, actions, idle_timeout, hard_timeout, **record_dict)

    def load_blocking_rules(self, datapath):
        """ The dictionary must have all required fields """
        if rules.new_ruleset_exists():
            rules_dict = rules.get_ruleset()
            rules.mark_ruleset(marking=rules.up_to_date)
        else:
            return

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        for rule in rules_dict['blacklist']:
            description = rule.pop('description')
            rule_action = rule.pop('action')
            if rule_action == 'drop':
                actions = ''  # no action, by default means drop packet in ryu
            else:
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            priority = rule.pop('priority')
            if self._validate_rule(**rule):
                print("Adding rule: {}".format(description))
                match = parser.OFPMatch(**rule)
                self.add_flow(datapath, priority, match, actions)
                print("Rule added.")
            else:
                print("Could not add rule: {}".format(description))

    @staticmethod
    def add_flow(datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, **record_dict):
        """
        This method will insert a flow into the Open vSwitch (or some other SDN switch) that this controller manages.
        :param datapath: The datapath device. (The traffic-normalizer, namely Janus)
        :param priority: The priority of this flow
        :param match: The fields to match packets against
        :param actions: What to do
        :param idle_timeout: Time (in seconds) that the flow will expire in, but if a match is made, this is refreshed.
        :param hard_timeout: Time (in seconds) that this flow will expire in.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)  # Send the flow mod to the switch (and the switch will insert it)

        expires_at = datetime.now() + timedelta(seconds=hard_timeout)  # add a value that if passed, the flow expires
        record_dict = record_dict.copy()
        record_dict['expiration_time'] = expires_at
        if priority is not 0:
            flows.insert(**record_dict)  # insert flow in database

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Handle packet_in events. These are created whenever a packet is propagated from the
        SDN switch to the controller, because there was a table-miss
        (No flow could be matched to it from the pipeline). Pipeline and flow buckets are in OFP spec 1.3.1
        :param ev: Represents the event that was triggered. It contains all the data related.
        This method will pass the message to the analyser and the packet will either be forwarded or blocked
        """
        # EVENT & PACKET DATA
        msg = ev.msg  # Get the message that contains all the data for the event, to initialise necessary variables
        datapath = msg.datapath  # The Janus device (SDN switch) that generated this event. {in case of multiple Janus}
        ofproto = datapath.ofproto  # The OpenFlow protocol that the device uses (to use appropriate library)
        parser = datapath.ofproto_parser  # The OpenFlow protocol parser
        in_port = msg.match['in_port']  # The port of Janus from whence the packet came
        dpid = datapath.id  # The id of the Janus device that triggered this event
        pkt = packet.Packet(msg.data)  # The packet that triggered the event (All headers included)
        eth_pkt = pkt.protocols[0]  # Get L2 packet (Link-layer).
        ethertype = eth_pkt.ethertype  # The type indicates if this is an IPv4, IPv6, LLDP packet, etc.

        self.load_blocking_rules(datapath)  # Check if a new rule was added to the blacklist

        match_dict = {}  # Contains all the fields that will be added in the flow
        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src

        # L2 match
        match_dict['in_port'] = in_port
        match_dict['eth_type'] = ethertype
        match_dict['eth_src'] = src_mac
        match_dict['eth_dst'] = dst_mac

        # Use dictionary of current device (supports more than 1 Janus devices)
        # Add the source mac address of the packet as the key that identifies which port this address is connected to
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # ****Silently discard these ether types (IPv4, ARP, etc)**** #
        if ethertype in self.ethertypes_to_discard:
            return

        # Simply forward NDP messages without further actions
        if pkt.protocols[1].nxt == inet.IPPROTO_ICMPV6:
            msg_type = pkt.protocols[2].type_
            if msg_type in self.ndp_messages:
                # Check for replies to Janus' ping and add host addresses to RT
                if (dst_mac == self.temporary_mac_id) and (in_port is not self.wan_port):
                    ipv6_pkt = pkt.protocols[1]
                    if ipv6_pkt.src not in self.hosts:
                        self.hosts.append(ipv6_pkt.src)
                        routing.insert_address(ipv6_pkt.src)
                        print("The node at \""+ipv6_pkt.src+"\" reacted to probing.")
                else:
                    data = msg.data
                    # if the destination mac address is already learned, do something and forward the packet
                    if dst_mac in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst_mac]
                    # If mac is not known, then flood
                    else:
                        out_port = ofproto.OFPP_FLOOD

                    # construct action list.
                    actions = [parser.OFPActionOutput(out_port)]
                    out = parser.OFPPacketOut(datapath=datapath,
                                              buffer_id=msg.buffer_id,
                                              actions=actions,
                                              data=data,
                                              in_port=in_port)
                    datapath.send_msg(out)
                    print("Forwarded NDP message")
                return  # after processing NDP, return

        # Check if packet is IPv6
        if ethertype == ether_types.ETH_TYPE_IPV6:
            ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
            # Send packet to the Engine for analysis/normalisation
            # Analysis results structure -> [TrustLevel, Action, AnalysisResult, ipv6.ipv6]
            analysis_results = syn_anal.analyse(ipv6_pkt, in_port, self.wan_port, self.hosts)
            # Forged results to avoid overhead of analysis phase (TESTING)
            # analysis_results = [TrustLevel.trusted, Action.forward, AnalysisResult.passed, ipv6_pkt]
            trust = analysis_results[0]
            action = analysis_results[1]
            justification = analysis_results[2]
            ipv6_pkt = analysis_results[3]
            # Replace old ipv6 header, with the returned ipv6 header
            pkt.protocols[1] = ipv6_pkt

            l4_protocol = "Unsupported/None"
            print(trust.value)
            print(action.value)
            print(justification.value)

            # Create match fields with normalized packet, to avoid installing flow for ambiguous values
            match_dict['ipv6_src'] = ipv6_pkt.src
            match_dict['ipv6_dst'] = ipv6_pkt.dst

            # If the packet does not use TCP for example, the method get_protocol(tcp) will return 'null'
            icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

            # Check if the upper layer (L4) protocol is ICMPv6, TCP, or UDP
            if icmpv6_pkt:
                match_dict['ip_proto'] = inet.IPPROTO_ICMPV6
                match_dict['icmpv6_type'] = icmpv6_pkt.type_
                match_dict['icmpv6_code'] = icmpv6_pkt.code
                l4_protocol = "ICMPv6"
            elif tcp_pkt:
                match_dict['ip_proto'] = inet.IPPROTO_TCP
                match_dict['tcp_src'] = tcp_pkt.src_port
                match_dict['tcp_dst'] = tcp_pkt.dst_port
                l4_protocol = "TCP"
            elif udp_pkt:
                match_dict['ip_proto'] = inet.IPPROTO_UDP
                match_dict['udp_src'] = udp_pkt.src_port
                match_dict['udp_dst'] = udp_pkt.dst_port
                l4_protocol = "UDP"

            # Add record to logs
            logs.add_record(src_mac=src_mac, dst_mac=dst_mac, src_ip=ipv6_pkt.src, dst_ip=ipv6_pkt.dst,
                            protocol=l4_protocol, trust_level=trust.value, action=action.value,
                            justification=justification.value)

            # create the OFP match fields, in order to install flow mod
            match = parser.OFPMatch(**match_dict)

            # Log packet details
            self.logger.info("packet at PORT\"{0}\"\nFrom: {1}\nTo: {2}\n".format(in_port, src_mac, dst_mac))

            # if the destination mac address is already learned, do something and forward the packet
            if dst_mac in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst_mac]
            # If mac is not known, then flood
            else:
                out_port = ofproto.OFPP_FLOOD

            # construct action list.
            actions = [parser.OFPActionOutput(out_port)]

            record_dict = match_dict.copy()
            record_dict['l4_protocol'] = l4_protocol
            record_dict['action'] = action.name

            # Check action and if return or drop, then return from function
            if action == Action.drop:
                self.logger.info(
                    "Packet at PORT\"{0}\" was dropped.\nFrom: {1}\nTo: {2}\n".format(in_port, src_mac, dst_mac)
                )
                return  # return, which implicitly means that the packet is dropped

            # Block flow for 8 hours
            elif action == Action.block:
                self.block_flow(datapath, match, hard_timeout=28800, **record_dict)
                self.logger.info(
                    "Packets for flow blocked!\nFrom: {0}\nTo: {1}\n".format(src_mac, dst_mac)
                )
                return

            # Insert trusted flow for 10 minutes
            elif (out_port != ofproto.OFPP_FLOOD) and (trust == TrustLevel.trusted):
                self.add_flow(datapath, 1, match, actions, hard_timeout=600, **record_dict)
            else:
                print("Multicasting..")

            # finally, create a new packet and serialize it
            new_pkt = packet.Packet()
            new_pkt.add_protocol(pkt.protocols[0])
            new_pkt.add_protocol(pkt.protocols[1])
            new_pkt.add_protocol(pkt.protocols[2])
            new_pkt.serialize()

            data = new_pkt.data
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      actions=actions,
                                      data=data,
                                      in_port=in_port)
            datapath.send_msg(out)
            return
