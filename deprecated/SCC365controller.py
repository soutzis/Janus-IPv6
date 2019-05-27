
# @author psoutzis

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import tcp, ethernet, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto as inet

import json

json_file = '/home/soutzis/PycharmProjects/JanusTopologies/practical3/rules.json'


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Create Mappings Table
        self.mac_to_port = {}
        self.tcp_connections_SYN = {}
        self.tcp_connections_SYNACK = {}
        self.anomalous_packets = {}
        self.firewalls = []
        self.forward_only = False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """ Handle Configuration Changes """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        print("Switch {} has joined".format(datapath.id))

        self.add_flow(datapath, 0, match, actions)
        self.match_from_json(json_file, datapath)  # Add flows based on json file

        ##
        # Check if there are any rules for the switch that has just joined the datapath
        # Be proactive where possible
        ##

    def _syn_flood_cm(self, datapath, parser, in_port, msg, raw_pkt):
        """
        This function implements an algorithm, that acts as a countermeasure against a SYN FLOOD attack.

        :param datapath: The datapath (switch instance)
        :param parser: The OF protocol parser
        :param in_port: The port where the packet was received
        :param msg: The ev.msg
        :param raw_pkt: The L1 packet (bits)

        This method will add the flow to the OVS IFF a connection has been established (3-way handshake).
        It will also log anomalous TCP packets and their sender.
        If a distinct sender has sent more than 20 anomalous packets, that sender's IP address is blocked for 1 minute.
        """
        dpid = datapath.id
        ofproto = datapath.ofproto

        # Variables that will be used to match a particular flow
        eth_pkt = raw_pkt.get_protocol(ethernet.ethernet)
        eth_dst = eth_pkt.dst
        eth_src = eth_pkt.src
        eth_type = eth_pkt.ethertype
        ipv4_pkt = raw_pkt.get_protocol(ipv4.ipv4)
        ipv4_src = ipv4_pkt.src
        ipv4_dst = ipv4_pkt.dst
        ip_proto = ipv4_pkt.proto
        tcp_pkt = raw_pkt.get_protocol(tcp.tcp)
        tcp_src = tcp_pkt.src_port
        tcp_dst = tcp_pkt.dst_port

        forward_only = False  # Flag that indicates to just forward a packet
        handshake_complete = False  # Flag that indicates that a 3way handshake is complete
        ignore_pkt = False  # Flag that indicates that the packet is anomalous

        # Record SYN packet sent (Check if only SYN flag is set)
        if tcp_pkt.has_flags(tcp.TCP_SYN) and not tcp_pkt.has_flags(tcp.TCP_ACK):
            # Add a tuple containing source ip, destination ip and the destination port number (receiver's port)
            self.tcp_connections_SYN[ipv4_src] = (ipv4_src, ipv4_dst, tcp_pkt.dst_port)
            forward_only = True  # Mark packet as forward-only
            print("----------------RECEIVED SYN-------------------")

        # Record SYNACK
        elif tcp_pkt.has_flags(tcp.TCP_SYN, tcp.TCP_ACK):
            # Check if the received packet is a response to a SYN. Compare with tuple in SYN dictionary if exists.
            if ipv4_dst in self.tcp_connections_SYN.keys():
                matching_tuple = (ipv4_dst, ipv4_src, tcp_pkt.src_port)
                print("------------MATCHED SYNACK WITH SYN-------------")
                # If the 2 tuples are identical, then mark as forward-only and insert this tuple in the SYN_ACK dict
                if self.tcp_connections_SYN[ipv4_dst] == matching_tuple:
                    forward_only = True
                    self.tcp_connections_SYNACK[ipv4_dst] = matching_tuple
            # If packet's destination ip address was not in SYN dict, then packet must be anomalous. Mark to ignore
            else:
                ignore_pkt = True

        # Complete 3-way handshake and add flows
        elif tcp_pkt.has_flags(tcp.TCP_ACK) and not tcp_pkt.has_flags(tcp.TCP_SYN):
            # Check if ACK packet is a response to a SYN_ACK
            if ipv4_src in self.tcp_connections_SYNACK.keys():
                matching_tuple = (ipv4_src, ipv4_dst, tcp_pkt.dst_port)
                # If the 2 tuples are identical, then mark as the handshake as complete
                if self.tcp_connections_SYNACK[ipv4_src] == matching_tuple:
                    handshake_complete = True
                    print("-----------------MATCHED ACK WITH SYNACK------------------")
                    del self.tcp_connections_SYNACK[ipv4_src]  # Now that handshake is complete, remove recorded SYN
                    del self.tcp_connections_SYN[ipv4_src]  # Now that handshake is complete, remove recorded SYNACK
            # If packet's source ip address was not in SYN_ACK dict, then packet must be anomalous. Mark to ignore
            else:
                ignore_pkt = True

        # IFF ignore_pkt flag is set, then return and drop this packet
        if ignore_pkt:
            # Log anomalous packet and host's source
            self.logger.warning("RECEIVED ANOMALOUS PACKET FROM HOST WITH IP: {}".format(ipv4_src))
            # IF source has sent an anomalous packet before, then:
            if ipv4_src in self.anomalous_packets.keys():
                # IF anomalous packets from source are more than 20, then add flow mod to block sender for a minute
                if self.anomalous_packets[ipv4_src] > 20:
                    action = ''
                    priority = 65535
                    timeout = 60
                    match = parser.OFPMatch(eth_type=eth_type, ipv4_src=ipv4_src)
                    self.add_flow(datapath, priority, match, action, hard_timeout=timeout)
                    print("{0} HAS BEEN BLOCKED FOR {1} SECONDS".format(ipv4_src, timeout))
                    self.anomalous_packets[ipv4_src] = 0  # Reset anomalous packet counter
                else:
                    self.anomalous_packets[ipv4_src] += 1  # Add +1 to anomalous packets from sender
            # If sender's address is not in anomalous packet dictionary, then insert a new entry
            else:
                self.anomalous_packets[ipv4_src] = 1
            # return from function (PACKET_IN SHOULD 'RETURN' IMMEDIATELY AFTER THIS)
            return

        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
            self.logger.info("PACKET OUT: Port %s", str(out_port))
        else:
            self.logger.info("PACKET OUT: Flooding")
            out_port = ofproto.OFPP_FLOOD

        # The action of sending a packet out converted to the correct OpenFLow format
        actions = [parser.OFPActionOutput(out_port)]
        rcvr_actions = [parser.OFPActionOutput(in_port)]

        # Install the Flow-Mod, if packet is not flagged as forward-only and iff handshake has been completed
        if out_port != ofproto.OFPP_FLOOD and not forward_only and handshake_complete:
            sender_match = parser.OFPMatch(
                in_port=in_port, eth_type=eth_type, eth_src=eth_src, eth_dst=eth_dst,
                ip_proto=ip_proto, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst, tcp_src=tcp_src, tcp_dst=tcp_dst
            )
            receiver_match = parser.OFPMatch(
                in_port=out_port, eth_type=eth_type, eth_src=eth_dst, eth_dst=eth_src,
                ip_proto=ip_proto, ipv4_src=ipv4_dst, ipv4_dst=ipv4_src, tcp_src=tcp_dst, tcp_dst=tcp_src
            )
            self.add_flow(datapath, 1, sender_match, actions)
            self.add_flow(datapath, 1, receiver_match, rcvr_actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # Although a flow-mod may have been installed, we still need to send the packet that
        # triggered the event back out
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        return

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """ Handle Packet In OpenFlow Events """
        self.logger.info("EVENT: PACKET IN")

        # Collect EVENT data
        msg = ev.msg  # The message containing all the data needed from the openflow event
        datapath = ev.msg.datapath  # The switch (datapath) that the event came from
        ofproto = ev.msg.datapath.ofproto  # OF Protocol lib to be used with the OF version on the switch
        parser = ev.msg.datapath.ofproto_parser  # OF Protocol Parser that matches the OpenFlow version on the switch
        dpid = ev.msg.datapath.id  # ID of the switch (datapath) that the event came from

        # Collect packet data
        pkt = packet.Packet(msg.data)  # The packet relating to the event (including all of its headers)
        in_port = msg.match['in_port']  # The port that the packet was received on the switch

        # Build basic (L2) match
        match_dict = {}
        eth = pkt.protocols[0]  # Lowest layer header available (ethernet)
        match_dict["in_port"] = in_port  # Add the input port into the match
        match_dict["eth_type"] = eth.ethertype  # Add ethernet type into the match
        match_dict["eth_src"] = eth.src  # Add source mc address into the match
        match_dict["eth_dst"] = eth.dst  # Add destination mac address into the match

        # Build Advanced (L4) Match
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            # For IP
            ip = pkt.protocols[1]  # Get the next header in, that, as ethertype is IP here, next header is IP
            match_dict["ip_proto"] = ip.proto
            match_dict["ipv4_src"] = ip.src
            match_dict["ipv4_dst"] = ip.dst

            # IF PACKET HAS TCP PROTOCOL APPLY DoS PROTECTION
            if ip.proto == inet.IPPROTO_TCP:
                # For TCP
                nw = pkt.protocols[2]

                # IF this switch is a firewall, apply countermeasures for DoS attack through SYN FLOODING
                if dpid in self.firewalls:
                    self._syn_flood_cm(datapath, parser, in_port, msg, pkt)
                    return  # stop processing pkt

                match_dict["tcp_src"] = nw.src_port
                match_dict["tcp_dst"] = nw.dst_port
                self.logger.info("MATCH CREATED: TCP")
            elif ip.proto == inet.IPPROTO_UDP:
                # For UDP
                nw = pkt.protocols[2]
                match_dict["udp_src"] = nw.src_port
                match_dict["udp_dst"] = nw.dst_port
                self.logger.info("MATCH CREATED: UDP")
            elif ip.proto == inet.IPPROTO_ICMP:
                # For ICMP
                icmp = pkt.protocols[2]
                match_dict["icmpv4_type"] = icmp.type
                match_dict["icmpv4_code"] = icmp.code
                self.logger.info("MATCH CREATED: ICMP")
            else:
                self.logger.info("MISS: Ignoring IP Proto %x" % ip.proto)
                return
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            # For ARP
            arp = pkt.protocols[1]  # Get the next header in, that, as ethertype is ARP here, next header is ARP
            match_dict["arp_sha"] = arp.src_mac
            match_dict["arp_tha"] = arp.dst_mac
            match_dict["arp_spa"] = arp.src_ip
            match_dict["arp_tpa"] = arp.dst_ip
            match_dict["arp_op"] = arp.opcode
            self.logger.info("MATCH CREATED: ARP")
        else:
            self.logger.info("MISS: Ignoring Ethernet Type %x" % eth.ethertype)
            return

        # Little fix for the ryu match problem with incremental match building in OFv1_3
        # Rather than using append_fields, that does not apply ordering, we use kwargs
        match = parser.OFPMatch(**match_dict)

        # Add the mac address to port mapping to the dict
        # The outer dict represents a mapping of switches to their mappings
        # The inner dict represents a mapping of mac addresses to ports
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # If the dst mac address has a mapping in the table, the switch should send
        # the packet out only via the port mapped
        # Else, just flood the packet to all ports
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
            self.logger.info("PACKET OUT: Port %s", str(out_port))
        else:
            self.logger.info("PACKET OUT: Flooding")
            out_port = ofproto.OFPP_FLOOD

        # The action of sending a packet out converted to the correct OpenFLow format
        actions = [parser.OFPActionOutput(out_port)]

        # Install the Flow-Mod
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # Although a flow-mod may have been installed, we still need to send the packet that
        # triggered the event back out
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        return

    def add_flow(self, datapath, priority, match, actions, hard_timeout=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if hard_timeout is not None:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)

        self.logger.info("FLOW MOD: Written")
        datapath.send_msg(mod)

    def match_from_json(self, file_name, datapath):
        """ Your JSON file must have all required fields """
        # For the file_name, try using the whole path (e.g. /home/vagrant/Firewall-CW/rules.json)
        try:
            with open(file_name, "r") as rules_file:
                rules_dict = json.load(rules_file)
            if rules_dict['datapath'] is None:
                self.logger.info("Invalid Rules File!")
                return
            elif rules_dict['datapath'][str(datapath.id)]:  # Check if this is FW switch
                self.firewalls.append(datapath.id)  # Append datapath id (id of switch) in list of firewalls.
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                for rule in rules_dict['datapath'][str(datapath.id)]:
                    description = rule.pop('description')
                    rule_action = rule.pop('action')
                    if rule_action == 'drop':
                        actions = ''   # no action, by default means drop packet in ryu
                    else:
                        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                    priority = rule.pop('priority')
                    if self._validate_rule(**rule):
                        print("Adding rule: {}".format(description))
                        match = parser.OFPMatch(**rule)
                        self.add_flow(datapath, priority, match, actions)
                        print("Rule added.")
                    else:
                        print("Could not add rule: {}\nPlease check if eth_type (Layer 3) "
                              "or ip_proto (Layer 4 - needs eth_type too) are missing".format(description))
        except Exception:
            self.logger.info("Rules File \"" + file_name + "\" Failed to Parse")

    @staticmethod
    def _validate_rule(**rule):
        fields = rule.keys()
        layer3_fields = ['ipv4_dst', 'ipv4_src']
        layer4_fields = ['tcp_src', 'tcp_dst', 'udp_src', 'udp_dst', 'icmpv4_type', 'icmpv4_code']
        layer3_required = 'eth_type'
        layer4_required = 'ip_proto'
        for f in layer3_fields:
            if f in fields:
                if layer3_required not in fields:
                    return False
        for f in layer4_fields:
            if f in fields:
                if layer4_required not in fields or layer3_required not in fields:
                    return False

        return True
