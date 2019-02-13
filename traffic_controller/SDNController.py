from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import *
from ryu.ofproto import ofproto_v1_3, ofproto_v1_5


class CustomController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CustomController, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.mac_to_port = {}
        self.eth_proto_names = {ethernet.ether.ETH_TYPE_IPV6: "IPv6",
                                ethernet.ether.ETH_TYPE_IP: "IP",
                                ethernet.ether.ETH_TYPE_ARP: "ARP"
                                }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @staticmethod
    def add_flow(datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src

        # Ignore below eth packet types
        if eth_pkt.ethertype == ethernet.ether.ETH_TYPE_LLDP:
            print("LLDP packet received. Ignoring..\n")
            return
        elif eth_pkt.ethertype == ethernet.ether.ETH_TYPE_IPV6:
            # print("Received IPV6 auto-configuration message. Ignoring..\n")
            return

        # get the received port number from packet_in message.
        in_port = msg.match['in_port']
        print()
        self.logger.info("Received packet at PORT %s of SWITCH %s -> MAC_SRC: %s, MAC_DST: %s",
                         in_port, dpid, src_mac, dst_mac)

        # learn MAC_Address-PORT mapping. Do every time, because port might change
        self.mac_to_port[dpid][src_mac] = in_port
        # print look up table
        print("MAC lookup-table: ", self.mac_to_port[dpid], sep='')

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
            print("Packet Type = ", self.eth_proto_names[eth_pkt.ethertype], sep='')
            # Check if it is an ARP packet
            if eth_pkt.ethertype == ethernet.ether.ETH_TYPE_ARP:
                arp_pkt = packet.Packet(ev.msg.data).get_protocol(arp.arp)
                matcher = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            # Check if it is an IP packet
            print("Forwarding packet to port", out_port)
        else:
            print("Flooding message.")
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time.
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, 1, matcher, actions)

        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)
        print()
