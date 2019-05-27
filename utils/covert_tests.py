from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, IPv6ExtHdrFragment
from scapy.sendrecv import send


def version_covert_channel(src: str, dst: str, numpackets=2):
    ip = IPv6()
    ip.version = 5
    ip.src = src
    ip.dst = dst
    layer4 = ICMPv6EchoRequest()
    pkt = ip / layer4
    pkt.show()
    send(pkt, count=numpackets)
    
    
def fragment_covert_channel(src, dst):

    payload1 = ''
    for i in range(1280):
        payload1 = payload1 + '0'
        
    payload2 = ''
    for i in range(1280):
        payload2 = payload2 + '0'
        
    # Create IPv6 Packet
    ip6 = IPv6()
    ip6.dst = dst
    ip6.src = src
    
    # Create ICMPv6 Packet
    icmpv6 = ICMPv6EchoRequest(cksum=0x7b57, data=payload1)
    
    # Create Fragments
    frg_hdr1 = IPv6ExtHdrFragment()  # offset=0, m=1, id=511, nh=58
    frg_hdr1.offset = 0
    frg_hdr1.m = 1
    frg_hdr1.id = 511
    frg_hdr1.nh = 44

    frg_hdr2 = IPv6ExtHdrFragment()  # offset=162, m=0, id=511, nh=6
    frg_hdr2.offset = 162
    frg_hdr2.m = 0
    frg_hdr2.id = 511
    frg_hdr2.nh = 6

    tcp_hdr = TCP()
    tcp_hdr.source_port = 1055
    tcp_hdr.destination_port = 8080

    # Create Packet for sending
    pkt1 = ip6/frg_hdr1/icmpv6
    pkt2 = ip6/frg_hdr2/tcp_hdr/payload2

    pkt1.show()
    pkt2.show()
    # Send Packets
    send(pkt1)
    send(pkt2)


# version_covert_channel("fe80::49:3cff:fe20:c149", "fe80::24c5:6ff:fea8:94b1", 11)
fragment_covert_channel("fe80::cfe:96ff:fed8:6591", "fe80::1c10:35ff:fe43:d93")
