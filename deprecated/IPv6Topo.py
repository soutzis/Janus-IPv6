from ipmininet.iptopo import IPTopo
from ipmininet.router.config import RouterConfig, RADVD, AdvPrefix, AdvRDNSS
from ipmininet.ipnet import IPNet
from ipmininet.link import IPLink, IPv6Interface
from ipmininet.cli import IPCLI
from mininet.node import OVSKernelSwitch, RemoteController


class RouterAdvNet(IPTopo):

    def build(self, *args, **kwargs):
        """

        Topology Representation:
        +----+           +----+       +----+       +----+           +----+
        | h2 +-----------+ r2 +-------+ s0 +-------+ r1 +-----------+ h1 |
        +----+           +----+       +----+       +----+           +----+

        Daemons like RADVD, QUAGGA, ZEBRA, etc, have to be installed on the machine for them to work

        """
        # =========== #
        # Add Routers #
        # =========== #
        # r1 will be in the 'protected' network
        r1 = self.add_router_v6('r1', mac="11:00:00:00:00:00", config=(RouterConfig, {'daemons': [RADVD]}))
        # r2 that will represent the 'internet' connection
        r2 = self.add_router_v6('r2', mac="22:00:00:00:00:00", config=(RouterConfig, {'daemons': [RADVD]}))

        # =================== #
        # Add Open vSwitch(s) #
        # =================== #
        s0 = self.addSwitch('s0')

        # Add Hosts
        h1 = self.addHost('h1', mac="00:00:00:00:00:01")
        h2 = self.addHost('h2', mac="00:00:00:00:00:02")

        # ======================= #
        # Add links between nodes #
        # ======================= #
        self.addLink(r2, h2, params1={
            "ip": "2001:2141::1/64",
            "ra": [AdvPrefix("2001:2141::/64")]
        })
        self.addLink(r2, s0)
        self.addLink(s0, r1)
        self.addLink(r1, h1, params1={
            "ip": "2001:1341::1/64",
            "ra": [AdvPrefix("2001:1341::/64")]
        })

        # Can advertise more prefixes like so:
        # self.addLink(r1, h1, params1={
        #     "ip": ("2001:1341::1/64", "2001:2141::1/64"),
        #     "ra": [AdvPrefix("2001:1341::/64"), AdvPrefix("2001:2141::/64")]
        # })

        # self.addLink(r0, dns,
        #              params1={"ip": ("2001:89ab::1/64", "2001:cdef::1/64")},
        #              params2={"ip": ("2001:89ab::d/64", "2001:cdef::d/64")})

        super(RouterAdvNet, self).build(*args, **kwargs)

    def add_router_v6(self, name, **kwargs):
        return self.addRouter(name, use_v4=False, use_v6=True, **kwargs)


# RUN MININET
topo1 = RouterAdvNet()


def topology():
    net = IPNet(use_v4=False,
                allocate_IPs=False,
                switch=OVSKernelSwitch,
                controller=RemoteController,
                topo=topo1
                )

    net.start()
    IPCLI(net)
    net.stop()


# Execute
topology()
