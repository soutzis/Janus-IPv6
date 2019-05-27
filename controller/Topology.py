# Mininet uses python 2.7. This venv is python 3.6
# Ignore pycharm import errors. This will not be run in the IDE, but by mininet
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import RemoteController


class Topo1(Topo):

    def __init__(self):
        Topo.__init__(self)

        switch1 = self.addSwitch('s1')

        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')

        self.addLink(host1, switch1)  # will add link to PORT 1 of the switch by default. This is out of protected net.
        self.addLink(host2, switch1)
        self.addLink(host3, switch1)


class Topo2(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        switch1 = self.addSwitch('s1')

        host1 = self.addHost('h1')
        host2 = self.addHost('h2')

        self.addLink(host1, switch1)  # will add link to PORT 1 of the switch by default. This is out of protected net.
        self.addLink(host2, switch1)


def run():
    """ Configure Network and Run Mininet """
    topo = Topo1()
    net = Mininet(topo=topo, controller=RemoteController)
    # set the MAC address with following command:
    # h1.intf('h1-eth0').setMAC('00:00:00:00:00:01')
    # h2.intf('h2-eth0').setMAC('00:00:00:00:00:02')
    # h3.intf('h3-eth0').setMAC('00:00:00:00:00:03')
    net.start()

    net.get('h1').cmd('add_ipv6 1')  # run the "add_ipv6" custom script for all hosts
    net.get('h2').cmd('add_ipv6 2')
    net.get('h3').cmd('add_ipv6 3')

    CLI(net)  # Run mininet cli

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()


topos = {
    'topo1': (lambda: Topo1()),
    'topo2': (lambda: Topo2())
}
