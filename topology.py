from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch, Controller, RemoteController
from time import sleep

class MyTopo( Topo ):
    "ring topology example."
    def build( self ):
        "Create custom topo."

        # Add hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        
        #Add switches
        u = self.addSwitch('s1')
        v = self.addSwitch('s2')
        x = self.addSwitch('s3')
        y = self.addSwitch('s4')
        w = self.addSwitch('s5')
        z = self.addSwitch('s6')
        
        # Add links
        self.addLink( h1, u )
        self.addLink( u, v )
        self.addLink( u, x )
        self.addLink( u, w )
        self.addLink( v, w )
        self.addLink( v, x )
        self.addLink( x, w )
        self.addLink( x, y )
        self.addLink( y, w )
        self.addLink( y, z )
        self.addLink( z, w )
        self.addLink( z, h2)
        self.addLink( z, h3)

topos = { 'dynamic_topo': ( lambda: MyTopo() ) }

if __name__ == '__main__':
    setLogLevel('info')
    topo = MyTopo()
    c1 = RemoteController('c1', ip='127.0.0.1',port=6633)
    net = Mininet(topo=topo, controller=c1)
    net.start()
    CLI(net)
    net.stop()












