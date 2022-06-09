#!/usr/bin/python

#You may need to first execute: mn -c

import subprocess
import re
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController, OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.link import Intf
from mininet.util import quietRun

def myNet():

    CONTROLLER_IP='127.0.0.1'

    # Create network
    net = Mininet( controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)

    # Create devices 
    ## Server
    #router 1A
    h1 = net.addHost( 'h1', ip='192.168.1.2/24', mac='00:00:00:00:01:02', defaultRoute='via 192.168.1.1' )
    h2 = net.addHost( 'h2', ip='192.168.1.3/24', mac='00:00:00:00:01:03', defaultRoute='via 192.168.1.1' )
    h6 = net.addHost( 'h6', ip='192.168.1.4/24', mac='00:00:00:00:01:04', defaultRoute='via 192.168.1.1' )
    h7 = net.addHost( 'h7', ip='192.168.1.5/24', mac='00:00:00:00:01:05', defaultRoute='via 192.168.1.1' )

    #router 1B
    h3 = net.addHost( 'h3', ip='192.168.2.2/24', mac='00:00:00:00:02:02', defaultRoute='via 192.168.2.1' )
    h4 = net.addHost( 'h4', ip='192.168.2.3/24', mac='00:00:00:00:02:03', defaultRoute='via 192.168.2.1' )
    h8 = net.addHost( 'h8', ip='192.168.2.4/24', mac='00:00:00:00:02:04', defaultRoute='via 192.168.2.1' )
    h9 = net.addHost( 'h9', ip='192.168.2.5/24', mac='00:00:00:00:02:05', defaultRoute='via 192.168.2.1' )

    #router 1C
    h5 = net.addHost( 'h5', ip='192.168.5.2/24', mac='00:00:00:00:05:02', defaultRoute='via 192.168.5.1' )
    
    

    ## Switches
    s1a = net.addSwitch( 's1a' , protocols=["OpenFlow10"], dpid='1A' )
    s1b = net.addSwitch( 's1b' , protocols=["OpenFlow10"], dpid='1B' )
    s1c = net.addSwitch( 's1c' , protocols=["OpenFlow10"], dpid='1C' )
    s2 = net.addSwitch( 's2' , protocols=["OpenFlow10"], dpid='2' )
    s3 = net.addSwitch( 's3' , protocols=["OpenFlow10"], dpid='3' )
    s4 = net.addSwitch( 's4' , protocols=["OpenFlow10"], dpid='4' )

    # Create links 
    net.addLink(s1a, s1b, port1=1, port2=1)
    net.addLink(s1c, s1a, port1=1, port2=4)      
    net.addLink(s1a, s2, port1=2, port2=1)   
    net.addLink(s1b, s3, port1=2, port2=1)
    net.addLink(s1c, s4, port1=2, port2=1)
    net.addLink(s1a, s1b, port1=5, port2=5)    

    net.addLink(h1, s2, port1=1, port2=2)   
    net.addLink(h2, s2, port1=1, port2=3)   
    net.addLink(h3, s3, port1=1, port2=2)   
    net.addLink(h4, s3, port1=1, port2=3)

    net.addLink(h5, s4, port1=1, port2=2)   
    net.addLink(h6, s2, port1=1, port2=4)   
    net.addLink(h7, s2, port1=1, port2=5)   
    net.addLink(h8, s3, port1=1, port2=4)
    net.addLink(h9, s3, port1=1, port2=5)


    c1 = net.addController( 'c1', ip=CONTROLLER_IP, port=6633)

    net.build()        
    
    # Start controllers and connect switches
    c1.start()
    s1a.start( [c1] )
    s1b.start( [c1] )
    s1c.start( [c1] )
    s2.start( [c1] )
    s3.start( [c1] )
    s4.start( [c1] )

    for host in net.hosts:
        host.cmd('smcroute -k')

    for host in net.hosts:
        host.cmd( 'route add -net 224.0.0.0 netmask 240.0.0.0 dev', host.defaultIntf() )
        host.cmd('sysctl net.ipv4.icmp_echo_ignore_broadcasts=0')

        print(host.defaultIntf())

        if host.name == 'h1' or host.name == 'h3' or host.name == 'h6' or host.name == 'h8':
            mul_group = '239.0.0.1'
        else:
            mul_group = '239.0.0.2'
        
       # host.cmd('smcroute -k')
        host.cmd('smcroute -d')
        if host.name == 'h5':
            continue

        host.cmd('smcroute -j', host.defaultIntf(), mul_group)

    CLI( net )

    net.stop()
    subprocess.call(["mn", "-c"], stdout=None, stderr=None)

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()