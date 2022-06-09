# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    set_ev_cls)
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import arp, ether_types, ethernet, icmp, igmp, ipv4, packet
from ryu.ofproto import ofproto_v1_0


DEBUG = True

#DEBUG = False
    # print only self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)
#DEBUG = True 
    # print with cayn color IGMP packets
    # print with lightcyan color the multicast_ports_list table
    # print every time the device and what packet it has, before adding flows

ARP_table = {
    '192.168.1.2': '00:00:00:00:01:02',
    '192.168.1.3': '00:00:00:00:01:03',
    '192.168.1.4': '00:00:00:00:01:04',
    '192.168.1.5': '00:00:00:00:01:05',
    '192.168.2.2': '00:00:00:00:02:02',
    '192.168.2.3': '00:00:00:00:02:03',
    '192.168.2.4': '00:00:00:00:02:04',
    '192.168.2.5': '00:00:00:00:02:05',
    '192.168.5.2': '00:00:00:00:05:02',
}

mac_port_1A = {
    1: '00:00:00:00:03:01',
    2: '00:00:00:00:01:01',
    4: '00:00:00:00:04:01',
    5: '00:00:00:00:05:01',
}

mac_port_1B = {
    1: '00:00:00:00:03:02',
    2: '00:00:00:00:02:01',
    5: '00:00:00:00:05:02',
}

mac_port_1C = {
    1: '00:00:00:00:04:02',
    2: '00:00:00:00:05:01',
}

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
 
    multicast_ports_list = []
    class MulticastPorts():
        def __init__(self, dpid):
            self.dpid = dpid
            self.addresses = []

    for device in multicast_ports_list:
        print(device.dpid, device.addresses)


    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = msg.datapath_id

        #Proactive packets with tos 8

        if dpid == 0x1A:
            #-------tos = 8 send to port 5--------
            actions = []            
            actions.append(datapath.ofproto_parser.OFPActionSetDlSrc('00:00:00:00:05:01'))
            actions.append(datapath.ofproto_parser.OFPActionSetDlDst('00:00:00:00:05:02'))
            actions.append(datapath.ofproto_parser.OFPActionOutput(5)) 
            match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_tos=8,  nw_dst='192.168.2.0', nw_dst_mask=24)
            self.add_flow(datapath, match, actions)
       
        elif dpid == 0x1B:
            #---------tos = 8 send to port 5--------
            actions = []
            actions.append(datapath.ofproto_parser.OFPActionSetDlSrc('00:00:00:00:05:02'))
            actions.append(datapath.ofproto_parser.OFPActionSetDlDst('00:00:00:00:05:01'))
            actions.append(datapath.ofproto_parser.OFPActionOutput(5)) 
            match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_tos=8,  nw_dst='192.168.1.0', nw_dst_mask=24)
            self.add_flow(datapath, match, actions)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        self.mac_to_port.setdefault(dpid, {})
        
        if not DEBUG:
            if not '33:33' in dst:
                self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port


        ###################################### Router 1A ##################################################   
        if dpid == 0x1A:
            #ARP Packet
            if ethertype == ether_types.ETH_TYPE_ARP:
                arp_pkt = pkt.get_protocol(arp.arp) 

                actions = [datapath.ofproto_parser.OFPActionOutput(2)]
                if arp_pkt.opcode == 1:   
                    self.send_arp_reply(actions, datapath, '00:00:00:00:01:01', '192.168.1.1',  arp_pkt.src_mac,  arp_pkt.src_ip)

                return

            #IP Packet    
            elif ethertype == ether_types.ETH_TYPE_IP:
                ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

                # ------------------IGMP Packet-------------------------
                if ipv4_pkt.proto == 2:
                    igmp_pkt = pkt.get_protocol(igmp.igmp)
                    actions = []
                    
                    #Add new port in table, if already come this packet -> not forward
                    if not self.add_mul_address('1A', igmp_pkt.records[0].address, msg.in_port):
                        return

                    if DEBUG:
                        print("\033[94m1A IGMP Packet from:", ipv4_pkt.src, "to join in group:", igmp_pkt.records[0].address,"\033[00m")
                        self.print_mul_addresses()

                    # forward IGMP packet to neighbors devices
                    if msg.in_port == 1:
                        actions.append(datapath.ofproto_parser.OFPActionOutput(2))
                        actions.append(datapath.ofproto_parser.OFPActionOutput(4))
                    elif msg.in_port == 2:
                        actions.append(datapath.ofproto_parser.OFPActionOutput(1))
                        actions.append(datapath.ofproto_parser.OFPActionOutput(4))

                    elif msg.in_port == 4:
                        actions.append(datapath.ofproto_parser.OFPActionOutput(1))
                        actions.append(datapath.ofproto_parser.OFPActionOutput(2))
                    

                    # provlhmatiko, kanei loupa me ton 1B sta ports 1, 5 
                    #actions.append(datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD))

                # ------------------Unicast Packet--------------------------
                elif '192.168' in ipv4_pkt.dst:

                    # Unicast Packet comes from subnet(h1, h2) or Router 1C -> Send to Router 1B
                    if '192.168.2' in ipv4_pkt.dst:    
                        actions = [(datapath.ofproto_parser.OFPActionSetDlSrc('00:00:00:00:03:01')),
                                (datapath.ofproto_parser.OFPActionSetDlDst('00:00:00:00:03:02')),
                                (datapath.ofproto_parser.OFPActionOutput(1))]

                        # 24 mast because we don t care about the dst ip
                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_dst=ipv4_pkt.dst, nw_dst_mask=24, in_port=msg.in_port) 
                        self.add_flow(datapath, match, actions)

                    # Unicast Packet comes from subnet(h1, h2) or Router 1B -> Send to Router 1C
                    elif '192.168.5' in ipv4_pkt.dst:    
                        actions = [(datapath.ofproto_parser.OFPActionSetDlSrc('00:00:00:00:04:01')),
                                (datapath.ofproto_parser.OFPActionSetDlDst('00:00:00:00:04:02')),
                                (datapath.ofproto_parser.OFPActionOutput(4))]

                        # 24 mast because we don t care about the dst ip
                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_dst=ipv4_pkt.dst, nw_dst_mask=24, in_port=msg.in_port) 
                        self.add_flow(datapath, match, actions)

                    # Unicast Packet comes from router 1B or router 1C-> Send to Subnet(h1, h2)
                    elif '192.168.1' in ipv4_pkt.dst:   
                        actions = [(datapath.ofproto_parser.OFPActionSetDlSrc('00:00:00:00:01:01')),
                                (datapath.ofproto_parser.OFPActionSetDlDst(ARP_table[ipv4_pkt.dst])),
                                (datapath.ofproto_parser.OFPActionOutput(2))] 

                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_dst=ipv4_pkt.dst, nw_dst_mask=32, in_port=msg.in_port)
                        self.add_flow(datapath, match, actions)

                # ----------------Multicast Packet---------------------------
                elif '239.0.0' in ipv4_pkt.dst:
                    if DEBUG:
                        print('-----r1-------')
                        print(pkt)
                        
                   # Find output ports to forward the packet
                    output_ports = self.find_mul_port("1A", ipv4_pkt.dst, msg.in_port)
                    
                    # Erroorrr not found output ports
                    if not output_ports:
                        return

                    # Create actions
                    actions = []  
                    for port in output_ports:
                        actions.append(datapath.ofproto_parser.OFPActionSetDlSrc(mac_port_1A[port]))
                        actions.append(datapath.ofproto_parser.OFPActionOutput(port))


                    match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_dst=ipv4_pkt.dst, in_port=msg.in_port)
                    self.add_flow(datapath, match, actions)

                # packet with destination ip non exist --> reply ICMP host destination unreachable
                else:
                    actions = [datapath.ofproto_parser.OFPActionOutput(2)]
                    self.send_icmp__type3_reply(actions, datapath, '00:00:00:00:01:01', '192.168.1.1', src, ipv4_pkt.src, msg.data[14:])
                    return

                #kick message
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=pkt.data)
                datapath.send_msg(out)


                return
            return


        ###################################### Router 1B ##################################################   
        if dpid == 0x1B:
            # ARP Packet
            if ethertype == ether_types.ETH_TYPE_ARP:
                arp_pkt = pkt.get_protocol(arp.arp) 

                actions = [datapath.ofproto_parser.OFPActionOutput(2)]
                if arp_pkt.opcode == 1:   
                    self.send_arp_reply(actions, datapath, '00:00:00:00:02:01', '192.168.2.1',  arp_pkt.src_mac,  arp_pkt.src_ip)
              
                return

            # IP Packet
            elif ethertype == ether_types.ETH_TYPE_IP: 
                ipv4_pkt = pkt.get_protocol(ipv4.ipv4)


                 # ----------------------------IGMP Packet----------------------------
                if ipv4_pkt.proto == 2:
                    igmp_pkt = pkt.get_protocol(igmp.igmp)
                    actions = []

                    #Add new port, if already come this packet -> not forward
                    if not self.add_mul_address('1B', igmp_pkt.records[0].address, msg.in_port):
                        return

                    if DEBUG:
                        print("\033[94m1B IGMP Packet from:", ipv4_pkt.src, "to join in group:", igmp_pkt.records[0].address,"\033[00m")
                        self.print_mul_addresses()

                      # forward IGMP packet to neighbors devices
                    if msg.in_port == 1:
                        actions.append(datapath.ofproto_parser.OFPActionOutput(2))
                    elif msg.in_port == 2:
                        actions.append(datapath.ofproto_parser.OFPActionOutput(1))
                    
                        
                    # provlhmatiko, kanei loupa me ton 1A sta ports 1, 5 
                    #actions.append(datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD))

                
                # ------------------------Unicast Packet-----------------------------------
                elif '192.168.' in ipv4_pkt.dst:            
                    # Unicast Packet comes from subnet(h3, h4) -> Send to Router 1A
                    if ('192.168.1' in ipv4_pkt.dst) or ('192.168.5' in ipv4_pkt.dst):      
                        actions = [(datapath.ofproto_parser.OFPActionSetDlSrc('00:00:00:00:03:02')),
                                (datapath.ofproto_parser.OFPActionSetDlDst('00:00:00:00:03:01')),
                                (datapath.ofproto_parser.OFPActionOutput(1))]  

                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_dst=ipv4_pkt.dst, nw_dst_mask=24, in_port=msg.in_port)
                        self.add_flow(datapath, match, actions)
                    
                    # Unicast Packet comes from router 1A or router 1C -> Send to subnet(h3, h4)
                    elif '192.168.2' in ipv4_pkt.dst:                                 
                        actions = [(datapath.ofproto_parser.OFPActionSetDlSrc('00:00:00:00:02:01')),
                                (datapath.ofproto_parser.OFPActionSetDlDst(ARP_table[ipv4_pkt.dst])),
                                (datapath.ofproto_parser.OFPActionOutput(2))]

                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_dst=ipv4_pkt.dst, nw_dst_mask=32, in_port=msg.in_port)
                        self.add_flow(datapath, match, actions)
                    
                # --------------------------------Multicast Packet-----------------------------------
                elif '239.0.0' in ipv4_pkt.dst:
                    if DEBUG:
                        print('-----r2-------')
                        print(pkt)
        
                    # Find output ports to forward the packet
                    output_ports = self.find_mul_port("1B", ipv4_pkt.dst, msg.in_port)
                    
                    # Erroorrr not found output ports
                    if not output_ports:
                        return

                    # Create actions
                    actions = []  
                    for port in output_ports:
                        actions.append(datapath.ofproto_parser.OFPActionSetDlSrc(mac_port_1B[port]))
                        actions.append(datapath.ofproto_parser.OFPActionOutput(port))


                    match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_dst=ipv4_pkt.dst, in_port=msg.in_port)
                    self.add_flow(datapath, match, actions)


                # Packet with destination ip non exist --> reply ICMP host destination unreachable
                else:
                    actions = [datapath.ofproto_parser.OFPActionOutput(2)]
                    self.send_icmp__type3_reply(actions, datapath, '00:00:00:00:02:01', '192.168.2.1', src, ipv4_pkt.src, msg.data[14:])
                    return 

    
                
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=pkt.data)
               
                datapath.send_msg(out)
            
                return
            return


        ###################################### Router 1C ##################################################   
        if dpid == 0x1C:
           
             # ARP Packet
            if ethertype == ether_types.ETH_TYPE_ARP:
                arp_pkt = pkt.get_protocol(arp.arp) 

                actions = [datapath.ofproto_parser.OFPActionOutput(2)]
                if arp_pkt.opcode == 1:   
                    self.send_arp_reply(actions, datapath, '00:00:00:00:05:01', '192.168.5.1',  arp_pkt.src_mac,  arp_pkt.src_ip)
              
                return

            # IP Packet
            elif ethertype == ether_types.ETH_TYPE_IP:
                ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

                 # -------------------------------IGMP Packet----------------------------------------
                if ipv4_pkt.proto == 2:
                    igmp_pkt = pkt.get_protocol(igmp.igmp)
                    actions = []

                    #Add new port, if already came this packet -> not forward
                    if not self.add_mul_address('1C', igmp_pkt.records[0].address, msg.in_port):
                        return
                    
                    if msg.in_port == 1:
                        actions.append(datapath.ofproto_parser.OFPActionOutput(2))
                    
                    if DEBUG:
                        print("\033[94m1C IGMP Packet from:", ipv4_pkt.src, "to join in group:", igmp_pkt.records[0].address,"\033[00m")
                        self.print_mul_addresses()

                    #actions.append(datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD))
                       
                # ------------------------Unicast Packet-----------------------------------
                elif '192.168.' in ipv4_pkt.dst:

                    # Unicast Packet comes from subnet(h5) -> Send to Router 1A
                    if '192.168.1' in ipv4_pkt.dst or '192.168.2' in ipv4_pkt.dst:      
                        actions = [(datapath.ofproto_parser.OFPActionSetDlSrc('00:00:00:00:04:02')),
                                (datapath.ofproto_parser.OFPActionSetDlDst('00:00:00:00:04:01')),
                                (datapath.ofproto_parser.OFPActionOutput(1))] 
        
                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_dst=ipv4_pkt.dst, nw_dst_mask=24, in_port=msg.in_port)
                        self.add_flow(datapath, match, actions)  
                    
                    # Unicast Packet comes from router 1A or router 1B-> Send to subnet(h5)
                    elif '192.168.5' in ipv4_pkt.dst:                                    
                        actions = [(datapath.ofproto_parser.OFPActionSetDlSrc('00:00:00:00:05:01')),
                                (datapath.ofproto_parser.OFPActionSetDlDst(ARP_table[ipv4_pkt.dst])),
                                (datapath.ofproto_parser.OFPActionOutput(2))]  

                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_dst=ipv4_pkt.dst, nw_dst_mask=32, in_port=msg.in_port)
                        self.add_flow(datapath, match, actions)   

                # ---------------------------------Multicast packet--------------------------------
                elif '239.0.0.' in ipv4_pkt.dst:
                    if DEBUG:
                        print('-----r3-------')
                        print(pkt)
                
                    # Find output ports
                    output_ports = self.find_mul_port("1C", ipv4_pkt.dst, msg.in_port)
                   
                    # Erroorrr not found output ports
                    if not output_ports:
                        return
        
                    # Create actions
                    actions = []  
                    for port in output_ports:
                        actions.append(datapath.ofproto_parser.OFPActionSetDlSrc(mac_port_1C[port]))
                        actions.append(datapath.ofproto_parser.OFPActionOutput(port))
                    
                    match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_dst=ipv4_pkt.dst, in_port=msg.in_port)
                    self.add_flow(datapath, match, actions)

                 # Packet with destination ip non exist --> reply ICMP host destination unreachable
                else:
                    actions = [datapath.ofproto_parser.OFPActionOutput(2)]
                    self.send_icmp__type3_reply(actions, datapath, '00:00:00:00:05:01', '192.168.5.1', src, ipv4_pkt.src, msg.data[14:])
                    return 
            
                
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=pkt.data)
               
                datapath.send_msg(out)

                return


        ####################################### Switches ##################################################   
        if dpid == 0x2 or dpid == 0x3 or dpid == 0x4:
            if ethertype == ether_types.ETH_TYPE_IP:
                ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
                

                # -------------------- IGMP Packet ---------------------------
                if ipv4_pkt.proto == 2:
                    igmp_pkt = pkt.get_protocol(igmp.igmp)

                    #Add new port, if already come this packet -> not forward
                    if not self.add_mul_address(dpid, igmp_pkt.records[0].address, msg.in_port):
                        return

                    if DEBUG:
                        print("\033[94m", dpid, "IGMP Packet from:", ipv4_pkt.src, "to join in group:", igmp_pkt.records[0].address,"\033[00m")
                        self.print_mul_addresses()

                    #IGMP packets that comes from routers, do not forward to hosts
                    if msg.in_port == 1:
                        return

                    actions = [datapath.ofproto_parser.OFPActionOutput(1)]

                    out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER,
                                actions=actions, data=pkt.data)    
                    datapath.send_msg(out)
                    return

                # --------------------------Multicast Packet ------------------------------------   
                elif '239.0.0.' in ipv4_pkt.dst:
                    if DEBUG:
                        print('-----', dpid, '-------')
                        print(pkt)

                    # Find output ports to forward the packet
                    output_ports = self.find_mul_port(dpid, ipv4_pkt.dst, msg.in_port)
                    
                    # Erroorrr not found output ports
                    if not output_ports:
                        return

                    actions = []
                    for port in output_ports:
                        actions.append(datapath.ofproto_parser.OFPActionOutput(port))
                   
                    match = datapath.ofproto_parser.OFPMatch(dl_dst=eth.dst, in_port=msg.in_port)                    
                    self.add_flow(datapath, match, actions)

                
                    out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER,
                                actions=actions, data=pkt.data)    
                    datapath.send_msg(out)
                    return

                 
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        match = datapath.ofproto_parser.OFPMatch(
            in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)


    # Search the multicast_ports_list and return the corrects output ports for whom to call it
    def find_mul_port(self, dpid, mul_address, input_port):
        output_ports = []

        # Search for the correct dpid
        for device in self.multicast_ports_list:
            if device.dpid != dpid:
                continue

            # Search for the correct multicast address
            for address in device.addresses:
                if address["address"] != mul_address: 
                    continue
               
                # Search for the corrects ports
                for port in address["ports"]:
                    if port == input_port:
                        continue

                    output_ports.append(port)

                break 
            break

        return output_ports

    # Add new output ports to multicast_ports_list for whom to call it
    def add_mul_address(self, dpid, Address, Port):

        # Search if dpid exist
        for device in self.multicast_ports_list:
            if device.dpid != dpid:
                continue

            # dpid exist, search if the address exist
            for address in device.addresses:
                if address["address"] != Address: 
                    continue

                # check if port already exists 
                if Port in address["ports"]:
                    return False

                #Insert Port
                address["ports"].append(Port)
                return True           
            
            # Address did not found, insert new address and port   
            device.addresses.append({"address": Address,"ports":[Port]})
            return True

        # dpid did not found, insert new dpid, address and port
        self.multicast_ports_list.append(self.MulticastPorts(dpid))
        self.multicast_ports_list[-1].addresses.append({"address": Address,"ports":[Port]})
        return True
         
    # Print multicast_ports_list
    def print_mul_addresses(self):
        
        # xazos alla apotelesmatikos tropos gia na epktypw8ei to table mono mia fora meta thn ektelesh twn IGMP Packet
        count = 0
        for device in self.multicast_ports_list:
            for address in device.addresses:
                for port in address["ports"]:
                    count = count + 1

        if count == 24:
            print("\n\033[96m---------------- Output Ports-----------------------")
            for device in self.multicast_ports_list:
                print(device.dpid, device.addresses)
            print("---------------------------------------------------\033[00m\n")


     



    def send_arp_reply(self, actions, datapath, src_mac, src_ip, dst_mac, dst_ip):
        ofproto = datapath.ofproto
        
        send_packet = packet.Packet()
        send_packet.add_protocol(ethernet.ethernet(ethertype = 0x806, dst = dst_mac,src = src_mac))
        send_packet.add_protocol(arp.arp(opcode = 2, src_mac = src_mac, src_ip = src_ip, dst_mac = dst_mac, dst_ip = dst_ip))

        send_packet.serialize()
        data = send_packet.data
        out = datapath.ofproto_parser.OFPPacketOut(datapath = datapath, buffer_id = ofproto.OFP_NO_BUFFER, in_port = ofproto.OFPP_CONTROLLER, actions = actions, data = data)
        print("\033[93mSend ARP REPLY from:", src_ip, 'to', dst_ip, "\033[00m")
        datapath.send_msg(out)


    def send_icmp__type3_reply(self, actions, datapath, src_mac, src_ip, dst_mac, dst_ip, msg_without_eth):
        ofproto = datapath.ofproto
        
        send_packet = packet.Packet()
        send_packet.add_protocol(ethernet.ethernet(ethertype = 0x800, dst = dst_mac,src = src_mac))
        send_packet.add_protocol(ipv4.ipv4(proto = 1, src = src_ip, dst = dst_ip))
        send_packet.add_protocol(icmp.icmp(type_= 3 , code = 1, data = icmp.dest_unreach(data_len = len(msg_without_eth), data = msg_without_eth)))
       
        send_packet.serialize()
        data = send_packet.data
        out = datapath.ofproto_parser.OFPPacketOut(datapath = datapath, buffer_id = ofproto.OFP_NO_BUFFER, in_port = ofproto.OFPP_CONTROLLER, actions = actions, data = data)
        print("\033[91mSend ICMP -Destination Host Unreachable- REPLY from:", src_ip, 'to', dst_ip, "\033[00m")
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
