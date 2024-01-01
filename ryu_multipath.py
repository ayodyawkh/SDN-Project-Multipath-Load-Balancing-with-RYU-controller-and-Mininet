from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib import mac, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event

from collections import defaultdict
from operator import itemgetter

import os
import random
import time

# Cisco Reference bandwidth = 1 Gbps
REFERENCE_BW = 10000000
DEFAULT_BW = 10000000
MAX_PATHS = 2

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.switches = []
        self.hosts = {}
        self.multipath_group_ids = {}
        self.group_ids = []
        self.adjacency = defaultdict(dict)
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))

    def get_paths(self, src, dst):
        #Get all the paths between src and dst using depth-first search
        if src == dst: #src and dst are on the same switch
            return [[src]]
            
        paths = []
        stack = [(src, [src])]
        while stack:
            current_node, current_path = stack.pop()
            
            #Iterate over the neighbors of the current node that have not been visited in the current path
            for next_node in set(self.adjacency[current_node].keys()) - set(current_path):
                if next_node == dst:
                    paths.append(current_path + [next_node])
                else:
                    stack.append((next_node, current_path + [next_node]))
        return paths
        

    def get_link_cost(self, s1, s2):
        #Calculate link cost based on bandwidth using Cisco reference model
        e1 = self.adjacency[s1][s2] #Retrieve edge weights
        e2 = self.adjacency[s2][s1]
        
        bandwidth_s1 = self.bandwidths[s1][e1] 
        bandwidth_s2 = self.bandwidths[s2][e2]
        min_bandwidth = min(bandwidth_s1, bandwidth_s2) #Determine minimum bandwidth
        
        effective_weight = REFERENCE_BW / min_bandwidth #Calculate link cost
        return effective_weight

    def get_path_cost(self, path):
        #Calculate the total path cost by summing link costs
        cost = 0
        for idx, node in enumerate(path[:-1]):
            next_node = path[idx + 1]
            cost += self.get_link_cost(node, next_node)
        return cost

    def get_optimal_paths(self, src, dst):
        # Select up to n lowest cost paths for multipath routing
        paths = self.get_paths(src, dst)
        paths_count = min(len(paths), MAX_PATHS)
        
        sorted_paths = sorted(paths, key=lambda x: self.get_path_cost(x)) #Sort paths in ascending order of cost
        print("Multipaths ", src, " to ", dst, " : ", sorted_paths[:paths_count])
        return sorted_paths[:paths_count]

    def add_ports_to_paths(self, paths, first_port, last_port):
        #Add input and output ports into each path
        paths_with_ports = []

        for path in paths:
            ports_by_switch = {}
            in_port = first_port
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.adjacency[s1][s2]
                ports_by_switch[s1] = (in_port, out_port)
                in_port = self.adjacency[s2][s1]
            ports_by_switch[path[-1]] = (in_port, last_port)
            paths_with_ports.append(ports_by_switch)
            
        return paths_with_ports

    def generate_openflow_gid(self):
        #Returns a random OpenFlow group id
        n = random.randint(0, 2**32)
        while n in self.group_ids:
            n = random.randint(0, 2**32)
        return n
        
    def create_or_get_group_id(self, dp, ofp, ofp_parser, node, src, dst, sum_of_pw, out_ports):
        group_new = False
        if (node, src, dst) not in self.multipath_group_ids:
            group_new = True
            self.multipath_group_ids[node, src, dst] = self.generate_openflow_gid()

        group_id = self.multipath_group_ids[node, src, dst]
        
        buckets = []
        
        for port, weight in out_ports:
            bucket_weight = int(round((1 - weight / sum_of_pw) * 10))
            bucket_action = [ofp_parser.OFPActionOutput(port)]
            buckets.append(
                    ofp_parser.OFPBucket(
                    weight=bucket_weight,
                    watch_port=port,
                    watch_group=ofproto_v1_3.OFPG_ANY,
                    actions=bucket_action
                )
            )
        if group_new:
            req = ofp_parser.OFPGroupMod(
                dp, ofproto_v1_3.OFPGC_ADD, ofproto_v1_3.OFPGT_SELECT, group_id,
                buckets
            )
        else:
            req = ofp_parser.OFPGroupMod(
                dp, ofproto_v1_3.OFPGC_MODIFY, ofproto_v1_3.OFPGT_SELECT,
                group_id, buckets)
            
        dp.send_msg(req)

        return group_id

    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        computation_start = time.time()
        paths = self.get_optimal_paths(src, dst)
                                          
        pw = [self.get_path_cost(path) for path in paths]
        
        sum_of_pw = sum(pw)
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
                                                                                              
        switches_in_paths = set().union(*paths)

        for node in switches_in_paths:
            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            ports = defaultdict(list)
            actions = []
            i = 0

            for i, path in enumerate(paths_with_ports):
                if node in path:
                    in_port, out_port = path[node]
                    if (out_port, pw[i]) not in ports[in_port]:
                        ports[in_port].append((out_port, pw[i]))
                                  
            for in_port, out_ports in ports.items():
                match_ip = ofp_parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst
                )
                match_arp = ofp_parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_ARP, arp_spa=ip_src, arp_tpa=ip_dst
                )

                if len(out_ports) > 1:
                    group_id = self.create_or_get_group_id(
                    dp, ofp, ofp_parser, node, src, dst, sum_of_pw, out_ports)
                    
                    actions = [ofp_parser.OFPActionGroup(group_id)]

                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]

                self.add_flow(dp, 32768, match_ip, actions)
                self.add_flow(dp, 1, match_arp, actions)
                
        print("Path installation finished in ", time.time() - computation_start) 
        return paths_with_ports[0][src][1]
        
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        #Install flow rules in a switch.

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    
    def del_flow(self, datapath, dst):
        #Delete flow rules in a switch.
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(dl_dst=addrconv.mac.text_to_bin(dst))
        
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_DELETE)
            
        datapath.send_msg(mod)
        
    def handle_arp_packet(self, src, dst, src_ip, dst_ip, opcode):
        #Handle ARP Packets
        
        #Process ARP replies
        if opcode == arp.ARP_REPLY:
            self.arp_table[src_ip] = src
            h1 = self.hosts[src]
            h2 = self.hosts[dst]
            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
            self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip)  # reverse
        
        #Process ARP requests
        elif opcode == arp.ARP_REQUEST and dst_ip in self.arp_table:
            self.arp_table[src_ip] = src
            dst_mac = self.arp_table[dst_ip]
            h1 = self.hosts[src]
            h2 = self.hosts[dst_mac]
            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
            self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip)  # reverse

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        #Handles initial switch connection events
        print("switch_features_handler is called")

        datapath = ev.msg.datapath 
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        #Retrieves link bandwidth information from port description statistics reply
        switch = ev.msg.datapath
        for port in ev.msg.body:
            self.bandwidths[switch.id][port.port_no] = port.curr_speed

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #Process incoming packets, learn host locations, and install forwarding rules
        
        #Extract relevant information from the event
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        #Extract packet information
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        #Avoid broadcast from LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        if pkt.get_protocol(ipv6.ipv6):  #Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        #Learn source host location
        if src not in self.hosts: 
            self.hosts[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        #Handle ARP packets
        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            opcode = arp_pkt.opcode
            
            self.handle_arp_packet(src, dst, src_ip, dst_ip, opcode)

        actions = [parser.OFPActionOutput(out_port)] #Define OpenFlow actions for packet output

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def switch_enter_handler(self, ev):
        #Handles switch connection events
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser

        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch

            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        #Handles switch disconnection events
        switch = ev.switch.dp
        if switch.id in self.switches:
            try:
                del self.switches[switch.id] 
                del self.datapath_list[switch.id] 
                del self.adjacency[switch.id] 
            except:
                pass


    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        #Updates topology information upon link additions
        s1 = ev.link.src
        s2 = ev.link.dst
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no

        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        src_port = link.src.port_no
        dst_port = link.dst.port_no

        print("Link added:", src_dpid, src_port, "<->", dst_dpid, dst_port)

        print(self.arp_table)
        for src_mac, (src_switch, src_port) in self.hosts.items():
            src_ip = next((ip for ip, mac in self.arp_table.items() if mac == src_mac), None)
            for dst_mac, (dst_switch, dst_port) in self.hosts.items():
                dst_ip = next((ip for ip, mac in self.arp_table.items() if mac == dst_mac), None)
                if src_ip != dst_ip:
                    print(self.hosts.items, src_switch, src_port, dst_switch, dst_port, src_ip, dst_ip)
                    self.install_paths(src_switch, src_port, dst_switch, dst_port, src_ip, dst_ip)
    
    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        #Updates topology information upon link deletions
        s1 = ev.link.src
        s2 = ev.link.dst
        print(self.adjacency)
        try:
            del self.adjacency[s1.dpid][s2.dpid]
            del self.adjacency[s2.dpid][s1.dpid]
        except:
            pass

        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        src_port = link.src.port_no
        dst_port = link.dst.port_no

        print("Link deleted:", src_dpid, src_port, "<->", dst_dpid, dst_port)

        print(self.arp_table)
        for src_mac, (src_switch, src_port) in self.hosts.items():
            src_ip = next((ip for ip, mac in self.arp_table.items() if mac == src_mac), None)
            for dst_mac, (dst_switch, dst_port) in self.hosts.items():
                dst_ip = next((ip for ip, mac in self.arp_table.items() if mac == dst_mac), None)
                if src_ip != dst_ip:
                    print(self.hosts.items, src_switch, src_port, dst_switch, dst_port, src_ip, dst_ip)
                    self.install_paths(src_switch, src_port, dst_switch, dst_port, src_ip, dst_ip)
    