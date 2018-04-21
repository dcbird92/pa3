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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet.arp import arp


class u0717742_SeanHammond(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(u0717742_SeanHammond, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
	self.servers = []
	self.clients = {}
	self.servers_info = {}
	self.clients["10.0.0.1"] = {"mac":"00:00:00:00:00:01","port":1}
	self.clients["10.0.0.2"] = {"mac":"00:00:00:00:00:02","port":2}
	self.clients["10.0.0.3"] = {"mac":"00:00:00:00:00:03","port":3}
	self.clients["10.0.0.4"] = {"mac":"00:00:00:00:00:04","port":4}
	self.servers_info["10.0.0.5"] = {"mac":"00:00:00:00:00:05","port":5}
	self.servers_info["10.0.0.6"] = {"mac":"00:00:00:00:00:06","port":6} 
	self.index = 0
	self.ip_mac = {}
	self.server_mac_port = {}
	self.ip_mac["10.0.0.5"] = "00:00:00:00:00:05"
	self.ip_mac["10.0.0.6"] = "00:00:00:00:00:06"
	self.server_mac_port["00:00:00:00:00:05"] = 5
	self.server_mac_port["00:00:00:00:00:06"] = 6
	self.servers.append("10.0.0.5")
	self.servers.append("10.0.0.6")
	self.virtual_ip = {}
	self.virtual_ip["10.0.0.5"] = "0"
	self.virtual_ip["10.0.0.6"] = "0"
	
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    def client_flow(self, datapath, in_port, out_port, new_dst_ip, new_dst_mac, old_dst_ip):
	print("CLIENT_FLOW")
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser
	match = parser.OFPMatch(in_port=in_port, ipv4_dst=old_dst_ip,
				 eth_dst=new_dst_mac, eth_type=ether_types.ETH_TYPE_IP)

	actions = [parser.OFPActionSetField(ipv4_dst=new_dst_ip), parser.OFPActionOutput(port=out_port)]
 	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
 	mod = parser.OFPFlowMod(datapath=datapath, match=match,priority=ofproto.OFP_DEFAULT_PRIORITY,
		instructions=inst)
	datapath.send_msg(mod)
 	print("CLIENT_FLOW_END")


    def server_flow(self, datapath, in_port, out_port, src_ip, dst_ip, dst_mac, src_mac, old_ip):
	print("SERVER_FLOW")
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser
	temp_index = 0
	if self.index == 0:
		temp_index = 1
	match = parser.OFPMatch(in_port=in_port, ipv4_dst=dst_ip, eth_dst=dst_mac, eth_type=ether_types.ETH_TYPE_IP)
	server = self.servers[temp_index]
	actions = [parser.OFPActionSetField(ipv4_src=old_ip),parser.OFPActionOutput(port=out_port)]
	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
	mod = parser.OFPFlowMod(datapath=datapath,match=match,priority=ofproto.OFP_DEFAULT_PRIORITY,
		instructions=inst)
	datapath.send_msg(mod)
	print("SERVER_FLOW_END")
	

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    

    def index_change(self):
	if self.index == 0:
		self.index = 1
	else:
		self.index = 0

    def _send_packet(self, datapath, in_port, out_port, pkt, is_arp, current_server, add_flow):
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser
	pkt.serialize()
	data = pkt.data
	actions = [parser.OFPActionOutput(port=in_port)]

	if add_flow:
		serv = self.servers[current_server]
		self.client_flow(datapath, in_port, out_port, serv, self.servers_info[serv]["mac"], is_arp.dst_ip)
		self.server_flow(datapath, out_port, in_port, serv, is_arp.src_ip, is_arp.src_mac,
				self.servers_info[serv]["mac"], is_arp.dst_ip)
	out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,
				in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)

	datapath.send_msg(out)

    def arp_handler(self, datapath, in_port, out_port, eth, is_arp):
	if is_arp.opcode != 1:
		return
	pkt = packet.Packet()
	
	if is_arp.dst_ip in self.clients:
		pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=self.clients[is_arp.dst_ip]["mac"]))
		pkt.add_protocol(arp(opcode=2, src_mac=self.clients[is_arp.dst_ip]["mac"],
				src_ip=is_arp.dst_ip, dst_mac=is_arp.src_mac, dst_ip=is_arp.src_ip))	
		self._send_packet(datapath, in_port, out_port, pkt, is_arp, self.index, False)
		return
	ser = self.servers[self.index]
	
	pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=self.servers_info[ser]["mac"]))
	pkt.add_protocol(arp(opcode=2, src_mac=self.servers_info[ser]["mac"],
				src_ip=is_arp.dst_ip, dst_mac=is_arp.src_mac, dst_ip=is_arp.src_ip))
	self._send_packet(datapath, in_port, out_port, pkt, is_arp, self.index, True)
	self.index_change()
	return	
	
	
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
	dpid = datapath.id
	
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
           return

	server_ip = self.servers[self.index]
	out_port = self.servers_info[server_ip]["port"]
	arp_msg = pkt.get_protocol(arp)
	if eth.ethertype == ether_types.ETH_TYPE_ARP:
		self.arp_handler(datapath, int(in_port), int(out_port), eth, arp_msg)
		return
	
	dst = eth.dst
	src = eth.src

	self.mac_to_port.setdefault(dpid,{})
	self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
	self.mac_to_port[dpid][src] = in_port
		
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
#	print("source: ", src)
#	print("self.mac_to_port[dpid=",dpid,"][src=",src,"]=inport",in_port)
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

