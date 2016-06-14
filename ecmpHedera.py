#!/usr/bin/env python


from struct import pack
from zlib import crc32

from lib.revent.revent import EventMixin, Event
from lib.addresses import IPAddr
from pox.lib.packet.vlan import vlan
from pox.lib.packet.ipv4 import ipv4

import pox.lib.util as util
from pox.core import core
from pox.openflow.discovery import Discovery
from pox.host_tracker import host_tracker

from pox.lib.util import dpidToStr,str_to_dpid

import pox.openflow.libopenflow_01 as of
from collections import defaultdict
import pox.lib.packet as pkt

from collections import namedtuple
from time import sleep
import pdb

from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp

from copy import deepcopy
from datetime import datetime

from flowmonitorH import Monitoring

from DemandEstimation import demand_estimation
import json
from pox.lib.recoco import Timer
import time

log = core.getLogger()
switch_ports = {}
switch_ids = {}


class Switch(EventMixin):
	def __init__(self):
	    self.connection = None
	    self.dpid = None
	    self.ports = None

	def connect(self, connection):
	    if self.dpid is None:
	        self.dpid = connection.dpid
	    assert self.dpid == connection.dpid
	    self.connection = connection

	def send_packet_data(self, outport, data = None):
		msg = of.ofp_packet_out(in_port=of.OFPP_NONE, data = data)
		msg.actions.append(of.ofp_action_output(port = outport))
		self.connection.send(msg)

	def send_packet_bufid(self, outport, buffer_id = -1):
	    msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
	    msg.actions.append(of.ofp_action_output(port = outport))
	    msg.buffer_id = buffer_id
	    self.connection.send(msg)

	def install(self, port, match, next_in_port ,idle_timeout = 0,buf = None):
		msg = of.ofp_flow_mod()
		msg.match = match
		#msg.data = event.ofp
		msg.idle_timeout = idle_timeout
		msg.actions.append(of.ofp_action_output(port = port))
		msg.buffer_id = buf
		msg.flags = of.OFPFF_SEND_FLOW_REM
		msg.in_port = next_in_port
		self.connection.send(msg)

	def install_prio(self, port, match, next_in_port ,idle_timeout = 20,buf = None, prio = 0):
		print "Inside prioritized install"
		msg = of.ofp_flow_mod()
		msg.match = match
		if prio:
			msg.priority = prio
		msg.idle_timeout = idle_timeout
		msg.actions.append(of.ofp_action_output(port = port))
		msg.buffer_id = buf
		msg.flags = of.OFPFF_SEND_FLOW_REM
		msg.in_port = next_in_port
		self.connection.send(msg)

	def drop(self, event):
		"""Tell the switch to drop the packet"""
		if event.ofp.buffer_id is not None: #nothing to drop because the packet is not in the Switch buffer
			msg = of.ofp_packet_out()
			msg.buffer_id = event.ofp.buffer_id 
			event.ofp.buffer_id = None # Mark as dead, copied from James McCauley, not sure what it does but it does not work otherwise
			msg.in_port = event.port
			self.connection.send(msg)

class NewFlow(Event):
	def __init__(self, path, match):
		Event.__init__(self)
		self.match = match
		log.debug("inside newflow!!: %s",self.match)
		self.path = path

class NewSwitch(Event):
	def __init__(self, switch):
		Event.__init__(self)
		self.switch = switch
		log.debug("inside NewSwitch!!: %s",self.switch)

class ECMP(EventMixin):
	_eventMixin_events = set([
							NewFlow,NewSwitch,
							])
	def __init__(self):
		self.FlowMonitor = Monitoring(postfix=datetime.now().strftime("%Y%m%d%H%M%S"))
		self.addListeners(self.FlowMonitor)
		core.Monitoring.addListeners(self) #add ECMP as a listener to monitoring
                print vars(core.Monitoring), vars(self)
		core.openflow.addListeners(self)
		core.openflow_discovery.addListeners(self)
		#core.host_tracker.addListeners(self)
		self.graph = {}
		self.wt_graph = {}
		self.port_info = {}
		self.possible_routes = []
		self.switches = {}
		self.macTable = {}
		self.bw = 1000.0 #Mbps
		self.matchDict = {}
		self.elephantsHandled = {}
		self.mtr = {}
		#self.flushTimer = Timer(10, self._flushWtGraph, recurring = True)

	def dijkstra(self,graph,src):
		'''gets adjacent nodes of source'''
		self.topodict = deepcopy(graph)
		length = len(self.topodict)
		type_ = type(self.topodict)

		nodes = self.topodict.keys()
		#pdb.set_trace()
		visited = [src]
		path = {src:{src:[]}}
		nodes.remove(src)
		distance_graph = {src:0}
		pre = next = src
		paths = {}
		while nodes:
		    distance = float('inf')
		    for v in visited:
		        #pdb.set_trace()
		        for d in nodes:
		            if d in self.topodict[v].keys():
		                new_dist = self.topodict[src][v] + self.topodict[v][d]
		                if new_dist < distance:
		                    distance = new_dist
		                    next = d
		                    pre = v
		                    self.topodict[src][d] = new_dist
		                    path[src][next] = [pre]
		                elif new_dist == distance:
		                    if not d in path[src].keys():
		                        path[src][d] = []
		                    path[src][d].append(v)
		    distance_graph[next] = distance

		    visited.append(next)
		    nodes.remove(next)

		return path

	def iterate(self,all_paths, src, dst,node = None):
		for j in all_paths[src][dst]:
			if node is not None:
				self.routes[-1].append(node)
			if j == src:
				self.routes[-1].append(j)
				self.routes.append([])				
			else:
				self.routes[-1].append(j)
				self.iterate(all_paths, src, j)

	def get_routes(self,all_paths, src, dst):
		'''getting all possible routes from source to destination'''

		self.routes = [[]]
		#pdb.set_trace()
		for node in all_paths[src][dst]:
			self.temp = node
			self.iterate(all_paths, src, node,self.temp)			

		return self.routes

	def _handle_LinkEvent(self, event):
		'''handling LinkEvent'''
		link = event.link
		if event.added:
		    log.debug("Received LinkEvent, Link Added from %s to %s over port %d", util.dpid_to_str(link.dpid1), util.dpid_to_str(link.dpid2), link.port1)
		    switch_ports[link.dpid1,link.port1] = link
		    switch_ids[link.dpid1] = util.dpid_to_str(link.dpid1)
		    switch_ids[link.dpid2] = util.dpid_to_str(link.dpid2)
		    if not link.dpid1 in self.graph.keys():
		    	self.graph[link.dpid1] = {}
		    self.graph[link.dpid1][link.dpid2] = 1
		    self.graph[link.dpid1][link.dpid1] = 0

		    if not link.dpid1 in self.wt_graph.keys():
				self.wt_graph[link.dpid1] = {}
		    if not link.dpid2 in self.wt_graph.keys():
				self.wt_graph[link.dpid2] = {}
		    self.wt_graph[link.dpid1][link.dpid2] = {'weight': 0, 'numFlows': 0, 'elephants': 0}
		    self.wt_graph[link.dpid2][link.dpid1] = {'weight': 0, 'numFlows': 0, 'elephants': 0}

		    if not link.dpid1 in self.port_info.keys():
		    	self.port_info[link.dpid1] = {}
		    self.port_info[link.dpid1][link.dpid2] = link.port1

		else:
		    log.debug("Received LinkEvent, Link Removed from %s to %s over port %d", util.dpid_to_str(link.dpid1), util.dpid_to_str(link.dpid2), link.port1)

	def _ecmp_hash(self, packet):
	    ''' Return an ECMP-style 5-tuple hash for TCP/IP packets, otherwise 0.
	    RFC2992 '''
	    hash_input = [0] * 5
	    if isinstance(packet.next, ipv4):
	        ip = packet.next
	        hash_input[0] = ip.srcip.toUnsigned()
	        hash_input[1] = ip.dstip.toUnsigned()
	        hash_input[2] = ip.protocol
	        if isinstance(ip.next, tcp) or isinstance(ip.next, udp):
	            l4 = ip.next
	            hash_input[3] = l4.srcport
	            log.debug('isinstance(ip.next, tcp)')
	            hash_input[4] = l4.dstport
	            return crc32(pack('LLHHH', *hash_input))
	    return 0

	def flood(self,event):
		"""Tell all switches to flood the packet, remember that we disable inter-switch flooding at startup"""

		for (dpid,switch) in switch_ids.iteritems():
			msg = of.ofp_packet_out()
			if switch == self:
				if event.ofp.buffer_id is not None:
					msg.buffer_id = event.ofp.buffer_id
				else:
					msg.data = event.ofp.data
				msg.in_port = event.port
			else:
				msg.data = event.ofp.data
			ports = [p for p in self.switches[dpid].connection.ports if (dpid,p) not in switch_ports]
			#print 'ports: ' + str(ports)
			if len(ports) > 0:
				for p in ports:
					msg.actions.append(of.ofp_action_output(port = p))
				self.switches[dpid].connection.send(msg)

	def _handle_PacketIn (self, event):
		'''handling packets based on the packet type'''
		packet = event.parsed
		src_switch = None
		dst_switch = None
		path = []
		self.flowroute = []
		self.final_path = [] 
		match = of.ofp_match.from_packet(packet)

		SwitchPort = namedtuple('SwitchPoint', 'dpid port')
		
		if (event.dpid,event.port) not in switch_ports:						# only relearn locations if they arrived from non-interswitch links
			self.macTable[packet.src] = SwitchPort(event.dpid, event.port)	#relearn the location of the mac-address

		if packet.effective_ethertype == packet.LLDP_TYPE:
			self.switches[event.dpid].drop(event)
			log.debug("Switch %s dropped LLDP packet", event.dpid)
		elif (packet.dst not in self.macTable) or (not isinstance(packet.next, ipv4)):
			self.flood(event)			
			#print 'flooding'
		else:
			if packet.src in self.macTable.keys():
				src_switch = self.macTable[packet.src].dpid
				log.debug('source_switch: %s',str(src_switch))
			else:
				log.debug('packet.src not in mactable: %s',str(packet.src))
			if packet.dst in self.macTable.keys():		
				dst_switch = self.macTable[packet.dst].dpid
				log.debug('dst switch: %s',str(dst_switch))
			else:
				log.debug('packet dst not in mactable: %s',str(packet.dst))

			if packet.dst in self.macTable.keys():
				final_out_port = self.macTable[packet.dst].port

			if src_switch == dst_switch:
				next_in_port = self.macTable[packet.src].port
				self.switches[dst_switch].install(final_out_port, match, next_in_port,idle_timeout = 10,buf = event.ofp.buffer_id)
			else:
				if src_switch in self.graph.keys():
					path = self.dijkstra(self.graph, src_switch)
					self.possible_routes = self.get_routes(path, src_switch, dst_switch)

					for i in range(len(self.possible_routes)):
						if len(self.possible_routes[i])<=1:
							self.possible_routes.remove(self.possible_routes[i])
					for i in range(len(self.possible_routes)):
						self.possible_routes[i].insert(0,dst_switch)
						self.possible_routes[i].reverse()
					log.debug('Possible_routes: %s',str(self.possible_routes))

					if self.possible_routes:
						'''Install entries on route between two switches'''
						self.install_path(event,packet,self.possible_routes,final_out_port)
						self.switches[self.final_path[-1]].send_packet_data(final_out_port, event.data)
						#self.switches[packet.dst].send_packet_data(final_out_port, event.data)
						if isinstance(packet.next, of.ipv4) and isinstance(packet.next.next, of.tcp):
							self.matchDict[(packet.next.srcip, packet.next.dstip, packet.next.next.srcport, packet.next.next.dstport)] = (self.final_path, match)
					else:
						log.debug("No possible path to reach destination switch!!!")


	def install_path(self,event,packet,routes,final_out_port):
		'''installing hashed route from source to destination'''
		self.routes = routes
		self.event = event
		self.packet = packet
		self.final_path = []
		self.hash_ = self._ecmp_hash(packet)
		log.debug('hash_ : %s',str(self.hash_))
		log.debug('len(routes) : %s',str(len(routes)))

		choice = self.hash_ % len(self.routes)
		self.final_path = sorted(self.routes)[choice]
		log.debug('self.final_path : %s',str(self.final_path))

		if self.final_path == None:
		    log.debug('final path is None!!!')
		    return


		match = of.ofp_match.from_packet(packet)

		if match.nw_src != '10.123.123.1' and match.nw_dst != '10.123.123.1' and match.tp_dst != '22':
			s = "\nInstalled_path: " + str(self.final_path) + str(match) + str(time.ctime())
			fd = open('hederalog', 'a')
			fd.write(s)
			fd.close()
			if ((match.nw_src, match.nw_dst, match.tp_src, match.tp_dst) not in self.mtr):
				self.mtr[(match.nw_src, match.nw_dst, match.tp_src, match.tp_dst)] = (0, self.final_path, 0) #(demand, currentPath. isElephant)
				for i in range(0, (len(self.final_path) - 1)):
					self.wt_graph[self.final_path[i]][self.final_path[i+1]]['numFlows'] += 1
					self.wt_graph[self.final_path[i+1]][self.final_path[i]]['numFlows'] += 1

		for i, node in enumerate(self.final_path):
			node_dpid = node
			if i < len(self.final_path) - 1:
			    next_node = self.final_path[i + 1]
			    out_port = self.port_info[node][next_node]
			    next_in_port = self.port_info[next_node][node]
			else:
			    out_port = final_out_port
			log.debug('node_dpid : %s',str(node_dpid))

			self.switches[node_dpid].install(out_port, match, next_in_port,idle_timeout = 10,buf = None)

		self.raiseEvent(NewFlow(self.final_path, match))

			
	def _handle_ConnectionUp (self, event):
		'''handling ConnectionUp'''
		sw = self.switches.get(event.dpid)
		sw_str = dpidToStr(event.dpid)

		if sw is None:
		    sw = Switch()
		    self.switches[event.dpid] = sw
		    sw.connect(event.connection)
		    self.raiseEvent(NewSwitch(sw))


	def _handle_HostEvent (self, event):
	    """ Here is the place where is used the listener"""
	    print "Host, switchport and switch..." + str(event.entry)

	def _handle_ConnectionDown(self, event):
		log.info("Switch %s going down", util.dpid_to_str(event.dpid))
		del self.switches[event.dpid]

	def _flushWtGraph(self):
		for k,v in self.wt_graph.iteritems():
			for k1,v1 in v.iteritems():
				if self.wt_graph[k][k1]['numFlows'] == 0:
					self.wt_graph[k][k1]['weight'] = 0

	def _getMaxPathWeight(self, path):
		if len(path) == 0:
			return 0
		maxwt = 0
		for i in range(0, (len(path) - 1)):
			weight = self.wt_graph[path[i]][path[i+1]]['weight']
			if weight > maxwt:
				maxwt = weight
		return maxwt

	def _getPathWeight(self, path):
		if len(path) == 0:
			return 0
		weight = 0
		for i in range(0, (len(path) - 1)):
			weight += self.wt_graph[path[i]][path[i+1]]['weight']
		return (weight / len(path))

	def _getPathCongestion(self, path):
		if len(path) == 0:
			return 0
		cong = 0
		for i in range(0, (len(path) - 1)):
			cong += self.wt_graph[path[i]][path[i+1]]['numFlows']
		return (cong / (len(path)-1))

	def _getAllPaths(self, flow):
		src_switch = flow['src']
		dst_switch = flow['dst']
		path = self.dijkstra(self.graph, src_switch)
		paths = self.get_routes(path, src_switch, dst_switch)
		for i in range(len(paths)):
			if (len(paths[i]) <= 1):
				paths.remove(paths[i])
		for i in range(len(paths)):
			paths[i].insert(0,dst_switch)
			paths[i].reverse()
		return paths		

	def _handle_NewStats(self, event):
		'''Handle new elephant flow statistics gathered.'''
		log.debug("NewStats triggered")
		hostList = []
		handleFlows = []
		tes = 1

		# Update number of elephants for the flows captured. Later used for path selection
		for i in range(0, len(event.flows)):
			match = event.flows[i]['match']
			if not self.mtr.has_key(((match.nw_src, match.nw_dst, match.tp_src, match.tp_dst))):
				continue
			currentDemand, currentPath, ie = self.mtr[(match.nw_src, match.nw_dst, match.tp_src, match.tp_dst)]
			if not ie:
				self.mtr[(match.nw_src, match.nw_dst, match.tp_src, match.tp_dst)] = (currentDemand, currentPath, 1)
				for j in range(0, (len(currentPath) - 1)):
					self.wt_graph[currentPath[j]][currentPath[j+1]]['elephants'] += 1
					self.wt_graph[currentPath[j+1]][currentPath[j]]['elephants'] += 1

		# Filtering
		for i in range(0, len(event.flows)):
			src = self.macTable[event.flows[i]['src']].dpid
			dst = self.macTable[event.flows[i]['dst']].dpid
			event.flows[i]['src'] = src
			event.flows[i]['dst'] = dst
			match = event.flows[i]['match']
			if not self.mtr.has_key(((match.nw_src, match.nw_dst, match.tp_src, match.tp_dst))):
				continue
			currentDemand, currentPath, ie = self.mtr[(match.nw_src, match.nw_dst, match.tp_src, match.tp_dst)]
			linkWt = 0
			flowAdded = 0

			fq = open('flowSequence', 'a')
			if tes == 1:
				tes = 0
				fq.write("\n\nNew Flow stats recvd:" + str(time.ctime()))
			fq.write("\n" + str(match) + "\nDemand is : " + str(event.flows[i]['demand']))
			fq.close()

			for j in range(0, (len(currentPath) - 1)):
				if not self.wt_graph.has_key(currentPath[j])\
				 or not self.wt_graph[currentPath[j]].has_key(currentPath[j+1])\
				 or not self.wt_graph[currentPath[j]][currentPath[j+1]].has_key('weight'):
				   break

				if self.wt_graph[currentPath[j]][currentPath[j+1]]['weight'] > 0:
					self.wt_graph[currentPath[j]][currentPath[j+1]]['weight'] -= currentDemand
					self.wt_graph[currentPath[j+1]][currentPath[j]]['weight'] -= currentDemand
				linkWt = self.wt_graph[currentPath[j]][currentPath[j+1]]['weight']
				linkWt += event.flows[i]['demand']
				cong = self.wt_graph[currentPath[j]][currentPath[j+1]]['elephants']
				# Check if the path is congested with a factor more than 1 and demand is more than 0.5
				if linkWt > 0.5 and cong > 1 and not flowAdded:
					handleFlows.append(event.flows[i])
					flowAdded = 1
					break
			if not flowAdded:
				# This means that the flow wasn't considered for rerouting
				for j in range(0, (len(currentPath) - 1)):
					self.wt_graph[currentPath[j]][currentPath[j+1]]['weight'] += event.flows[i]['demand']
					self.wt_graph[currentPath[j+1]][currentPath[j]]['weight'] += event.flows[i]['demand']
			self.mtr[(match.nw_src, match.nw_dst, match.tp_src, match.tp_dst)] = (event.flows[i]['demand'], currentPath, 1)

		# Rerouting if possible
		for flow in handleFlows:
			#1. find all possible paths for this match
			paths = self._getAllPaths(flow)
			#2. select the least weighted path
			match = flow['match']
			minWt = 100
			if not self.mtr.has_key(((match.nw_src, match.nw_dst, match.tp_src, match.tp_dst))):
				continue
			currentDemand, currentPath, ie = self.mtr[(match.nw_src, match.nw_dst, match.tp_src, match.tp_dst)]

			for p in paths:
				estWt = self._getMaxPathWeight(p) + flow['demand']
				if minWt > estWt:
					minWt = estWt
					insPath = p

			#TODO Try utilizing all the core switches. keeping track of
			#3. update selected path weight and congestion
			#4. install			
			if insPath != currentPath:
				for i in range(0, (len(insPath) - 1)):
					self.wt_graph[insPath[i]][insPath[i+1]]['weight'] += flow['demand']
					self.wt_graph[insPath[i+1]][insPath[i]]['weight'] += flow['demand']
					self.wt_graph[insPath[i]][insPath[i+1]]['numFlows'] += 1
					self.wt_graph[insPath[i+1]][insPath[i]]['numFlows'] += 1
					self.wt_graph[insPath[i]][insPath[i+1]]['elephants'] += 1
					self.wt_graph[insPath[i+1]][insPath[i]]['elephants'] += 1

				for j in range(0, (len(currentPath) - 1)):
					if self.wt_graph[currentPath[j]][currentPath[j+1]]['numFlows'] > 0:
						self.wt_graph[currentPath[j]][currentPath[j+1]]['numFlows'] -= 1
						self.wt_graph[currentPath[j+1]][currentPath[j]]['numFlows'] -= 1
					if self.wt_graph[currentPath[j]][currentPath[j+1]]['elephants'] > 0:
						self.wt_graph[currentPath[j]][currentPath[j+1]]['elephants'] -= 1
						self.wt_graph[currentPath[j+1]][currentPath[j]]['elephants'] -= 1
						if self.wt_graph[currentPath[i]][currentPath[i+1]]['elephants'] == 0:
							self.wt_graph[currentPath[i]][currentPath[i+1]]['weight'] = 0
							self.wt_graph[currentPath[i+1]][currentPath[i]]['weight'] = 0

				self.mtr[(match.nw_src, match.nw_dst, match.tp_src, match.tp_dst)] = (flow['demand'], insPath, 1)
				self._install_LC_path(insPath, flow['match'])
			else:
				# No alternative path could be found
				for j in range(0, (len(currentPath) - 1)):
					self.wt_graph[currentPath[j]][currentPath[j+1]]['weight'] += flow['demand']
					self.wt_graph[currentPath[j+1]][currentPath[j]]['weight'] += flow['demand']

		fw = open('grpwt', 'a')
		fw.write(json.dumps(self.wt_graph, sort_keys=True, indent=2))
		fw.write("\n")
		fw.close()
		fw = open('edge', 'a')
		s = "congestion for 10.0.0.1\n"
		s += str(self.wt_graph[2001][3001]['weight'] + self.wt_graph[2002][3001]['weight'])
		fw.write(s)
		fw.write("\n")
		fw.close()

# Install the least congested path selected from above algo.
	def _install_LC_path(self, LC_route, match):
		flow_match = match
		_route, match = self.matchDict[match.nw_src, match.nw_dst, match.tp_src, match.tp_dst]
		if _route != LC_route :#and str(LC_route) not in self.elephantsHandled:
			self.elephantsHandled[str(LC_route)] = match
			s = "\nLC_route: " + str(LC_route) + str(match) + str(time.ctime())
			fd = open('hederalog', 'a')
			fd.write(s)
			s = "\nOld_route: " + str(_route)
			fd.write(s)
			fd.close()
			log.info("Installing LC path")
			for i, node in enumerate(LC_route):
				node_dpid = node
				if i < len(LC_route) - 1:
					next_node = LC_route[i + 1]
					out_port = self.port_info[node][next_node]
					next_in_port = self.port_info[next_node][node]
				else:
					out_port = self.macTable[match.dl_dst].port
				log.debug('node_dpid : %s',str(node_dpid))

				self.switches[node_dpid].install_prio(out_port, match, next_in_port,idle_timeout = 10,buf = None)#,prio=65535)
			self.matchDict[match.nw_src, match.nw_dst, match.tp_src, match.tp_dst] = (LC_route, match)
			self.raiseEvent(NewFlow(LC_route, match))

	def _handle_FlowRemoved(self, event):
		if hasattr(event, 'match'):
			match = event.match
			if match.nw_dst != '10.123.123.1' and match.nw_src != '10.123.123.1' and \
			self.mtr.has_key(((match.nw_src, match.nw_dst, match.tp_src, match.tp_dst))):
				fd = open('removedflows', 'a')
				s = "\n Flow removed: " + str(event.match) + str(time.ctime())
				fd.write(s)
				fd.close()
				demand, path, ie = self.mtr[(match.nw_src, match.nw_dst, match.tp_src, match.tp_dst)]
				for i in range(0, (len(path) - 1)):
					if self.wt_graph[path[i]][path[i+1]]['numFlows'] > 0:
						self.wt_graph[path[i]][path[i+1]]['numFlows'] -= 1
						self.wt_graph[path[i+1]][path[i]]['numFlows'] -= 1
					if self.wt_graph[path[i]][path[i+1]]['weight'] > 0:
						self.wt_graph[path[i]][path[i+1]]['weight'] -= demand
						self.wt_graph[path[i+1]][path[i]]['weight'] -= demand
					if self.wt_graph[path[i]][path[i+1]]['elephants'] > 0:
						self.wt_graph[path[i]][path[i+1]]['elephants'] -= 1
						self.wt_graph[path[i+1]][path[i]]['elephants'] -= 1
						if self.wt_graph[path[i]][path[i+1]]['elephants'] == 0:
							self.wt_graph[path[i]][path[i+1]]['weight'] = 0
							self.wt_graph[path[i+1]][path[i]]['weight'] = 0
				del self.mtr[(match.nw_src, match.nw_dst, match.tp_src, match.tp_dst)]
#def start_me():
#	ECMP()

class ECMP_forwarding(EventMixin):
	def __init__(self):
		core.openflow.addListeners(self)

		def start_me():
			ECMP()

		core.call_when_ready(start_me, "openflow_discovery")		

   

def launch ():
	#from host_tracker import launch
	#launch()
	from flowmonitorH import launch
	launch(postfix=datetime.now().strftime("%Y%m%d%H%M%S"))
	core.registerNew(ECMP_forwarding)
