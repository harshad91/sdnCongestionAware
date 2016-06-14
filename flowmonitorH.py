#!/usr/bin/env python

"""
FlowMonitor

Requires openflow.discovery and ecmp
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.revent.revent import EventMixin, Event
import pox.lib.util as util
from pox.lib.recoco import Timer

from datetime import datetime

from collections import defaultdict
from collections import namedtuple
import pox.lib.packet as pkt
from pox.openflow.of_json import flow_stats_to_list
import struct
from pox.lib.addresses import IPAddr,EthAddr
import time
import pdb
# import logging

log = core.getLogger()
# fh = logging.FileHandler("log.txt")
# formatter = logging.Formatter("%(asctime)s - %(message)s")
# fh.setFormatter(formatter)
# log.addHandler(fh)

switches = {}

monitored_paths = {}
monitored_pathsByMatch = {}
monitored_pathsBySwitch = {}

pathIterator = {}
barrier = {}


prev_stats = defaultdict(lambda:defaultdict(lambda:None))

Payload = namedtuple('Payload', 'pathId timeSent')


class ofp_match_withHash(of.ofp_match):
	##Our additions to enable indexing by match specifications
	@classmethod
	def from_ofp_match_Superclass(cls, other):	
		match = cls()
		
		match.wildcards = other.wildcards
		match.in_port = other.in_port
		match.dl_src = other.dl_src
		match.dl_dst = other.dl_dst
		match.dl_vlan = other.dl_vlan
		match.dl_vlan_pcp = other.dl_vlan_pcp
		match.dl_type = other.dl_type
		match.nw_tos = other.nw_tos
		match.nw_proto = other.nw_proto
		match.nw_src = other.nw_src
		match.nw_dst = other.nw_dst
		match.tp_src = other.tp_src
		match.tp_dst = other.tp_dst
		return match
		
	def __hash__(self):
		return hash((self.wildcards, self.in_port, self.dl_src, self.dl_dst, self.dl_vlan, self.dl_vlan_pcp, self.dl_type, self.nw_tos, self.nw_proto, self.nw_src, self.nw_dst, self.tp_src, self.tp_dst))

#Events used for communicating with LCP logic
class NewStats(Event):
	def __init__(self, flows):
		self.flows = flows

class FlowRemoved(Event):
	def __init__(self, match):
		self.match = match

class Monitoring (EventMixin):
	_eventMixin_events = set([
							NewStats,
							FlowRemoved,
							])

	def _timer_MonitorPaths(self):
		log.debug("Monitoring paths %s", str(datetime.now()))
		
		def AdaptiveTimer():
			changed = False
			#Increase or decrease the timers based on the throughput resuts measured based on the flowstats reply		
			if(self.increaseTimer == True):
				self.t._interval /= 1
				changed = True
			elif(self.decreaseTimer == True):
				self.t._interval *= 1.125
				changed = True
			
			#maximize the interval
			if self.t._interval > 60:
				self.t._interval = 60
				
			#minimize the interval
			if self.t._interval < 1:
				self.t._interval = 1
			
			#update next timer if, and only if, the timer has changed
			if changed == True:
				self.t._next = time.time() + self.t._interval
			
			#Reset input from received flowstats
			self.increaseTimer = False
			self.decreaseTimer = True		
		
		def LastSwitch():
			switchRead = {}
			for dpid in switches:
				switchRead[dpid] = False
				
			for p in monitored_paths: #Walk through all distinct paths and select both last and first switch to calculate throughput and packet loss.
				if switchRead[p[-1]] == False:
					switchRead[p[-1]] = True
					msg = of.ofp_stats_request(body=of.ofp_flow_stats_request())
					switches[p[-1]].connection.send(msg)
				
				if switchRead[p[0]] == False:
					switchRead[p[0]] = True
					msg = of.ofp_stats_request(body=of.ofp_flow_stats_request())
					switches[p[0]].connection.send(msg)
		
		AdaptiveTimer() #use to experiment with the adaptive timer)
		
		LastSwitch() #use to experiment with lastswitch switch selection
		
	def _send_flowsToEcmp(self):
		self.toSend = 1
		
	def __init__ (self,postfix):
		log.debug("Monitoring coming up")
		#from ecmp import ofp_match_withHash

		#self.ofp_match_withHash = ofp_match_withHash


		def startup():
			
			core.openflow.addListeners(self, priority=0xfffffffe) #took 1 priority lower as the discovery module, although it should not matter			
			
			self.decreaseTimer = False
			self.increaseTimer = False
			self.t = Timer(1, self._timer_MonitorPaths, recurring = True)
			
			
			self.f = open("output.%s.csv"%postfix, "w")
			#self.f.write("Experiment,Switch,SRC_IP,DST_IP,SRC_PORT,DST_PORT,Packet_Count,Byte_Count,Duration_Sec,Duration_Nsec,Delta_Packet_Count,Delta_Byte_Count,Delta_Duration_Sec,Delta_Duration_Nsec\n")
			self.f.flush()
			
			self.f2 = open("delay.%s.csv"%postfix, "w")
			self.f2.write("MeasurementType,Src/Initiator,Dst/Switch,Delay\n")
			self.f2.flush()
			
			self.experiment = postfix

			self.toSend = 0
			self.flows = []
			self.flowSendTimer = Timer(20, self._send_flowsToEcmp, recurring = True)
			self.bw = 0.01 #10 Mbps WRT 1Gbps. Here 1Gbps is 1
			log.debug("Monitoring started")			
	
		core.call_when_ready(startup, ('openflow_discovery')) #Wait for opennetmon-forwarding to be started
		
	def __del__(self):
		
		self.f.close()
	
	def _handle_NewSwitch (self, event):
		switch = event.switch
		log.debug("New switch to Monitor %s", switch.connection)
		switches[switch.connection.dpid] = switch
		switch.addListeners(self)
		
	def _handle_NewFlow(self, event):
		match = event.match
		path = event.path
		log.debug("New flow to monitor %s", str(path))
		spath = tuple(path)
				
		if spath not in monitored_paths.keys():
			monitored_paths[spath] = set([match])
		else:
			monitored_paths[spath].add(match)
			
		monitored_pathsByMatch[match] = spath

	def _handle_FlowRemoved(self, event):
		match = ofp_match_withHash.from_ofp_match_Superclass(event.ofp.match)
		path = monitored_pathsByMatch.pop(match, None)
		if path is not None:
			monitored_paths[path].remove(match)
			if not monitored_paths[path]:
				del monitored_paths[path]
		self.raiseEvent(FlowRemoved(match))

	def _handle_FlowStatsReceived(self, event):		
		#pdb.set_trace()
		#stats = flow_stats_to_list(event.stats)
		
		dpid = event.connection.dpid
		print dpid
		for stat in event.stats:
			
			match = ofp_match_withHash.from_ofp_match_Superclass(stat.match)
			if match.dl_type != pkt.ethernet.LLDP_TYPE and not (match.dl_type == pkt.ethernet.IP_TYPE and match.nw_proto == 253 and match.nw_dst == IPAddr("224.0.0.255")):
				if match not in prev_stats or dpid not in prev_stats[match]:
					prev_stats[match][dpid] = 0, 0, 0, 0, -1.0
				prev_packet_count, prev_byte_count, prev_duration_sec, prev_duration_nsec, prev_throughput = prev_stats[match][dpid]
				
				delta_packet_count = stat.packet_count - prev_packet_count
				delta_byte_count = stat.byte_count - prev_byte_count
				delta_duration_sec = stat.duration_sec - prev_duration_sec
				delta_duration_nsec = stat.duration_nsec - prev_duration_nsec
				
				if ((delta_duration_nsec > 0) and (match.nw_src is not None) and (match.nw_dst is not None)):
					cur_throughput = delta_byte_count / (delta_duration_sec + (delta_duration_nsec / 1000000000.0))
					timeString = datetime.now().strftime("%H:%M:%S.%f")[:-3]
					log.debug("Stat switch: %s\tnw_src: %s\tnw_dst: %s\tnw_proto: %s\tpacketcount: %d\t bytecount: %d\t duration: %d s + %d ns\t, delta_packetcount: %d, delta_bytecount: %d, delta_duration: %d s + %d ns, throughput: %f", util.dpid_to_str(dpid), match.nw_src, match.nw_dst, match.nw_proto, stat.packet_count, stat.byte_count, stat.duration_sec, stat.duration_nsec, delta_packet_count, delta_byte_count, delta_duration_sec, delta_duration_nsec, cur_throughput)
					self.f.write("%s,%s,%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s,%f\n"%(timeString, util.dpid_to_str(dpid), match.nw_src, match.nw_dst, match.nw_proto, stat.packet_count, stat.byte_count, stat.duration_sec, stat.duration_nsec, delta_packet_count, delta_byte_count, delta_duration_sec, delta_duration_nsec,match.tp_src,match.tp_dst, cur_throughput))
				
					#influence the timer by inspecting the change in throughput 
					if abs(cur_throughput - prev_throughput) > .05 * prev_throughput:
						self.decreaseTimer = False
					if abs(cur_throughput - prev_throughput) > .20 * prev_throughput:
						self.increaseTimer = True
					
					#log.debug("Stat switch: %s\tdl_type: %d\tnw_src: %s\tnw_dst: %s\tproto: %s\tsrc_port: %s\t dst_port: %s\tpacketcount: %d\t bytecount: %d\t duration: %d s + %d ns, delta_packetcount: %d, delta_bytecount: %d, delta_duration: %d s + %d ns", util.dpid_to_str(dpid), match.dl_type, match.nw_src, match.nw_dst, match.nw_proto, match.tp_src, match.tp_dst, stat.packet_count, stat.byte_count, stat.duration_sec, stat.duration_nsec, delta_packet_count, delta_byte_count, delta_duration_sec, delta_duration_nsec)
					#self.f.write("%s,%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n"%(self.experiment, util.dpid_to_str(dpid), match.nw_src, match.nw_dst, match.tp_src, match.tp_dst, stat.packet_count, stat.byte_count, stat.duration_sec, stat.duration_nsec, delta_packet_count, delta_byte_count, delta_duration_sec, delta_duration_nsec))
					
					self.f.flush()
					prev_stats[match][dpid] = stat.packet_count, stat.byte_count, stat.duration_sec, stat.duration_nsec, cur_throughput
					if match.nw_dst != '10.123.123.1' and match.nw_src != '10.123.123.1' and match.tp_src != '22' and match.tp_dst != '22':
						flowLivingTime = stat.duration_sec * 1e9 + stat.duration_nsec
						if flowLivingTime <= 1:
							flowLivingTime = 1
						flowDemand = 8* float(stat.byte_count) / flowLivingTime
						flowDemand = flowDemand / self.bw
						if flowDemand > 0.1:
							print "*********************Demand greater than 0.1***************************"
							found = 0
							index = 0
							for flow in self.flows:
								if flow.has_key('match') and flow['match'] == stat.match:
									found = 1
									index = self.flows.index(flow)
							if found:
								self.flows[index] = {'demand': flowDemand, 'converged': False, 'recLimited': False, 'match': stat.match, 'src': match.dl_src, 'dst': match.dl_dst}
							else:
								self.flows.append({'demand': flowDemand, 'converged': False, 'recLimited': False, 'match': stat.match, 'src': match.dl_src, 'dst': match.dl_dst})
				else:
					pass
					# log.debug('delta_duration_nsec is %s',str(delta_duration_nsec))
		if len(self.flows) > 0 and self.toSend:
			#print "New stats triggered " + str(self.flows)
			#import pdb;pdb.set_trace()
			self.toSend = 0
			temp = self.flows
			self.flows = []
			self.raiseEvent(NewStats(temp))

	def _handle_PacketIn(self, event):
		#log.debug("Incoming packet")
		timeRecv = time.time()
		packet = event.parsed
		if packet.effective_ethertype != pkt.ethernet.IP_TYPE:
			return
		ip_pck = packet.find(pkt.ipv4)
		if ip_pck is None or not ip_pck.parsed:
			log.error("No IP packet in IP_TYPE packet")
			return EventHalt
		
		if ip_pck.protocol != 253 or ip_pck.dstip != IPAddr("224.0.0.255"):
			#log.debug("Packet is not ours, give packet back to regular packet manager")
			return
		else:
			#log.debug("Received monitoring packet, with payload %s."%(ip_pck.payload))
			payload = eval(ip_pck.payload)
			
			log.debug("Delay from switch %s to %s = %f"%(EthAddr(packet.src), EthAddr(packet.dst), timeRecv - payload.timeSent ))
			self.f2.write("Path,%s,%s,%f\n"%(EthAddr(packet.src), EthAddr(packet.dst), timeRecv - payload.timeSent) )
			self.f2.flush()
			return EventHalt

def launch (postfix=datetime.now().strftime("%Y%m%d%H%M%S")):
	
	"""
	Starts the component
	"""
	core.registerNew(Monitoring, postfix)
	



