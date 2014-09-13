# Copyright 2013 James McCauley
# Copyright 2014 Antonis Manousis
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A kind of sloppy NAT component.

Required commandline parameters:
  --dpid            The DPID to NAT-ize
  --outside-port=X  The port on DPID that connects "upstream" (e.g, "eth0")

Optional parameters:
  --subnet=X        The local subnet to use (e.g., "192.168.0.1/24")
  --inside-ip=X     The inside-facing IP address the switch will claim to be

To get this to work with Open vSwitch, you probably have to disable OVS's
in-band control with something like:
  ovs-vsctl set bridge s1 other-config:disable-in-band=true

Please submit improvements. :)
"""
from threading import Timer
from time import *
from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
import pox.lib.packet as pkt

from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
from pox.lib.util import str_to_bool, dpid_to_str, str_to_dpid
from pox.lib.revent import EventMixin, Event
from pox.lib.recoco import Timer
import pox.lib.recoco as recoco

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.messenger
import pox.host_tracker
from pox.proto.dhcpd import DHCPD, SimpleAddressPool

import time
import random

FLOW_TIMEOUT = 60
FLOW_MEMORY_TIMEOUT = 60 * 10


class Record (object):
  def __init__ (self):
    self.touch()
    self.outgoing_match = None
    self.incoming_match = None
    self.real_srcport = None
    self.fake_srcport = None
    self.fake_dstport = None
    self.outgoing_fm = None
    self.incoming_fm = None

  @property
  def expired (self):
    return time.time() > self._expires_at

  def touch (self):
    self._expires_at = time.time() + FLOW_MEMORY_TIMEOUT

  def __str__ (self):
    s = "%s:%s" % (self.outgoing_match.nw_src, self.real_srcport)
    if self.fake_srcport != self.real_srcport:
      s += "/%s" % (self.fake_srcport,)
    s += " -> %s:%s" % (self.outgoing_match.nw_dst, self.outgoing_match.tp_dst)
    return s

class NAT (object):
  def __init__ (self, inside_ip, outside_ip, gateway_ip, dns_ip, outside_port,
      dpid, subnet = None):


    self.inside_ip = inside_ip
    self.outside_ip = outside_ip
    self.gateway_ip = gateway_ip
    self.dns_ip = dns_ip # Or None
    self.outside_port = outside_port
    self.dpid = dpid
    self.subnet = subnet

    self._outside_portno = None
    self._gateway_eth = None
    self._connection = None

    #Information about machines in the network
    self._mac_to_port = {}  # to reach x host we need to send traffic through port y
    self._ip_to_mac = {}    # host x's mac is tied with this ip
    self._ip_to_port = {}   # to reach x host we need to send traffic through port y

    # Which NAT ports have we used?
    # proto means TCP or UDP
    self._used_ports = set() # (proto,port)

    #Which NAT ports have we used for forwarding rules ?
    self._forwarding = {} # (key=port, value=IP)

    #Match ICMP seq numbers to IPs
    self._icmp_seq = {}

    # Flow records indexed in both directions
    # match -> Record
    self._record_by_outgoing = {}
    self._record_by_incoming = {}

    core.listen_to_dependencies(self)

  def _handle_core_ComponentRegistered(self,event):
    print event.name
    if event.name == "host_tracker":
      event.component.addListenerByName("HostEvent",
              self._handle_host_tracker_HostEvent)
    elif event.name == "messenger":
      event.component.addListenerByName("MessengerEvent",
              self.__handle_messenger_MessengerEvent)

  def __handle_messenger_MessengerEvent(self, event):
      print event.port
      #if event.join == True:
      #    self._forwarding[event.port] = event.ip
      #elif event.leave == True
      #    del self._forwarding[event.port]
      #### TRACK OVS PORT FOR THIS NIC
      #### self._mac_to_port[event.mac] = port
      #### self._ip_to_mac...
      #### self._ip_to_port...

  def _handle_host_tracker_HostEvent(self,event):
    self._mac_to_port[event.entry.macaddr]=event.entry.port
    #Add ping checks for the entries ?
    for key in event.entry.ipAddrs:
        if key in self._ip_to_mac:
            print "need to delete old port for port forwarding"
            for fport in self._forwarding:
                if self._forwarding[fport] == key:
                    #use dictionary comprehension instead.
                    del self._forwarding[fport]
                    self._used_ports.remove(('tcp',fport))
        self._forwarding[self._pick_forwarding_port()] = IPAddr(key)
        self._ip_to_mac[key] = event.entry.macaddr
        self._ip_to_port[key]= event.entry.port

  def _all_dependencies_met (self):
    log.debug('Trying to start...')
    if self.dpid in core.openflow.connections:
      self._start(core.openflow.connections[self.dpid])
    else:
      core.openflow.addListenerByName('ConnectionUp',
          self.__handle_dpid_ConnectionUp)

    self.expire_timer = Timer(60, self._expire, recurring = True)

  def _expire (self):
    dead = []
    for r in self._record_by_outgoing.itervalues():
      if r.expired:
        dead.append(r)

    for r in dead:
      del self._record_by_outgoing[r.outgoing_match]
      del self._record_by_incoming[r.incoming_match]
      #edw thelei veltiwsi i diagrafi fake_srcport i fake dstport?
      self._used_ports.remove((r.outgoing_match.nw_proto,r.fake_srcport))

    if dead and not self._record_by_outgoing:
      log.debug("All flows expired")

  def _remove_entry(self, dic, key):
      del dic[key]

  def _is_local (self, ip):
    if ip.is_multicast: return True
    if self.subnet is not None:
      if ip.in_network(self.subnet): return True
      return False
    if ip.in_network('192.168.0.0/16'): return True
    if ip.in_network('10.0.0.0/8'): return True
    if ip.in_network('172.16.0.0/12'): return True
    return False

  def _pick_port (self, flow):
    """
    Gets a possibly-remapped outside port

    flow is the match of the connection
    returns port (maybe from flow, maybe not)
    """

    port = flow.tp_src

    if port < 1024:
      # Never allow these
      port = random.randint(49152, 65534)

    # Pretty sloppy!

    cycle = 0
    while cycle < 2:
      if (flow.nw_proto,port) not in self._used_ports:
        self._used_ports.add((flow.nw_proto,port))
        return port
      port += 1
      if port >= 65534:
        port = 49152
        cycle += 1

    log.warn("No ports to give!")
    return None

  def _pick_forwarding_port (self):

      port = random.randint(49152, 65534)
      cycle = 0
      while cycle < 5:
          if ('tcp',port) not in self._used_ports:
              self._used_ports.add(('tcp',port))
              print port
              return port
          port+=1
          if port >= 65534:
            port = 49152
            cycle +=1
      log.warn("No ports to give")
      return None

  @property
  def _outside_eth (self):
    if self._connection is None: return None
    return self._connection.ports[self._outside_portno].hw_addr

  def _handle_FlowRemoved (self, event):
    pass

  @staticmethod
  def strip_match (o):
    m = of.ofp_match()

    fields = 'dl_dst dl_src nw_dst nw_src tp_dst tp_src dl_type nw_proto'

    for f in fields.split():
      setattr(m, f, getattr(o, f))

    return m

  @staticmethod
  def make_match (o):
    return NAT.strip_match(of.ofp_match.from_packet(o))

  def forward_icmp(self,event):
    packet = event.parsed
    icmp_rec = packet.find('echo')
    #Create ICMP ECHO REQUEST
    icmp=pkt.icmp()
    icmp.type = pkt.TYPE_ECHO_REQUEST
    icmp.payload = packet.find('icmp').payload

    #Wrap it in an IP packet
    ipp = pkt.ipv4()
    ipp.protocol = ipp.ICMP_PROTOCOL
    ipp.srcip = self.outside_ip
    ipp.dstip = packet.find('ipv4').dstip

    #Wrap it in an Ethernet frame
    e = pkt.ethernet()
    e.dst = self._gateway_eth  #EthAddr(self._ip_to_mac[self._icmp_seq[icmp_rec.id]])
    e.src = self._outside_eth #EthAddr(self._connection.ports[self._mac_to_port[e.dst]].hw_addr)
    e.type = e.IP_TYPE

    ipp.payload=icmp
    e.payload = ipp

    #Send
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = self._outside_portno))
    msg.data = e.pack()
    msg.in_port = event.port
    event.connection.send(msg)

  def respond_to_icmp(self,event):
    packet=event.parsed
    icmp_rec = packet.find('echo')
    print "icmp id " + str(icmp_rec.id)
    print self._icmp_seq
    #Create ICMP ECHO REPLY
    icmp = pkt.icmp()
    icmp.type = pkt.TYPE_ECHO_REPLY
    icmp.payload = packet.find('icmp').payload

    #Wrap it in an IP packet
    ipp = pkt.ipv4()
    ipp.protocol = ipp.ICMP_PROTOCOL
    if icmp_rec.id not in self._icmp_seq:
      ipp.srcip = packet.find('ipv4').dstip
      ipp.dstip = packet.find('ipv4').srcip
    else:
      ipp.srcip = packet.find('ipv4').srcip
      ipp.dstip = IPAddr(self._icmp_seq[icmp_rec.id])

    #Wrap it in an Ethernet frame
    e = pkt.ethernet()
    if icmp_rec.id not in self._icmp_seq:
      e.src = packet.dst
      e.dst = packet.src
    else:
      e.dst = EthAddr(self._ip_to_mac[self._icmp_seq[icmp_rec.id]])
      e.src = EthAddr(self._connection.ports[self._mac_to_port[e.dst]].hw_addr)
    e.type = e.IP_TYPE

    ipp.payload=icmp
    e.payload = ipp

    #Send
    msg = of.ofp_packet_out()
    if icmp_rec.id not in self._icmp_seq:
      msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
    else:
      msg.actions.append(of.ofp_action_output(port = self._mac_to_port[e.dst]))
    msg.data = e.pack()
    msg.in_port = event.port
    event.connection.send(msg)


  def _handle_PacketIn (self, event):
    if self._outside_eth is None: return

    print "PACKET",event.connection.ports[event.port].name,event.port,
    print self.outside_port, self.make_match(event.ofp)
    incoming = event.port == self._outside_portno
    log.debug("event.port is %s self._outside_portno is %s",event.port,self._outside_portno)
    if self._gateway_eth is None:
      self._arp_for_gateway()
      return

    packet = event.parsed
    dns_hack = False

    # TCP UDP and ICMP handling
    tcpp = False
    udpp = False
    icmpp = False
    tcpp = packet.find('tcp')
    if tcpp:
        ipp=tcpp.prev
    elif not tcpp:
      udpp = packet.find('udp')
      if udpp:
        if udpp.dstport == 53 and udpp.prev.dstip == self.inside_ip:
            if self.dns_ip and not incoming:
                dns_hack = True
        ipp = udpp.prev
      else:
        icmpp = packet.find('echo')
        if icmpp:
            log.debug("this is a ping")
            ipp = packet.find('icmp').prev
        else:
            return

    log.debug("incoming is %s",incoming)
    if not incoming:
      print "blabla"
    #  # Assume we only NAT public addresses
    #  if self._is_local(ipp.dstip) and not dns_hack:
    #      return
    else:
      # Assume we only care about ourselves
      if ipp.dstip != self.outside_ip: return

    match = self.make_match(event.ofp)

    if incoming:
      log.debug("incoming check")
      match2 = match.clone()
      match2.dl_dst = None # See note below
      record = self._record_by_incoming.get(match)
      #print "match  ="
      #print match
      #print "list of keys and respective records"
      #for key in self._record_by_incoming:
      #    print key
      #    print self._record_by_incoming[key]
      if record is None:
        print "RECORD IS NONE"
        if icmpp:
            if ipp.dstip == self.outside_ip:
                self.respond_to_icmp(event)
                return
        if tcpp:
          if tcpp.dstport in self._forwarding: ##if port can be found in dictionnary of forwarding rules
            record = Record()
            record.real_srcport = tcpp.srcport
            record.fake_srcport = tcpp.dstport
            record.fake_dstport = self._pick_port(match)

            #Port forwarding rule --incoming
            fm = of.ofp_flow_mod()
            log.debug("ADDING MY FLOW")
            fm.flags |= of.OFPFF_SEND_FLOW_REM
            fm.hard_timeout = FLOW_TIMEOUT
            fm.match=match.flip()
            fm.match.in_port = self._outside_portno
            fm.match.nw_src = ipp.srcip
            fm.match.nw_dst = self.outside_ip
            fm.match.tp_dst = tcpp.dstport  ##  the one that corresponds to the given ip
            fm.match.tp_src = tcpp.srcport
            fm.match.dl_src = packet.src
            fm.match.dl_dst = self._outside_eth

            fm.actions.append(of.ofp_action_dl_addr.set_src(self._connection.ports[self._ip_to_port \
                    [self._forwarding[tcpp.dstport]]].hw_addr))
            fm.actions.append(of.ofp_action_dl_addr.set_dst(self._ip_to_mac[self._forwarding[tcpp.dstport]]))
            fm.actions.append(of.ofp_action_nw_addr.set_dst(self._forwarding[tcpp.dstport]))
            fm.actions.append(of.ofp_action_tp_port.set_src(record.fake_dstport)) #fk_port to be added in a record
            fm.actions.append(of.ofp_action_tp_port.set_dst(22))

            fm.actions.append(of.ofp_action_output(port = self._ip_to_port[self._forwarding[tcpp.dstport]])) #50))

            record.incoming_match = self.strip_match(fm.match)
            record.incoming_fm = fm
            log.debug("port forw match %s", record.incoming_match)
            log.debug("Added my flow")

            #event.connection.send(fm)
            # PORT FORWARD OUTGOING RULE

            fm = of.ofp_flow_mod()
            log.debug("Add pf outgoing flow")
            fm.flags |= of.OFPFF_SEND_FLOW_REM
            fm.hard_timeout = FLOW_TIMEOUT
            fm.match=match.flip()
            fm.match.in_port = self._ip_to_port[self._forwarding[tcpp.dstport]]
            fm.match.dl_src = self._ip_to_mac[self._forwarding[tcpp.dstport]]
            fm.match.dl_dst = self._connection.ports[self._ip_to_port[self._forwarding[tcpp.dstport]]].hw_addr
            fm.match.nw_src = self._forwarding[tcpp.dstport]
            fm.match.nw_dst = ipp.srcip
            fm.match.tp_dst = record.fake_dstport
            fm.match.tp_src = 22

            fm.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
            fm.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
            fm.actions.append(of.ofp_action_nw_addr.set_src(self.outside_ip))
            fm.actions.append(of.ofp_action_nw_addr.set_dst(ipp.srcip))
            fm.actions.append(of.ofp_action_tp_port.set_dst(tcpp.srcport))
            fm.actions.append(of.ofp_action_tp_port.set_src(tcpp.dstport))
            fm.actions.append(of.ofp_action_output(port = self._outside_portno))

            record.outgoing_match = self.strip_match(fm.match)
            record.outgoing_fm = fm
            log.debug("%s installed", record)
            log.debug("added outgoing fw flow")

            self._record_by_incoming[record.incoming_match] = record
            self._record_by_outgoing[record.outgoing_match] = record

          else:
            print "I AM ignoring"
            return
      else :
        log.debug("%s reinstalled", record)
        record.incoming_fm.data = event.ofp # Hacky!
    else:
      log.debug("outgoing check")
      if icmpp:
        print icmpp.id
        print icmpp.seq
        print ipp
        if ipp.dstip == self.inside_ip or ipp.dstip == self.outside_ip:
          self.respond_to_icmp(event)
          return
        elif self._is_local(ipp.dstip):   #THERE USED TO BE A NOT THERE IN CASE WE WANT TO PING PUBLIC IPS
          #Logic for mangling outgoing icmp
          #first delete stale sequence numbers - this only allows one session to ping
          #self._icmp_seq = {k:v for k,v in self._icmp_seq.iteritems() if v != ipp.srcip}
          self._icmp_seq[icmpp.id] = ipp.srcip
          self.forward_icmp(event)
          return

      record = self._record_by_outgoing.get(match)
      print "record is not none"
      print record
      if record is None:
        record = Record()
        if tcpp:
          record.real_srcport = tcpp.srcport
        elif udpp:
          record.real_srcport = udpp.srcport
        record.fake_srcport = self._pick_port(match)

        # Outside heading in
        fm = of.ofp_flow_mod()
        fm.flags |= of.OFPFF_SEND_FLOW_REM
        fm.hard_timeout = FLOW_TIMEOUT
        fm.match = match.flip()
        fm.match.in_port = self._outside_portno
        fm.match.nw_dst = self.outside_ip
        fm.match.tp_dst = record.fake_srcport
        fm.match.dl_src = self._gateway_eth
        # We should set dl_dst, but it can get in the way.  Why?  Because
        # in some situations, the ARP may ARP for and get the local host's
        # MAC, but in others it may not.
        #fm.match.dl_dst = self._outside_eth
        fm.match.dl_dst = None

        fm.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
        fm.actions.append(of.ofp_action_nw_addr.set_dst(ipp.srcip))

        if dns_hack:
          fm.match.nw_src = self.dns_ip
          fm.actions.append(of.ofp_action_nw_addr.set_src(self.inside_ip))
        log.debug("real srcport %s face srcport %s",record.real_srcport,record.fake_srcport)
        if record.fake_srcport != record.real_srcport:
          fm.actions.append(of.ofp_action_tp_port.set_dst(record.real_srcport))

        fm.actions.append(of.ofp_action_output(port = event.port))

        record.incoming_match = self.strip_match(fm.match)
        record.incoming_fm = fm

        # Inside heading out
        fm = of.ofp_flow_mod()
        fm.data = event.ofp
        fm.flags |= of.OFPFF_SEND_FLOW_REM
        fm.hard_timeout = FLOW_TIMEOUT
        fm.match = match.clone()
        fm.match.in_port = event.port
        fm.actions.append(of.ofp_action_dl_addr.set_src(self._outside_eth))
        fm.actions.append(of.ofp_action_nw_addr.set_src(self.outside_ip))
        if dns_hack:
          fm.actions.append(of.ofp_action_nw_addr.set_dst(self.dns_ip))
        if record.fake_srcport != record.real_srcport:
          fm.actions.append(of.ofp_action_tp_port.set_src(record.fake_srcport))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(self._gateway_eth))
        fm.actions.append(of.ofp_action_output(port = self._outside_portno))

        record.outgoing_match = self.strip_match(fm.match)
        record.outgoing_fm = fm

        self._record_by_incoming[record.incoming_match] = record
        self._record_by_outgoing[record.outgoing_match] = record

        log.debug("%s installed", record)
      else:
        print "record existed"
        log.debug("%s reinstalled", record)
        record.outgoing_fm.data = event.ofp # Hacky!

    record.touch()

    # Send/resend the flow mods
    if incoming:
      data = record.outgoing_fm.pack() + record.incoming_fm.pack()
    else:
      data = record.incoming_fm.pack() + record.outgoing_fm.pack()
    self._connection.send(data)

    # We may have set one of the data fields, but they should be reset since
    # they won't be valid in the future.  Kind of hacky.
    record.outgoing_fm.data = None
    record.incoming_fm.data = None

  def __handle_dpid_ConnectionUp (self, event):
    if event.dpid != self.dpid:
      return
    self._start(event.connection)

  def _start (self, connection):
    self._connection = connection
    self._outside_portno = connection.ports[self.outside_port].port_no

    #process incoming traffic - to be processed by controller
    fm = of.ofp_flow_mod()
    fm.match.in_port = self._outside_portno
    fm.match.dl_type = 0x800 # IP
    fm.match.nw_dst = self.outside_ip
    fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    fm.priority = 2
    connection.send(fm)

    connection.addListeners(self)

    # Need to find gateway MAC -- send an ARP
    self._arp_for_gateway()

  def _arp_for_gateway (self):
    log.debug('Attempting to ARP for gateway (%s)', self.gateway_ip)
    self._ARPHelper_.send_arp_request(self._connection,
                                      ip = self.gateway_ip,
                                      port = self._outside_portno,
                                      src_ip = self.outside_ip)
#  def _arp_for_host(self, ip):
#      log.debug("Attempting to ARP for host (%s)", ip)
#      self._ARPHelper_.send_arp_request(self._connection,
#                                        ip = ip,
#                                        port=self.ip_to_port[self.inside_ip],
#                                        src_ip = self.inside_ip)

  def _handle_ARPHelper_ARPReply (self, event):
    if event.dpid != self.dpid: return
    if event.port != self._outside_portno: return
    if event.reply.protosrc == self.gateway_ip:
      self._gateway_eth = event.reply.hwsrc
      log.info("Gateway %s is %s", self.gateway_ip, self._gateway_eth)

  def _handle_ARPHelper_ARPRequest (self, event):
    if event.dpid != self.dpid: return

    dstip = event.request.protodst
    if event.port == self._outside_portno:
      if dstip == self.outside_ip:
        if self._connection is None:
          log.warn("Someone tried to ARP us, but no connection yet")
        else:
          event.reply = self._outside_eth
    else:
      if dstip == self.inside_ip or not self._is_local(dstip):
        if self._connection is None:
          log.warn("Someone tried to ARP us, but no connection yet")
        else:
          #event.reply = self._connection.eth_addr
          event.reply = self._connection.ports[event.port].hw_addr

def launch (dpid, outside_port, outside_ip = '10.0.0.2',
            inside_ip = '192.168.0.2'):

  import pox.proto.arp_helper as ah
  ah.launch(use_port_mac = True)
  pox.openflow.discovery.launch()
  pox.host_tracker.launch()
  dpid = str_to_dpid(dpid)
  inside_ip = IPAddr(inside_ip)
  outside_ip = IPAddr(outside_ip)
  dns_ip = IPAddr('8.8.8.8')
  gateway_ip = IPAddr('10.0.0.3')
  log.debug('Starting NAT')

  n = NAT(inside_ip, outside_ip, gateway_ip, dns_ip, outside_port, dpid)
  core.register(n)
