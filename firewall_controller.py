# Jacob McClure
# SDN Firewall using OpenFlow and Mininet

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can send it messages!
    self.connection = connection

    # This binds the PacketIn event listener
    connection.addListeners(self)

  def do_firewall (self, packet, packet_in):
    # The section will execute for every single packet
    msg = of.ofp_flow_mod()                        # create a flow_mod to send packets
    msg.match = of.ofp_match.from_packet(packet)   # setting the match
    check_icmp = packet.find('icmp')               # is packet icmp? (boolean variable)
    check_arp = packet.find('arp')                 # is packet arp? (boolean variable)
    check_tcp = packet.find('tcp')                 # is packet tcp? (boolean variable)
    check_ipv4 = packet.find('ipv4')               # is packet ipv4? (boolean variable)
    
    # Case 1: ICMP packet
    if check_icmp is not None:
      msg.data = packet_in              # allow switch to transmit the packet to the controller
      msg.nw_proto = 1                  # network protocol for ICMP is 1
      out_action = of.ofp_action_output(port = of.OFPP_FLOOD) # flood packet: send to all ports
      msg.actions.append(out_action)
      self.connection.send(msg)         # flood if packet is ICMP
    
    # Case 2: ARP packet
    elif check_arp is not None:
      msg.data = packet_in              # allow switch to transmit the packet to the controller
      msg.dl_type = 0x0806              # datalink layer uses ARP
      out_action = of.ofp_action_output(port = of.OFPP_FLOOD) # flood (send to all ports)
      msg.actions.append(out_action)    # append the action (flood)
      self.connection.send(msg)         # flood if packet is ARP
    
    # Case 3: TCP packet
    # rule: only allow TCP traffic to flow between host1 and host3
    elif check_tcp is not None:
      if ((check_ipv4.dstip == '10.0.1.30' and check_ipv4.srcip == '10.0.1.10') 
      or (check_ipv4.dstip == '10.0.1.10' and check_ipv4.srcip == '10.0.1.30')):
        # allow switch to transmit the packet to the controller
        msg.data = packet_in
        out_action = of.ofp_action_output(port = of.OFPP_FLOOD)   # flood (send to all ports)
        msg.actions.append(out_action)                            # append the action
        self.connection.send(msg)               # flood if packet is TCP to all ports)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
