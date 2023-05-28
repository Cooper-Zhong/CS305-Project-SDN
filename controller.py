from ryu.app.ofctl.api import get_datapath
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet.arp import ARP_REPLY
from ryu.ofproto.ofproto_v1_0 import OFPP_CONTROLLER
from ryu.topology import event, switches
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet, ethernet, ether_types, arp, icmp
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import udp
from ryu.topology import api
from ryu.topology.api import get_host
from ryu.topology.switches import Port, Host

from ofctl_utilis import OfCtl, VLANID_NONE, OfCtl_v1_0
from dhcp import DHCPServer
from Graph import Graph, MAX_V


class MyMap:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac

    def __str__(self):
        return 'ip:%s, mac:%s' % (self.ip, self.mac)


class ControllerApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ControllerApp, self).__init__(*args, **kwargs)
        self.hosts = []
        self.network = Graph()
        self.maps = []

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        """
        Event handler indicating a switch has come online.
        """
        print("switch_add")
        print(ev)
        switch = ev.switch
        self.network.add_node(switch.dp.id)
        self.network.nodes.sort()
        self.update_topology()

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        """
        Event handler indicating a switch has been removed
        """
        print("switch_delete")
        print(ev)
        switch = ev.switch
        self.network.delete_node(switch.dp.id)
        self.network.nodes.sort()
        self.update_topology()

    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        """
        Event handler indiciating a host has joined the network
        This handler is automatically triggered when a host sends an ARP response.
        """
        # TODO:  Update network topology and flow rules
        print("host_add")
        print(ev)
        host = ev.host
        self.hosts.append(host)
        self.update_topology()

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        """
        Event handler indicating a link between two switches has been added
        """
        # TODO:  Update network topology and flow rules
        print("link_add")
        print(ev)
        link = ev.link
        self.network.add_edge(link.src.dpid, link.dst.dpid, 1, link.src.port_no)
        self.update_topology()

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        """
        Event handler indicating when a link between two switches has been deleted
        """
        # TODO:  Update network topology and flow rules
        print("link_delete")
        print(ev)
        link = ev.link
        self.network.delete_edge(link.src.dpid, link.dst.dpid)
        self.update_topology()

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        """
        Event handler for when any switch port changes state.
        This includes links for hosts as well as links between switches.
        """
        # TODO:  Update network topology and flow rules
        print("port_modify")
        print(ev)
        src = ev.port.dpid
        port = ev.port.port_no
        self.network.port_on[src][port] = ev.port.is_live()
        self.update_topology()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        try:
            msg = ev.msg
            datapath = msg.datapath
            pkt = packet.Packet(data=msg.data)
            pkt_dhcp = pkt.get_protocols(dhcp.dhcp)
            pkt_arp = pkt.get_protocols(arp.arp)
            inPort = msg.in_port
            if pkt_dhcp:
                DHCPServer.handle_dhcp(datapath, inPort, pkt)
            elif pkt_arp:
                # 将ip和mac加入映射
                map = MyMap(pkt_arp[0].src_ip, pkt_arp[0].src_mac)
                b = True
                src_ip = pkt_arp[0].src_ip
                src_mac = pkt_arp[0].src_mac
                dst_ip = pkt_arp[0].dst_ip
                dst_mac = pkt_arp[0].dst_mac
                src = 0
                dst = 0
                for i in self.maps:
                    if i.ip == src_ip and i.mac == src_mac:
                        b = False
                    if i.ip == dst_ip:
                        dst_mac = i.mac
                if b:
                    self.maps.append(map)
                for host in self.hosts:
                    if host.mac == src_mac:
                        src = host.port.dpid
                    if host.mac == dst_mac:
                        dst = host.port.dpid
                ofctl = OfCtl_v1_0(datapath, self.logger)
                ofctl.send_arp(arp_opcode=ARP_REPLY, vlan_id=VLANID_NONE, dst_mac=src_mac, sender_mac=dst_mac,
                               sender_ip=dst_ip, target_mac=src_mac, target_ip=src_ip, src_port=OFPP_CONTROLLER,
                               output_port=inPort)
                #if dst_mac != '00:00:00:00:00:00':
                #    self.print_path(src, dst, src_mac, dst_mac)
            else:
                pass
            return
        except Exception as e:
            self.logger.error(e)

    def get_out_port(self, datapath, src, dst):
        dpid = datapath.id
        path, path_len = self.network.shortest_path(src, dst)
        if path_len == -1:
            return -1
        next_hop = path[path.index(dpid) + 1]
        out_port = self.network.port[dpid][next_hop]
        return out_port

    def update_topology(self):
        datapaths = get_datapath(self, dpid=None)
        #删除所有流表
        for datapath in datapaths:
            ofctl = OfCtl_v1_0(datapath, self.logger)
            ofctl.delete_flow(0, 0)
        self.network.paths = [[{} for i in range(MAX_V)] for j in range(MAX_V)]
        for node in self.network.nodes:
            self.network.dijkstra(node)
        #self.network.floyd()

        self.print_topology()
        print()

        for host in self.hosts:
            dst_mac = host.mac
            dst = host.port.dpid
            for datapath in datapaths:
                src = datapath.id
                ofp_parser = datapath.ofproto_parser
                ofctl = OfCtl_v1_0(datapath, self.logger)
                if src != dst:
                    out_port = self.get_out_port(datapath, src, dst)
                    if out_port == -1:
                        continue
                    actions = [ofp_parser.OFPActionOutput(out_port)]
                    ofctl.set_flow(0, 0, dl_dst=dst_mac, actions=actions)
                else:
                    actions = [ofp_parser.OFPActionOutput(host.port.port_no)]
                    ofctl.set_flow(0, 0, dl_dst=dst_mac, actions=actions)
        for src in self.network.nodes:
            for dst in self.network.nodes:
                if src == dst:
                    continue
                self.print_path(src, dst)
        print()

    def print_topology(self):
        for i in self.network.nodes:
            s = ''
            for j in self.network.nodes:
                if self.network.edges[i][j] != -1 and self.network.port_on[i][self.network.port[i][j]]:
                    s = s + 's%s:port_%s ' % (j, self.network.port[i][j])
            print('s%s has link with ' % i + s)

    def print_path(self, src, dst):
        path, path_len = self.network.shortest_path(src, dst)
        if path_len == -1:
            print('Can not reach from switch_%s to switch_%s' % (src, dst))
            return
        print('The distance from switch_%s to switch_%s : %s' % (src, dst, path_len-1))
        path_str = 'Path : '
        for switch in path:
            if switch == path[len(path)-1]:
                path_str = path_str + 'switch_%s' % switch
            else:
                path_str = path_str + 'switch_%s -> ' % switch
        print(path_str)
