import binascii

from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
import eventlet

class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99'  # don't modify, a dummy mac address for fill the mac enrty
    dns = '8.8.8.8'  # don't modify, just for the dns entry

    start_ip = '192.168.1.2'  # can be modified
    end_ip = '192.168.1.100'  # can be modified
    netmask = '255.255.255.0'  # can be modified
    hostname = 'hostname'
    dhcp_server = '192.168.1.154' # nono
    # routes = '10.27.255.254'

    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.


class DHCPServer():
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns
    hostname = Config.hostname
    dhcp_server = Config.dhcp_server
    # routes = Config.routes

    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        # TODO: Generate DHCP ACK packet herecon
        # 获取 DHCP Discover 消息的各个协议头
        print("ack")
        req_eth = pkt.get_protocol(ethernet.ethernet)
        req_ipv4 = pkt.get_protocol( ipv4.ipv4)
        req_udp = pkt.get_protocol( udp.udp)
        req = pkt.get_protocol( dhcp.dhcp)
        # 将 DHCP Discover 消息的 Option 53（消息类型）改为 Acknowledge（5）
        # Option 51（租约时间）改为 8640 秒（2 小时 24 分钟）
        # 客户端会根据响应消息的消息类型（Option 53）来确定接下来的步骤。
        # 将消息类型设置为 Acknowledge（5）可以让客户端知道它收到的是一个 DHCP Acknowledge 消息。
        options = req.options
        for i in options.option_list:
            if i.tag == 53:
                options.option_list.remove(i)
        # req.options.option_list.remove(
        #     next(opt for opt in req.options.option_list if opt.tag == 53))
        options.option_list.insert(0, dhcp.option(tag=51, value='0xffffffff'.encode()))
        options.option_list.insert(
            # 0, dhcp.option(tag=53, value='05'.decode('hex')))
            0, dhcp.option(tag=53, value=binascii.a2b_hex('05')))

        # 组装 DHCP Acknowledge 消息
        ack_pkt = packet.Packet()
        ack_pkt.add_protocol(ethernet.ethernet(
            ethertype=req_eth.ethertype, dst=req_eth.src, src=cls.hardware_addr))
        ack_pkt.add_protocol(
            ipv4.ipv4(dst=req_ipv4.dst, src=cls.dhcp_server, proto=req_ipv4.proto))
        ack_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        ack_pkt.add_protocol(dhcp.dhcp(op=2,
                                       chaddr=req_eth.src,
                                       # ciaddr=cls.start_ip,
                                       siaddr=cls.dhcp_server,
                                       boot_file=req.boot_file,
                                       yiaddr=cls.start_ip,
                                       xid=req.xid,
                                       # sname=cls.dns,
                                       options=req.options))
        print("ackyou"+ str(ack_pkt))
        return ack_pkt

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        # TODO: Generate DHCP OFFER packet here
        # get head
        print("offer")
        disc_eth = pkt.get_protocol(ethernet.ethernet)
        disc_ipv4 = pkt.get_protocol(ipv4.ipv4)
        disc_udp = pkt.get_protocol(udp.udp)
        disc = pkt.get_protocol(dhcp.dhcp)
        # if debug: print(disc)
        # 从DHCP options中删除标记为xx的option
        options = disc.options
        for i in options.option_list:
            if i.tag == 55 or i.tag == 53 or i.tag == 12:
                options.option_list.remove(i)
        # 在DHCP options的开头添加一个标记为xx的option，该option包含xxx
        # print(dir(cls))
        options.option_list.insert(0, dhcp.option(1,cls.netmask.encode()))
        options.option_list.insert(
            # 0, dhcp.option(tag=3, value=cls.dhcp_server))
            0, dhcp.option(3,cls.dhcp_server.encode()))
#router ip but default?
        options.option_list.insert(0, dhcp.option(tag=6, value=cls.dns.encode())) #dns
        options.option_list.insert(
            0, dhcp.option(tag=12, value=cls.hostname.encode()))
# no 12
        # 在DHCP options的开头添加一个标记为xx的option，该option表示消息类型，值为2(表示DHCP Offer)
        options.option_list.insert(
            # 0, dhcp.option(tag=53, value='02'.decode('hex')))
            # 0, dhcp.option(tag=53, value=bytes.fromhex('02')))
            0, dhcp.option(tag=53, value=binascii.a2b_hex('02')))
# length=1 but 02?
        options.option_list.insert(
            0, dhcp.option(tag=54, value=cls.dhcp_server.encode()))
# dhcp server address but default?

        offer_pkt = packet.Packet()  # create new package
        # 将以太网帧、IPv4报文、UDP报文和DHCP报文依次添加到报文中。
        offer_pkt.add_protocol(ethernet.ethernet(ethertype=disc_eth.ethertype, dst=disc_eth.src, src=cls.hardware_addr))
        offer_pkt.add_protocol(ipv4.ipv4(dst=disc_ipv4.dst, src=cls.dhcp_server, proto=disc_ipv4.proto))
        offer_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        # ip++
        arr = cls.start_ip.split('.')
        num = int(''.join(arr[3]))
        length = len(arr[3])
        num = num + 1
        cls.start_ip = cls.start_ip[:-length] + str(num)
        offer_pkt.add_protocol(dhcp.dhcp(op=2,
                                         chaddr=disc_eth.src,
                                         # htype=1,
                                         # flags=1,
                                         siaddr=cls.dhcp_server,
                                         boot_file=disc.boot_file,
                                         yiaddr=cls.start_ip,
                                         # chaddr=cls.hardware_addr,
                                         xid=disc.xid,
                                         # sname=cls.dns,
                                         options=options))
        print("offeryou" ,str(offer_pkt))
        return offer_pkt

    # 获取 DHCP 客户端状态，传入参数为 DHCP 协议头
    def get_state(cls, pkt_dhcp):
        # 根据 Option 53
        dhcp_state = ord(
            [opt for opt in pkt_dhcp.options.option_list if opt.tag == 53][0].value)
        # 获取 DHCP 协议头中的 Option 53（消息类型），并转换为整数类型
        if dhcp_state == 1:
            state = 'DHCPDISCOVER'
        elif dhcp_state == 2:
            state = 'DHCPOFFER'
        elif dhcp_state == 3:
            state = 'DHCPREQUEST'
        elif dhcp_state == 5:
            state = 'DHCPACK'
        return state

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        # TODO: Specify the type of received DHCP packet
        # You may choose a valid IP from IP pool and genereate DHCP OFFER packet
        # Or generate a DHCP ACK packet
        # Finally send the generated packet to the host by using _send_packet method
        # print(dir(pkt))
        pkt_dhcp = pkt.get_protocols(dhcp.dhcp)[0]
        # if debug: print(type(pkt))
        # if debug: print(pkt_dhcp)
        dhcp_state = cls.get_state(cls, pkt_dhcp)
        # cls.logger.info("NEW DHCP %s PACKET RECEIVED: %s" %
        #                  (dhcp_state, pkt_dhcp))
        print(dhcp_state)
        if dhcp_state == 'DHCPDISCOVER':
            # 将交换机发送一个 DHCP Offer 消息给客户端
            cls._send_packet(datapath, port, cls.assemble_offer(pkt,datapath))
        elif dhcp_state == 'DHCPREQUEST':
            cls._send_packet(datapath, port, cls.assemble_ack(pkt,datapath,port))
        else:
            return

    @classmethod
    def _send_packet(cls, datapath, port, pkt):
        print('sendpkt')
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if isinstance(pkt, str):
            pkt = pkt.encode()
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)


