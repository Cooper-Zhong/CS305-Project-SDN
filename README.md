### Group Member
* 杨宗奇 12111412
* 钟志源 12110517
* 刘晓群 12110943

&nbsp

## Task 0: Environment Setup
- We use pycharm for the main interaction with the mininet.
- After the `ssh connection`, we can directly manipulate the inside terminal also get packet from the inner wireshark.
ex. shown as following.
![|750](../../../attachments/mainenvir.png)

&nbsp

## Task 1: DHCP
* The implementation of this task mainly includes
	* dhcp.py
	* controller.py

### controller.py
* In the controller, we mainly use the `packet_in_handler` function.
	- Divide different kind of message in the event
	- Provide parameters into the `DHCPServer` class.
```python
msg = ev.msg
            datapath = msg.datapath
            pkt = packet.Packet(data=msg.data)
            pkt_dhcp = pkt.get_protocols(dhcp.dhcp)
            pkt_arp = pkt.get_protocols(arp.arp)
            inPort = msg.in_port
            if pkt_dhcp:
                DHCPServer.handle_dhcp(datapath, inPort, pkt)
```
### dhcp.py
This class can be called and build either `offer packet` or `ack packet` according to the dhcp state.
```python
dhcp_state = cls.get_state(cls, pkt_dhcp)
if dhcp_state == 'DHCPDISCOVER':
     cls._send_packet(datapath, port, cls.assemble_offer(pkt,datapath))
elif dhcp_state == 'DHCPREQUEST':
    cls._send_packet(datapath, port, cls.assemble_ack(pkt,datapath,port))
```
#### Attributes
```python
controller_macAddr = '7e:49:b3:f0:f9:99'  # don't modify, a dummy mac address for fill the mac enrty
    dns = '8.8.8.8'  # don't modify, just for the dns entry
    
    start_ip = '192.168.1.2'  # can be modified
    end_ip = '192.168.1.100'  # can be modified
    netmask = '255.255.255.0'  # can be modified
    hostname = 'hostname'     # can be modified
    dhcp_server = '192.168.1.154' # can be modified
```
#### Functions
- `assemble_ack` assemble ack packet in response to `quest`
- `assemble_offer` assemble offer packet in response to `discover`
- `_send_packet` send packets out to the acquiring place.

&nbsp

## Task2: Shortest Path Switching
* The implementation of this task mainly includes
	* controller.py
	* Graph.py

### Graph.py
It is a class described by ourselves, which is an abstract data structure aimed to store the topology of the net work and to run shoretest path algorithm.

#### Attributes
```python
class Graph:  
def __init__(self):  
self.nodes = []  
self.edges = [[-1 for i in range(MAX_V)] for j in range(MAX_V)]  
self.port = [[-1 for i in range(MAX_V)] for j in range(MAX_V)]  
self.port_on = [[False for i in range(MAX_V)] for j in range(MAX_V)]  
self.vis = []
```
* MAX_V: The maximum of the number of nodes
* nodes: The switches in the network
* edges: The link weight between two switches
* port: port[i][j] denotes which port of switch i used to connect to switch j
* port_on: port_on[i][j] denotes whether port j of i is on
* vis: boolean list for dijkstra and SPFA
* paths: shortest paths between any two switches

#### Functions
* dijskstra(self, src)
	* find shortest paths of the single source src.
	* uses PriorityQueue to optimize the time complexity
	* record the previous node of each node in the shortest path and join them to form a path then store it in the self.paths
* SPFA(self, src)
	* find shortest paths of the single source src.
	* uses Queue to implement SPFA algorithm and store the shortest paths into self.paths
* floyd(self, src)
	* uses floyd algorithm to find shortest paths between any two switches
* shortest_path(self, src, dst)
	* check if their is a shortest path between src and dst, return the path and its length, otherwise return an empty list and -1 

### controller.py
* In the controller, we mainly finish two things
	* send arp response messages to the hosts who invokes arp requests to let them learn the arp record and store the records in the local arp cache.
	* update the topology of abstract data structure, apply the shortest path algorithm, reset and install the flow table on all the switches, meanwhile print them out in the controller console.

#### Send ARP Response
* First we create an class $MyMap$ to store the relationship of hosts' ip and mac address, and get information of that from the initial arping of hosts.
* Then upon saving the arp request, we send an arp response according to the message in the arp packet.
```python
ofctl = OfCtl_v1_0(datapath, self.logger)  
ofctl.send_arp(arp_opcode=ARP_REPLY, vlan_id=VLANID_NONE, dst_mac=src_mac, sender_mac=dst_mac,  
sender_ip=dst_ip, target_mac=src_mac, target_ip=src_ip, src_port=OFPP_CONTROLLER,  
output_port=inPort)
```
* dst_mac: the destination mac address for which the arp response should send to
* sender_mac, sender_ip, target_mac, target_ip: fields of arp packet, the target should be the host who send arp request, and the sender should be the destination host that sender request for.
* src_port, out_port: To the switch who send the arp request to controller, the src_port of the arp response is OFPP_CONTROLLER, and it should be send to the host, so the out_port is the port which connected to the host.

#### Update_topology
* first we delete all previous flow table
![|475](../../../attachments/delete-1.png)
* Then we run one of three shortest path algorithms
	* for single source algorithms dijkstra and SPFA, traverse each node as the src.
	* for floyd, only run once
![|550](../../../attachments/ssp-1.png)
* get_out_port(self, datapath, src, dst)
	* in order to set flow table, we need to know which port of a certain switch connecting to the next hop in the shortest path of src to dst.
	```python
	def get_out_port(self, datapath, src, dst):  
		dpid = datapath.id  
		path, path_len = self.network.shortest_path(src, dst)  
		next_hop = path[path.index(dpid) + 1]  
		out_port = self.network.port[dpid][next_hop]  
		return out_port
	```
* Then we traverse each host as the dst, each switch as the src, get the shortest path and set the flow table using ofctl.
* Note that the switch that directly connecting to the host don't get the out_port from the shorest path but from the attribute of host.
```python
for host in self.hosts:  
dst_mac = host.mac  
dst = host.port.dpid  
for datapath in datapaths:  
src = datapath.id  
ofp_parser = datapath.ofproto_parser  
if src != dst:  
out_port = self.get_out_port(datapath, src, dst)  
actions = [ofp_parser.OFPActionOutput(out_port)]  
ofctl = OfCtl_v1_0(datapath, self.logger)  
ofctl.set_flow(0, 0, dl_dst=dst_mac, actions=actions)  
else:  
ofctl = OfCtl_v1_0(datapath, self.logger)  
actions = [ofp_parser.OFPActionOutput(host.port.port_no)]  
ofctl.set_flow(0, 0, dl_dst=dst_mac, actions=actions)
```
* Each time of updating the topology, we print all the shortest paths.![|600](../../../attachments/printpath.png)

After doing the above, we can achieve task2
