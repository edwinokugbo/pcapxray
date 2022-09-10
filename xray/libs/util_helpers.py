from datetime import datetime
from xray.models import Packet, Host, Network, Pcap, Tor
from django.conf import settings
import os, pprint, json
import networkx as nx
import matplotlib
from netaddr import IPAddress
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pyvis.network import Network

# plt.switch_backend('agg')
from xray.libs.tor_traffic_handle import TorTrafficHandle
import re

class UtilHelpers:
    """ Class of utility helper functions for various stuff """
    # def __init__.py(self):
    #     self.filename

    def create_packets_details(*args):
        text_to_save = []

        for pk in args[0]:
            eth = json.loads(pk.ethernet)
            text_to_save.append({
                "Ethernet": {
                    "dst": eth['dst'],
                    "src": eth['src']
                },
                "Payload": {
                    "forward": str(pk.forward),
                    "reverse": str(pk.reverse)
                },
                "covert": pk.covert,
                "file_signatures": pk.file_signatures,
                "session_key": pk.session_key,
            })

        repDir = str(os.path.join(settings.BASE_DIR, 'static/report/'),)
        with open(repDir + args[1] +'_packet_details.txt', 'wt') as out:
            out.write(pprint.pformat(text_to_save, compact=False, sort_dicts=True))

    def create_hosts(self, *args):
        """ Extract the available hosts from the loaded pcap file"""

        packets = args[0]
        name = args[1]

        # Delete all previous hosts entries from DB
        Host.delete_all(name)

        check_host_list = []
        packet_srcs = []
        packet_dsts = []
        packet_dicts = []
        print('Printing Packets...')
        for pkt in packets:
            if 'IP' in pkt:
                src = pkt['IP'].src
                dst = pkt['IP'].dst
                IP = 'IPv4'
                if src not in packet_srcs:
                    packet_srcs.append(src)

                if dst not in packet_dsts:
                    packet_dsts.append(dst)

                temp_dict = {'src': src, 'dst': dst, 'IP': IP}

                # temp_str = src + '/' + dst + '/' + IP
                temp_str = src
                if temp_str in check_host_list:
                    continue
                else:
                    check_host_list.append(temp_str)
                    packet_dicts.append(temp_dict)

            elif "IPv6" in pkt or "IPV6" in pkt:
                src = pkt['IPv6'].src
                dst = pkt['IPv6'].dst
                IP = 'IPv6'
                if src not in packet_srcs:
                    packet_srcs.append(src)

                if dst not in packet_dsts:
                    packet_dsts.append(dst)

                temp_dict = {'src': src, 'dst': dst, 'IP': IP}

                temp_str = src
                if temp_str in check_host_list:
                    continue
                else:
                    check_host_list.append(temp_str)
                    packet_dicts.append(temp_dict)

        insert_list = []
        for pkt in packet_dicts:
            insert_list.append(Host(name=name, src=pkt['src'], dst=pkt['dst'], ip_version=pkt['IP']))
        Host.objects.bulk_create(insert_list)

        return True

    def is_private(self, packet):
        IP = None
        is_source_private = None
        is_destination_private = None
        # IPV6 Condition
        if "IPv6" in packet or "IPV6" in packet:
            # Set Engine respective properties
            # if self.engine == "scapy":
            #     IP = "IPv6"
            # else:
            #     IP = "IPV6"

            IP = "IPv6"

            # TODO: Fix weird ipv6 errors in pyshark engine
            # * ExHandler as temperory fix
            try:
                is_source_private = IPAddress(packet[IP].src).is_private()
            except:
                pass
            try:
                is_destination_private = IPAddress(packet[IP].dst).is_private()
            except:
                pass

        elif "IP" in packet:  # IPV4 Condition
            # and packet["IP"].version == "4":
            # Handle IP packets that originated from LAN (Internal Network)
            # print(packet["IP"].version == "4")
            IP = "IP"
            is_source_private = IPAddress(packet[IP].src).is_private()
            is_destination_private = IPAddress(packet[IP].dst).is_private()

        return IP, is_source_private, is_destination_private

    def packet_reader(self, *args):
        """ Build the packets data from the supplied and loaded pcap file """

        packets = args[0]
        name = args[1]

        # Delete all previous packets entries from DB
        Packet.delete_all(name)

        tor_list = self.get_tor_tuples_fromdb()

        packet_dicts = []
        check_dict_list = []
        print('Extracting Packets...')
        # Run through the packets and extract all necessary data
        for pkt in packets:

            # Get the ethernet and IP addresses for the source and destination
            if 'IP' in pkt:
                ether_src = pkt.src
                ether_dst = pkt.dst
                ip_src = pkt['IP'].src
                ip_dst = pkt['IP'].dst
                ip_version = 'IPv4'

                # Get the packet protocol
                if 'TCP' in pkt:
                    protocol = 'TCP'
                elif 'UDP' in pkt:
                    protocol = 'UDP'
                elif 'DNS' in pkt:
                    protocol = 'DNS'
                else:
                    try:
                        protocol = pkt['IP'].proto
                    except IndexError:
                        protocol = 'NA'

                # Get the source and destination ports
                try:
                    if 'TCP' in pkt:
                        src_port = pkt['TCP'].sport
                        dst_port = pkt['TCP'].dport
                    elif 'UDP' in pkt:
                        src_port = pkt['UDP'].sport
                        dst_port = pkt['UDP'].dport
                    elif 'ICMP' in pkt:
                        src_port = 'ICMP'
                        dst_port = 'ICMP'
                    else:
                        src_port = 'NA'
                        dst_port = 'NA'
                except IndexError:
                    src_port = 'NA'
                    dst_port = 'NA'

                # Get the packet time
                try:
                    pkt_time = datetime.fromtimestamp(pkt.time)
                except IndexError:
                    pkt_time = None

                pkt_len = pkt['IP'].len

                summary = pkt.summary()
                # try:
                #     readable_payload = pkt.show()
                #     payload = readable_payload
                # except:
                payload = pkt.summary()

                # Determine which IP is the originating one and which is the receiving one
                # This is important because, the originating IP is the actual source
                IP, is_source_private, is_destination_private = self.is_private(pkt)

                # Determine the source and destination IP addresses and port by checking which is private and which is
                # not
                real_port = ''
                if is_source_private and not is_destination_private:
                    # Inter-network packet
                    # Key := Always lan hosts as source in session
                    # key = packet[IP].src + "/" + packet[IP].dst + "/" + dst_port
                    real_ether_src = ether_src
                    real_ether_dst = ether_dst
                    real_src = ip_src
                    real_dst = ip_dst
                    real_port = dst_port
                elif is_destination_private and not is_source_private:
                    # Inter-network packet
                    # Key := Always lan hosts as source in session
                    # key = packet[IP].dst + "/" + packet[IP].src + "/" + src_port
                    real_ether_src = ether_dst
                    real_ether_dst = ether_src
                    real_src = ip_dst
                    real_dst = ip_src
                    real_port = src_port
                else:
                    # Intra-network or Public ip communication
                    real_ether_src = ether_src
                    real_ether_dst = ether_dst
                    real_src = ip_src
                    real_dst = ip_dst
                    real_port = dst_port

                # Check for invalid networt ports and eliminate
                if real_port == 'NA':
                    continue

                # Check for duplicates and eliminate
                test_key = real_src + '/' + real_dst + '/' + str(real_port)

                if test_key not in check_dict_list:
                    check_dict_list.append(test_key)

                    port_type = self.get_port_type(str(real_port).strip())

                    # Check if any of test key is possible tor data
                    if isinstance(real_port, int):
                        if real_port and (real_dst, int(real_port)) in tor_list:
                            print('Possible Tor: ', real_dst, real_port)
                            port_type = 'Tor'

                    temp_dict = {'pkt_time': pkt_time, 'ether_src': real_ether_src, 'ether_dst': real_ether_dst, 'ip_src': real_src, 'ip_dst': real_dst, 'src_port': src_port, 'dst_port': dst_port, 'ip_version': ip_version, 'protocol': protocol, 'pkt_len': pkt_len,  'summary': summary, 'payload': str(payload), 'IP': IP, 'is_src_private': is_source_private, 'is_dst_private': is_destination_private, 'port': real_port, 'port_type': port_type}

                    if temp_dict not in packet_dicts:
                        packet_dicts.append(temp_dict)

            elif "IPv6" in pkt or "IPV6" in pkt:
                ether_src = pkt.src
                ether_dst = pkt.dst
                ip_src = pkt['IPv6'].src
                ip_dst = pkt['IPv6'].dst
                ip_version = 'IPv6'

                if 'TCP' in pkt:
                    protocol = 'TCP'
                elif 'UDP' in pkt:
                    protocol = 'UDP'
                elif 'DNS' in pkt:
                    protocol = 'DNS'
                else:
                    try:
                        protocol = pkt['IPv6'].proto
                    except AttributeError:
                        protocol = 'NA'

                try:
                    if 'TCP' in pkt:
                        src_port = pkt['TCP'].sport
                        dst_port = pkt['TCP'].dport
                    elif 'UDP' in pkt:
                        src_port = pkt['UDP'].sport
                        dst_port = pkt['UDP'].dport
                    elif 'ICMP' in pkt:
                        src_port = 'ICMP'
                        dst_port = 'ICMP'
                    else:
                        src_port = 'NA'
                        dst_port = 'NA'
                except IndexError:
                    src_port = 'NA'
                    dst_port = 'NA'

                try:
                    pkt_time = datetime.fromtimestamp(pkt.time)
                except IndexError:
                    pkt_time = None

                pkt_len = pkt['IPv6'].plen

                summary = pkt.summary()
                payload = pkt.summary()

                IP, is_source_private, is_destination_private = self.is_private(pkt)

                # Determine the source and destination IP addresses and port by checking which is private and which is
                # not
                real_port = ''
                if is_source_private and not is_destination_private:
                    # Inter-network packet
                    # Key := Always lan hosts as source in session
                    real_ether_src = ether_src
                    real_ether_dst = ether_dst
                    real_src = ip_src
                    real_dst = ip_dst
                    real_port = dst_port
                elif is_destination_private and not is_source_private:
                    # Inter-network packet
                    # Key := Always lan hosts as source in session
                    real_ether_src = ether_dst
                    real_ether_dst = ether_src
                    real_src = ip_dst
                    real_dst = ip_src
                    real_port = src_port
                else:
                    # Intra-network or Public ip communication
                    real_ether_src = ether_src
                    real_ether_dst = ether_dst
                    real_src = ip_src
                    real_dst = ip_dst
                    real_port = dst_port

                if real_port == 'NA':
                    continue

                # Check if any of test key is possible tor data
                if real_port and (real_dst, int(real_port)) in tor_list:
                    print('Possible Tor: ', real_dst, real_port)

                # Check for duplicates
                test_key = real_src + '/' + real_dst + '/' + str(real_port)
                if test_key not in check_dict_list:
                    check_dict_list.append(test_key)

                    port_type = self.get_port_type(str(real_port).strip())

                    # Check if any of test key is possible tor data
                    if isinstance(real_port, int):
                        if real_port and (real_dst, int(real_port)) in tor_list:
                            print('Possible Tor: ', real_dst, real_port)
                            port_type = 'Tor'

                    temp_dict = {'pkt_time': pkt_time, 'ether_src': real_ether_src, 'ether_dst': real_ether_dst, 'ip_src': ip_src, 'ip_dst': ip_dst, 'src_port': src_port, 'dst_port': dst_port, 'ip_version': ip_version, 'protocol': protocol, 'pkt_len': pkt_len,  'summary': summary, 'payload': str(payload), 'IP': IP, 'is_src_private': is_source_private, 'is_dst_private': is_destination_private, 'port': real_port, 'port_type': port_type}

                    if temp_dict not in packet_dicts:
                        packet_dicts.append(temp_dict)
                # if not any(d['src'] == src for d in packet_dicts):
                #     packet_dicts.append(temp_dict)

            elif 'DNS' in pkt:
                print(pkt)

            elif 'UDP' in pkt:
                print(pkt)
            elif 'ICMP' in pkt:
                print(pkt)

        # Bulk save the extracted packet data to DB
        insert_list = []
        for pkt in packet_dicts:
            insert_list.append(Packet(name=name, packet_time=pkt['pkt_time'], ether_src=pkt['ether_src'], ether_dst=pkt['ether_dst'], ip_src=pkt['ip_src'], ip_dst=pkt['ip_dst'], src_port=pkt['src_port'], dst_port=pkt['dst_port'],ip_version=pkt['ip_version'], protocol=pkt['protocol'], packet_length=pkt['pkt_len'], summary=pkt['summary'], payload=pkt['payload'], is_src_private=pkt['is_src_private'], is_dst_private=pkt['is_dst_private'], port=pkt['port'], port_type=pkt['port_type']))
        Packet.objects.bulk_create(insert_list)
        return True

    def create_graph(self, d, g, p=None):
        for a, b in d.items():
            g.add_node(a)
            if p is not None:
                g.add_edge(p, a)
            if not isinstance(b, set):
                self.create_graph(b, g, a)

    def build_graph_dict(self, *args):
        packets = Packet.objects.filter(name=args[0])[:30]
        pcap_name = args[0].replace('.pcap', '')

        packets_dict = {}
        ii = 0
        for pkt in packets:
            # packets_dict[ii] = {}
            packets_dict[pkt.ip_src] = {pkt.ip_dst: {pkt.src_port}}
            # packets_dict[ii]['ip_dst'] = {pkt.ip_dst}
            # packets_dict[ii]['port'] = {pkt.src_port}
            ii = ii + 1
            # self.update_without_overwriting(packets_dict, temp_dict)

        return pprint.pp(packets_dict)

    def build_graph_packets(self, *args):
        """ Create packet dictionary for plotting maps and graphs """
        packets = Packet.objects.filter(name=args[0])
        pcap_name = args[0].replace('.pcap', '')

        graph_packets = []
        packet_keys = []
        ii = 0
        for pkt in packets:
            if pkt.src_port == 'NA':
                ii = ii + 1
                continue

            covert = False
            if pkt.covert != '':
                covert = pkt.covert

            file_signatures = pkt.file_signatures
            if pkt.file_signatures is None:
                file_signatures = []
            temp_packet = {
                'Ethernet': {
                    'dst': pkt.ether_dst,
                    'src': pkt.ether_src,
                },
                'Payload': pkt.payload,
                'covert': covert,
                'file_signatures': file_signatures,
                'session_key': pkt.ip_src + '/' + pkt.ip_dst + '/' + pkt.port
            }
            graph_packets.append(temp_packet)
            packet_keys.append(pkt.ip_src + '/' + pkt.ip_dst + '/' + pkt.port)

        return graph_packets, packet_keys

    def build_interactive_graph_packets(self, *args):
        """ Create packet dictionary for plotting maps and graphs """

        packet_filter = args[1]
        if packet_filter == 'All':
            packets = Packet.objects.filter(name=args[0])
        else:
            packets = Packet.objects.filter(name=args[0], port_type=packet_filter)

        # pcap_name = args[0].replace('.pcap', '')

        graph_packets = []
        packet_keys = []
        ii = 0
        for pkt in packets:
            if pkt.src_port == 'NA':
                ii = ii + 1
                continue

            covert = False
            if pkt.covert != '':
                covert = pkt.covert

            file_signatures = pkt.file_signatures
            if pkt.file_signatures is None:
                file_signatures = []
            temp_packet = {
                'Ethernet': {
                    'dst': pkt.ether_dst,
                    'src': pkt.ether_src,
                },
                'Payload': pkt.payload,
                'covert': covert,
                'file_signatures': file_signatures,
                'session_key': pkt.ip_src + '/' + pkt.ip_dst + '/' + pkt.port,
                'port_type': pkt.port_type
            }
            graph_packets.append(temp_packet)
            packet_keys.append(pkt.ip_src + '/' + pkt.ip_dst + '/' + pkt.port)

        return graph_packets, packet_keys

    def clean_up_db(self):
        Packet.objects.all().delete()
        Network.objects.all().delete()
        Host.objects.all().delete()
        Pcap.objects.all().delete()

        return 'Datebase Clean'

    def get_port_number(self, port_str):
        """ function to et the port type from the user selected filter option """
        if port_str == 'HTTP':
            return '80'
        elif port_str == 'HTTPS':
            return '443'
        elif port_str == 'DNS':
            return '53'
        elif port_str == 'ICMP':
            return 'ICMP'
        elif port_str == 'Tor':
            return 'Tor'
        elif port_str == 'Malicious':
            return 'Mal'
        else:
            return 'Unknown'

    def get_port_type(self, port_num):
        """ function to et the port type from the user selected filter option """
        if port_num == '22':
            return 'SSH'
        if port_num == '80':
            return 'HTTP'
        elif port_num == '443':
            return 'HTTPS'
        elif port_num == '53':
            return 'DNS'
        elif port_num == 'ICMP':
            return 'ICMP'
        elif port_num == 'Tor':
            return 'Tor'
        elif port_num == 'Mal':
            return 'Malicious'
        else:
            return 'Unknown'

    def get_edge_color(self, edge_type):
        """ function to set the edge color based on thr traffic type """
        if edge_type == 'SSH':
            return '#23dff7'
        elif edge_type == 'HTTP':
            return '#06fd06'
        elif edge_type == 'HTTPS':
            return '#0a0afc'
        elif edge_type == 'DNS':
            return '#fea502'
        elif edge_type == 'ICMP':
            return '#f0f768'
        elif edge_type == 'Tor':
            return '#ffffff'
        elif edge_type == 'Mal':
            return '#ff6c6c'
        else:
            return '#ff00f3'

    def get_tor_data(self):
        # First, delete all Tor data in DB so we can update with a fresh list
        Tor.objects.all().delete()

        # Next, get Tor list data from remote
        tor_traffic_data = TorTrafficHandle()
        tor_nodes = tor_traffic_data.get_consensus_data()

        # Save retrieved data to DB
        insert_list = []
        for node in tor_nodes:
            insert_list.append(Tor(node=node))
        Tor.objects.bulk_create(insert_list)

    def get_tor_tuples_fromdb(self):
        tor_values = Tor.objects.all().values_list('node', flat=True)
        tor_list = [eval(ele) for ele in tor_values]
        return tor_list

    def get_tor_list_fromdb(self):
        tor_values = Tor.objects.all().values_list('node', flat=True)
        tor_list = [eval(ele) for ele in tor_values]
        return tor_list

    def get_theme_styles(self, theme):
        if theme == 0:
            return """
                #alchemy {
                    overflow: auto;
                    background-color: #000000 !important;
                }

                svg {
                    background-color: #000000 !important;
                }
            """
        elif theme == 1:
            return """
                #alchemy {
                    overflow: auto;
                    background-color: #ffffff !important;
                }

                svg {
                    background-color: #ffffff !important;
                }
            """
        elif theme == 2:
            return """
                #alchemy {
                    overflow: auto;
                    background-color: #cccccc !important;
                }

                svg {
                    background-color: #cccccc !important;
                }
            """
        else:
            return """
                #alchemy {
                    overflow: auto;
                    background-color: #000000 !important;
                }

                svg {
                    background-color: #000000 !important;
                }
            """

    def make_dynamic_map(self, data_path, template_path, name, packet_filter='All', theme=0):
        nodes = ''
        edges = ''

        theme_styles = '<style>'
        theme_styles += self.get_theme_styles(theme)
        theme_styles += '</style>'

        # Get a list of unique hosts ips for this pcap
        unique_ethers = []
        unique_hosts = Packet.get_unique_ethers(name)
        for hst in unique_hosts:
            if hst['host'] not in unique_ethers:
                unique_ethers.append(hst['host'])

        # Get the hosts and packets data that will be used to generate the map edges
        graph_dict, packets_keys = self.build_interactive_graph_packets(name, packet_filter)

        # Generate the edges of the graph
        for pkt in graph_dict:
            srcs, dsts, port = pkt['session_key'].split('/')
            src = pkt['Ethernet']['src']
            dst = pkt['Ethernet']['dst']
            if src in unique_ethers and dst in unique_ethers and pkt['port_type'] is not None:
                ssrc = src.replace(":", "")
                ssrc = ssrc.replace("__", "_")
                ddst = dst.replace(":", "")
                ddst = ddst.replace("__", "_")
                ssrc = re.sub('[^0-9_]', '0', ssrc)
                ddst = re.sub('[^0-9_]', '0', ddst)
                edges += '{ source: ' + ssrc + ', target: ' + ddst + ', edgeType: "' + pkt['port_type'] + '" },'

        edges = edges[:len(edges) - 1] + ']};'

        # Create the graph nodes
        for host in unique_hosts:
            nid = host['host'].replace(":", "")
            nid = nid.replace("__", "_")
            nid = re.sub('[^0-9_]', '0', nid)
            node_type = 'node'
            nodeCaption = host['host'] + ' - ' + host['ip']

            # if 8.8.8.8 that a gateway
            if host['port'] == '53':
                node_type = 'PossibleGateway'
                # nodeCaption += nodeCaption + '<br>PossibleGateway'

            nodes += '{ caption: "' + nodeCaption + '", nodeType: "' + node_type + '", id: ' + nid + ' },'

        # Remove the last extra comma from teh string generated above and replace with a closing
        # bracket and a comma
        nodes = nodes[:len(nodes)-1] + '],'

        # Create a string of the nodes, to be inserted into the map template for Alchemy library,
        # to generate the maps
        full_json = 'var pcapName = "' + name + '"; \n'
        full_json += 'var json = { comment: "PCAP Capture traffic Map",'
        full_json += ' nodes: [' + nodes
        full_json += ' edges: [' + edges

        # open text file in read mode and read html template
        html_file = open(data_path + "/plot_html.txt", "r")
        html = html_file.read()
        html_file.close()

        # Replace the template content with the generated javascript code for Alchemy.
        new_styles = html.replace('<replace-me-with-styles>', theme_styles)
        new_content = new_styles.replace('<replace-me-with-data>', full_json)

        # Save to report file
        file = template_path + "/report/interactive_map.html"
        print('trying to write file...', file)
        with open(file, 'w') as file_to_write:
            file_to_write.write(new_content)
            # file_to_write.close()
        return True

    def make_dynamic_map_data(self, name, packet_filter='All', edge_width=1):
        nodes = '['
        edges = '['

        # Get a list of unique hosts ips for this pcap
        unique_ethers = []
        unique_hosts = Packet.get_unique_ethers(name)
        for hst in unique_hosts:
            if hst['host'] not in unique_ethers:
                unique_ethers.append(hst['host'])

        # Get the hosts and packets data that will be used to generate the map edges
        graph_dict, packets_keys = self.build_interactive_graph_packets(name, packet_filter)
        # Generate the edges of the graph
        for pkt in graph_dict:
            srcs, dsts, port = pkt['session_key'].split('/')
            src = pkt['Ethernet']['src']
            dst = pkt['Ethernet']['dst']
            if src in unique_ethers and dst in unique_ethers and pkt['port_type'] is not None:
                ssrc = src.replace(":", "")
                ssrc = ssrc.replace("__", "_")
                ddst = dst.replace(":", "")
                ddst = ddst.replace("__", "_")
                ssrc = re.sub('[^0-9_]', '0', ssrc)
                ddst = re.sub('[^0-9_]', '0', ddst)
                edges += '{ from: ' + ssrc + ', to: ' + ddst + ", label: '" + pkt['port_type'] + "', color: '" + self.get_edge_color(pkt['port_type']) + "', width: " + str(edge_width) + ", length: 400, smooth: { enabled: true, type: 'dynamic', roundness: 0.5 }, },"

        edges = edges[:len(edges) - 1] + ']'

        # Create the graph nodes
        for host in unique_hosts:
            nid = host['host'].replace(":", "")
            nid = nid.replace("__", "_")
            nid = re.sub('[^0-9_]', '0', nid)
            node_type = 'node'
            bg_color = "#0fd623"
            nodeCaption = host['host'] + ' - ' + host['ip']

            # if port 53, that is a gateway
            if host['port'] == '53':
                node_type = 'PossibleGateway'
                bg_color = "#f7b21e"
            elif host['ip'] == '255.255.255.255':
                node_type = 'Broadcast'
                bg_color = '#45ccf5'

            color = " color: { border: '#2B7CE9', background: '" + bg_color + "', highlight: { border: '#2B7CE9', background: '#D2E5FF' }, hover: { border: '#2B7CE9',background: '#cccccc'} }, shape: 'circle', "
            nodes += '{ id: ' + nid + ", label: '" + host['ip'] + "', key: '" + host['ip'] + "', title:  '" + node_type + "', " + color + "},"

        # Remove the last extra comma from teh string generated above and replace with a closing
        # bracket and a comma
        nodes = nodes[:len(nodes)-1] + ']'

        return nodes, edges
