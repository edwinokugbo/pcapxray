from datetime import datetime
from xray.models import Packet, Host
from django.conf import settings
import os, pprint, json
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pyvis.network import Network

# plt.switch_backend('agg')


class UtilHelpers:
    """ Class of utility helper functions for various stuff """
    # def __init__(self):
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

                if temp_dict not in packet_dicts:
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

                if not any(d['src'] == src for d in packet_dicts):
                    # packet_dicts.append(Host(src=src, dst=dst))
                    packet_dicts.append(temp_dict)

        # for pkt in packet_dicts:
        #     host =
        #     host.save()

        insert_list = []
        for pkt in packet_dicts:
            insert_list.append(Host(name=name, src=pkt['src'], dst=pkt['dst'], ip_version=pkt['IP']))
        Host.objects.bulk_create(insert_list)

        return True

    def packet_reader(self, *args):
        """ Build the packets data from the supplied and loaded pcap file """

        packets = args[0]
        name = args[1]

        # Delete all previous packets entries from DB
        Packet.delete_all(name)

        packet_dicts = []
        print('Extracting Packets...')
        # Run through the packets and extract all necessary data
        for pkt in packets:
            if 'IP' in pkt:
                ether_src = pkt.src
                ether_dst = pkt.dst
                ip_src = pkt['IP'].src
                ip_dst = pkt['IP'].dst
                ip_version = 'IPv4'

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

                try:
                    src_port = pkt['TCP'].sport
                except IndexError:
                    src_port = 'NA'
                try:
                    dst_port = pkt['TCP'].dport
                except IndexError:
                    dst_port = 'NA'

                try:
                    pkt_time = datetime.fromtimestamp(pkt.time)
                except IndexError:
                    pkt_time = None

                pkt_len = pkt['IP'].len

                summary = pkt.summary()
                payload = pkt.summary()

                temp_dict = {'pkt_time': pkt_time, 'ether_src': ether_src, 'ether_dst': ether_dst, 'ip_src': ip_src, 'ip_dst': ip_dst, 'src_port': src_port, 'dst_port': dst_port, 'ip_version': ip_version, 'protocol': protocol, 'pkt_len': pkt_len,  'summary': summary, 'payload': str(payload)}

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
                    src_port = pkt['TCP'].sport
                except IndexError:
                    src_port = 'NA'
                try:
                    dst_port = pkt['TCP'].dport
                except IndexError:
                    dst_port = 'NA'

                try:
                    pkt_time = datetime.fromtimestamp(pkt.time)
                except IndexError:
                    pkt_time = None

                pkt_len = pkt['IPv6'].plen

                summary = pkt.summary()
                payload = pkt.summary()

                temp_dict = {'pkt_time': pkt_time, 'ether_src': ether_src, 'ether_dst': ether_dst, 'ip_src': ip_src, 'ip_dst': ip_dst, 'src_port': src_port, 'dst_port': dst_port, 'ip_version': ip_version, 'protocol': protocol, 'pkt_len': pkt_len,  'summary': summary, 'payload': str(payload)}

                if temp_dict not in packet_dicts:
                    packet_dicts.append(temp_dict)
                # if not any(d['src'] == src for d in packet_dicts):
                #     packet_dicts.append(temp_dict)

        insert_list = []
        for pkt in packet_dicts:
            insert_list.append(Packet(name=name, packet_time=pkt['pkt_time'], ether_src=pkt['ether_src'], ether_dst=pkt['ether_dst'], ip_src=pkt['ip_src'], ip_dst=pkt['ip_dst'], src_port=pkt['src_port'], dst_port=pkt['dst_port'],ip_version=pkt['ip_version'], protocol=pkt['protocol'], packet_length=pkt['pkt_len'], summary=pkt['summary'], payload=pkt['payload']))
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
        packets = Packet.objects.filter(name=args[0])[:100]
        pcap_name = args[0].replace('.pcap', '')

        graph_packets = []
        for pkt in packets:
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
                'session_key': pkt.ip_src + '/' + pkt.ip_dst + '/' + pkt.src_port
            }
            graph_packets.append(temp_packet)

        return graph_packets
        # G = nx.Graph()
        #
        # tdict = {'a1': {'aa1': {'aaa101': {'information'}, 'aaa201': {'information'}},
        #                 'aa2': {'cca101': {'information'}, 'aca201': {'information'}},
        #                 'ab1': {'aasdfaa101': {'information'}, 'aadaa201': {'information'}}},
        #          'a2': {'ab1': {'aasdfaa101': {'information'}, 'aadaa201': {'information'}},
        #                 'ab2': {'zz101': {'information'}, 'azz201': {'information'}},
        #                 'ac2': {'aaa101': {'information'}, 'aaa201': {'information'}}},
        #          'a3': {'ac1': {'aaa101': {'information'}, 'aaa201': {'information'}},
        #                 'ac2': {'aaa101': {'information'}, 'aaa201': {'information'}}}}
        # self.create_graph(packets_dict, G)
        # nx.draw(G, with_labels=True)
        # plt.savefig(str(os.path.join(settings.BASE_DIR, 'static/report/'),) + pcap_name + '_plot.png')
        #
        # # G = nx.from_dict_of_dicts(packets_dict)
        # # nx.draw(G)
        # # pprint.pp(packets_dict)
        # # pprint.pp(G)
        # net = Network(height="600px", width="100vw", bgcolor="black", font_color="white")
        # net.barnes_hut()
        # net.from_nx(G)
        # net.save_graph(str(os.path.join(settings.BASE_DIR, 'templates/report/'),) + pcap_name + '_plot.html')
