# Custom Module Imports

# For tests
#import pcap_reader

# Library Import
from stem.descriptor import remote
from xray.models import Packet, Tor

# Tor Traffic Module Class
# This class, using stem.descriptor.remote, retrieves potential descriptors of tor nodes and stores them in memory.
# It then associates the possible tor nodes with the sessions already stored.


class TorTrafficHandle:

    def __init__(self):
        self.memory = {
            'tor_nodes': [],
            'possible_tor_traffic': [],
            'session_keys': [],
        }
        if not self.memory['tor_nodes']:
            self.get_consensus_data()

    def get_consensus_data(self):
        try:
            tor_nodes = []
            for desc in remote.get_consensus().run():
                tor_nodes.append((desc.address, desc.or_port))
            return tor_nodes
        except Exception as exc:
            print("Unable to retrieve the consensus: %s" % exc)

    def tor_traffic_detection(self, name):
        session_keys = []
        tor_nodes = []
        possible_tor_traffic = []

        packets = Packet.objects.filter(name=name).values('ip_src', 'ip_dst', 'port')

        for pkt in packets:
            session_keys.append(pkt['ip_src'] + '/' + pkt['ip_dst'] + '/' + pkt['port'])

        tor_values = Tor.objects.all().values_list('node', flat=True)
        tor_nodes = [eval(ele) for ele in tor_values]

        if tor_nodes:
            for session in session_keys:
                current_session = session.split("/")
                if current_session[2].isdigit() and (current_session[1], int(current_session[2])) in tor_nodes:
                    possible_tor_traffic.append(session)

            return possible_tor_traffic








