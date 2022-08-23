from scapy.all import *
from xray.models import Packet
from netaddr import IPAddress
from xray.libs.malicious_traffic_detector import maliciousTrafficIdentifier
from xray.libs.communication_details_fetch import trafficDetailsFetch

tls_view_feature = False

class PacketProcessor():
    """ Pcap reader and processor class """
    current_pcap_file = ""
    session_keys = []
    engine = "scapy"


    def __init__(self):
        self.current_pcap_file
        self.eth_layer = "Ether"

    # def load_pcap_file(self):
    #     rdpcap(self.current_pcap_file)
    #     print('pcap is here')

    def get_ethernet_data(self, packet, is_source_private):
        src = ""
        dst = ""

        if is_source_private:
            if self.eth_layer in packet:
                src = packet[self.eth_layer].src
                dst = packet[self.eth_layer].dst
            payload_direction = "forward"
        else:
            if self.eth_layer in packet:
                src = packet[self.eth_layer].src
                dst = packet[self.eth_layer].dst
            payload_direction = "reverse"

        ethernet = '{"src": "' + src + '", "dst": "' + dst + '"}'
        return ethernet, src, dst, payload_direction

    def is_private(self, packet):
        IP = None
        is_source_private = None
        is_destination_private = None
        # IPV6 Condition
        if "IPv6" in packet or "IPV6" in packet:
            # Set Engine respective properties
            if self.engine == "scapy":
                IP = "IPv6"
            else:
                IP = "IPV6"

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

    def get_icmp_session_key(self, packet):
        (IP, is_source_private, is_destination_private) = self.is_private(packet)

        # Key creation similar to both private interface condition
        key1 = packet[IP].src + "/" + packet[IP].dst + "/" + "ICMP"
        key2 = packet[IP].dst + "/" + packet[IP].src + "/" + "ICMP"

        # First come first serve
        if key2 in self.session_keys:
            session_key = key2
        else:
            session_key = key1

        return session_key, is_source_private, is_destination_private, IP

    def get_tcp_session_key(self, packet):
        (IP, is_source_private, is_destination_private) = self.is_private(packet)

        key1 = ""
        key2 = ""

        # Set Engine respective properties
        if self.engine == "pyshark":
            src_port = str(
                packet["TCP"].srcport if "TCP" in packet else packet["UDP"].srcport)
            dst_port = str(
                packet["TCP"].dstport if "TCP" in packet else packet["UDP"].dstport)
        else:
            src_port = str(
                packet["TCP"].sport if "TCP" in packet else packet["UDP"].sport)
            dst_port = str(
                packet["TCP"].dport if "TCP" in packet else packet["UDP"].dport)

        # Session Key Creation
        if is_source_private and not is_destination_private:
            # Internet work packet
            # Key := Always lan hosts as source in session
            key = packet[IP].src + "/" + packet[IP].dst + "/" + dst_port
            session_key = key
        elif is_destination_private and not is_source_private:
            # Internet work packet
            # Key := Always lan hosts as source in session
            key = packet[IP].dst + "/" + packet[IP].src + "/" + src_port
            session_key = key
        else:
            # Intranet work or Public ip communication
            key1 = packet[IP].src + "/" + packet[IP].dst + "/" + dst_port
            key2 = packet[IP].dst + "/" + packet[IP].src + "/" + src_port

            # print("key1: " + key1)
            # print("key2: " + key2)
            # First come first serve
            if key2 in self.session_keys:
                session_key = key2
            else:
                session_key = key1

                # print("key: " + str(is_source_private), str(is_destination_private))

        return session_key, is_source_private, is_destination_private, IP

    def get_scapy_payload_dump(self, packet):
        global tls_view_feature
        if tls_view_feature:
            if "TLS" in packet:
                payload_dump = str(packet["TLS"].msg)
            elif "SSLv2" in packet:
                payload_dump = str(packet["SSLv2"].msg)
            elif "SSLv3" in packet:
                payload_dump = str(packet["SSLv3"].msg)
            else:
                payload_dump = str(bytes(packet["TCP"].payload))
        else:
            # TODO: clean this payload dump
            payload_dump = str(bytes(packet["TCP"].payload))

        return payload_dump

    def process_packet_data(self, packet) :
        # ***********
        # Gets a unique key from the packet's data representing the session
        # The key contains the port (destination or source), destination IP and source IP.

        session_key = None
        covert = False
        file_signatures = []

        if "TCP" in packet or "UDP" in packet:
            session_key, is_ip_src_private, is_ip_dst_private, IP = self.get_tcp_session_key(packet)

        elif "ICMP" in packet:
            session_key, is_source_private, is_destination_private, IP = self.get_icmp_session_key(packet)

        if not session_key:
            return

        (ethernet, ether_src, ether_dst, payload_direction) = self.get_ethernet_data(packet, is_ip_src_private)

        payload_string = ""  # Variable to hold payload and detect covert

        # Gets Pyshark payload
        if self.engine == "pyshark":
            # <TODO>: Payload recording for pyshark
            # Refer https://github.com/KimiNewt/pyshark/issues/264
            try:
                payload_dump = str(packet.get_raw_packet())
                payload_string = packet.get_raw_packet()
            except:
                payload_dump = ""

        # Gets Scapy payload
        elif self.engine == "scapy":
            global tls_view_feature
            if "TCP" in packet:
                payload_dump = self.get_scapy_payload_dump(packet)
                payload_string = packet["TCP"].payload
            elif "UDP" in packet:
                payload_dump = str(bytes(packet["UDP"].payload))
                payload_string = packet["UDP"].payload
            elif "ICMP" in packet:
                payload_dump = str(bytes(packet["ICMP"].payload))
                payload_string = packet["ICMP"].payload

            # ***********
            # Stores covert file signatures
            if payload_string:
                file_signs = maliciousTrafficIdentifier.covert_payload_prediction(
                    payload_string)
                # print(file_signs)
                if file_signs:
                    Packet("file_signatures").extend(file_signs)
                    file_signatures = list(
                        set(file_signatures))

        src, dst, port = session_key.split("/")
        # Covert detection and store
        if not trafficDetailsFetch.is_multicast(src) and not trafficDetailsFetch.is_multicast(dst) and \
                maliciousTrafficIdentifier.covert_traffic_detection(packet) == 1:
                    covert = True

        # return packet fields for insert into DB
        return session_key, is_ip_src_private, is_ip_dst_private, IP, ethernet, ether_src, ether_dst, payload_direction, payload_dump, covert, file_signatures

    def extract_packets(self, packets):
        """ This function extracts the packets and breaks it down into the network info """
        netdata = []
        ii = 0
        # Loop through all the network packets and extract the packet data
        for pack in packets:
            # (session_key, is_source_private, is_destination_private, IP) = self.process_packet_data(pack)
            returned_packet = self.process_packet_data(pack)
            if returned_packet:
                (session_key, is_source_private, is_destination_private, IP, ethernet, ether_src, ether_dst, payload_direction, payload_dump, covert, file_signatures) = returned_packet
                self.session_keys.append(session_key)

                # Create payload for DB
                forward = ""
                reverse = ""
                if payload_direction == "forward":
                    payload = '{"forward": ["' + payload_dump.replace("\\", "\\\\") + '"], "reverse": "[]"}'
                    forward = payload_dump
                    reverse = "[]"
                else:
                    payload = '{"forward": "[]", "reverse": ["' + payload_dump.replace("\\", "\\\\") + '"]}'
                    forward = "[]"
                    reverse = payload_dump
                            
                if IP == 'IP':
                    IP = 'IPv4'

            # Check if returned pack is None. If not None, append to list for creating the DB
            if returned_packet:
                netdata.append(
                    Packet(session_key=session_key, ethernet=ethernet, forward=forward, reverse=reverse, ether_src=ether_src, ether_dst=ether_dst, ip=IP, covert=covert, file_signatures=file_signatures))

            ii = ii + 1
            if ii > 100:
                break
        return netdata
