# Custom Module Imports
from xray.libs import communication_details_fetch
from xray.models import Packet, Network

# Library Import
import os, json, sys

# import magic signatures for detecting covert traffic
from xray.data.magic_numbers import magic_numbers

destination_hosts = []
signatures = {}

# Module to Identify Possible Malicious Traffic
# This file uses a list of malicious known file signatures, called magic_numbers and checks whether they are in the packets.
class maliciousTrafficIdentifier:

    def __init__(self):
        (session_key, possible_mal_traffic, dest_hosts) = Packet.onjects.all().values('session_key, destination_hosts, possible_mal_traffic')
        global destination_hosts
        destination_hosts = dest_hosts

        print(session_key)
        for session in session_key:
            src, dst, port = session.split("/")
            if port.isdigit() and self.malicious_traffic_detection(src, dst, int(port)) == 1:
                possible_mal_traffic.append(session)

    @staticmethod
    def malicious_traffic_detection(self, src, dst, port):
        # TODO : It currently whitelists all the ports
        # very_well_known_ports = [443] # used to differentiate possible mal vs serious mal
        # well_known_ports = [20, 21, 22, 23, 25, 53, 69, 80, 161, 179, 389, 443]
        if not communication_details_fetch.trafficDetailsFetch.is_multicast(
                src) and not communication_details_fetch.trafficDetailsFetch.is_multicast(dst) and \
                (dst in destination_hosts and destination_hosts[dst][
                    "domain_name"] == "NotResolvable") or port > 1024:
            return 1
        return 0

    # TODO: Covert communication module --> Add here
    # * Only add scapy first

    # Covert Detection Algorithm
    @staticmethod
    def covert_traffic_detection(packet):
        # covert ICMP - icmp tunneling ( Add TCP )
        tunnelled_protocols = ["DNS", "HTTP"]

        # TODO: this does not handle ipv6 --> so check before calling this function
        # if "IP" in packet:
        #    if communication_details_fetch.trafficDetailsFetch.is_multicast(packet["IP"].src) or communication_details_fetch.trafficDetailsFetch.is_multicast(packet["IP"].dst):
        #        return 0

        if "ICMP" in packet:
            if "TCP in ICMP" in packet or "UDP in ICMP" in packet or "DNS" in packet \
                    or "padding" in packet \
                    or filter(lambda x: x in str(packet["ICMP"].payload), tunnelled_protocols):
                return 1
        elif "DNS" in packet:
            # print(packet["DNS"].qd.qname)
            try:
                if communication_details_fetch.trafficDetailsFetch.dns(
                        packet["DNS"].qd.qname.strip()) == "NotResolvable" or \
                        len(filter(str.isdigit, str(packet["DNS"].qd.qname).strip())) > 8:
                    return 1
            except:
                pass
        return 0

    # Covert payload prediction algorithm
    @staticmethod
    def covert_payload_prediction(payload):

        ### Magic Number OR File Signature Intelligence
        # Fetch the File Signature OR Magic Numbers Intelligence from the Internet
        # Obtained from the Internet
        #          @ https://gist.github.com/Qti3e/6341245314bf3513abb080677cd1c93b
        #          @ /etc/nginx/mime.types
        #          @ http://www.garykessler.net/library/file_sigs.html
        #          @ https://en.wikipedia.org/wiki/List_of_file_signatures
        #
        global signatures
        try:
            if signatures == {}:
                signatures = json.load(magic_numbers)
            matches = []
            # Fetch payload from Packet in hex format
            string_payload = str(payload)
            try:
                payload = bytes(payload).hex()
            except:
                payload = str(payload)
            # Check dictionary for possible matches
            try:
                for file_type in signatures.keys():
                    for sign in signatures[file_type]["signs"]:
                        offset, magic = sign.split(",")
                        magic = magic.strip()
                        # print(magic, file_type)
                        # print(magic, string_payload, file_type)
                        if magic.lower() in payload or magic in string_payload:
                            matches.append(file_type)
            except:
                pass
            # print(matches, string_payload)
            return matches
        except:
            # print("File signature analysis failed!")
            return []