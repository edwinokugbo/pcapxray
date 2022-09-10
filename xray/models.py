import os
from datetime import datetime

from django.conf import settings
from django.db import models
from django.db.models import Q
import json


class Packet(models.Model):
    name = models.CharField(max_length=255, null=True)
    ether_src = models.CharField(max_length=20, null=True)
    ether_dst = models.CharField(max_length=20, null=True)
    ip_src = models.CharField(max_length=20, null=True)
    ip_dst = models.CharField(max_length=20, null=True)
    port = models.CharField(max_length=15, null=True)
    port_type = models.CharField(max_length=15, null=True)
    src_port = models.CharField(max_length=15, null=True)
    dst_port = models.CharField(max_length=15, null=True)
    ip_version = models.CharField(max_length=7, null=True)
    protocol = models.CharField(max_length=10, null=True)
    is_src_private = models.BooleanField(null=True)
    is_dst_private = models.BooleanField(null=True)
    covert = models.CharField(max_length=10)
    forward = models.TextField(null=True)
    reverse = models.TextField(null=True)
    file_signatures = models.CharField(max_length=255, null=True)
    payload = models.TextField(null=True)
    summary = models.TextField(null=True)
    session_key = models.CharField(max_length=255, null=True)
    ethernet = models.CharField(max_length=75, null=True)
    packet_time = models.DateTimeField(null=True)
    packet_length = models.IntegerField(null=True)

    def __str__(self):
        return str(self.name) + " : " + str(self.ip_src) + " : " + str(self.ip_dst)

    def get_record(self):
        return self.objects.get()

    @staticmethod
    def delete_all(name):
        """ empty table o we can fill with new packets data from user selected file """
        return Packet.objects.filter(name=name).delete()

    @staticmethod
    def save_batch_data(data):
        """ save batch packets to DB """
        return Packet.objects.bulk_create(data)

    @staticmethod
    def get_sources(name):
        """ Get the list of source and destination IPs for source and destination combo boxes """
        src_list = set(Packet.objects.filter(name=name).values_list('ether_src', flat=True))
        dest_list = set(Packet.objects.filter(name=name).values_list('ether_dst', flat=True))
        return src_list, dest_list

    def get_unique_ethers(name):
        test_lst = []
        unique_lst = []
        hosts = Packet.objects.filter(name=name)

        for host in hosts:
            if host.ether_src not in test_lst:
                test_lst.append(host.ether_src)
                unique_lst.append({'host': host.ether_src, 'ip': host.ip_src, 'port': host.port, 'type': host.port_type})
            if host.ether_dst not in test_lst:
                test_lst.append(host.ether_dst)
                unique_lst.append({'host': host.ether_dst, 'ip': host.ip_dst, 'port': host.port, 'type': host.port_type})

        return unique_lst

    def generate_map_report(self, ip, name):
        packets = Packet.objects.filter(
            Q(name=name) & ~Q(port_type=None) & Q(ip_src=ip) | Q(ip_dst=ip)).values('ether_src', 'ether_dst', 'ip_src', 'ip_dst', 'summary', 'port', 'port_type')

        report = '<h3>Pcap Node Report/Analysis</h3><hr class="py-2 py-2">'
        report += '<h4>Selected Node</h4>'
        report += '<p>' + ip + '</p><br>'
        report += '<h4>Related Nodes</h4>'

        for pkt in packets:
            if pkt['port_type'] is not None:
                report += '<div class="row-bg mb-2 px-4 py-2 border-2 border-slate-200"><span class="bold">Source: </span> <span class="blue">Ether</span> - ' + \
                          pkt['ether_src'] + ' </span> <span class="blue">IP</span> - ' + pkt[
                              'ip_src'] + ' <span class="bold">Destination: </span> </span> <span class="blue">Ether</span> - ' + \
                          pkt['ether_dst'] + ' </span> <span class="blue">IP</span> - ' + pkt[
                              'ip_dst'] + ' <span class="bold">Traffic:</span> ' + pkt[
                              'port_type'] + '<br> <span class="blue">Payload: </span>' + pkt['summary'] + '</div>'
        return report

class Network(models.Model):
    lan_hosts = models.CharField(max_length=30, null=True)
    destination_hosts = models.CharField(max_length=30, null=True)
    tor_nodes = models.CharField(max_length=20, null=True)
    possible_tor_traffic = models.CharField(max_length=20, null=True)
    possible_malicious_traffic = models.CharField(max_length=20, null=True)
    signatures = models.CharField(max_length=20, null=True)

    def __str__(self):
        return self.lan_hosts +  ":" + self.destination_hosts


class Host(models.Model):
    name = models.CharField(max_length=255, null=True)
    src = models.CharField(max_length=25, null=True)
    dst = models.CharField(max_length=25, null=True)
    ip_version = models.CharField(max_length=7, null=True)

    def __str__(self):
        return self.src + ' / ' + self.dst

    @staticmethod
    def delete_all(name):
        """ empty table so we can fill with new hosts data from user selected file """
        return Host.objects.filter(name=name).delete()

    @staticmethod
    def save_batch_data(data):
        """ save batch packets to DB """
        return Host.objects.bulk_create(data)

    def get_unique_list(name):
        unique_lst = []
        hosts = Host.objects.filter(name=name)

        for host in hosts:
            if host.src not in unique_lst:
                unique_lst.append(host.src)
            if host.dst not in unique_lst:
                unique_lst.append(host.dst)

        return unique_lst


class Pcap(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(null=True)
    date_uploaded = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.name)

    def check_pcap_loaded(self, name):
        found = Pcap.objects.filter(name=name).count()
        return found

    def store_pcap(self, name):
        self.delete_all(name)
        cap = Pcap(name=name)
        cap.save()

    def delete_all(self, name):
        return Pcap.objects.filter(name=name).delete()


class Default(models.Model):
    THEME_CHOICES = ((0, 'Dark'), (1, 'Light'), (2, 'Grey'))
    REPORT_CHOICES = ((0, 'No'), (1, 'Yes'))
    EDGE_WIDTH_CHOICES = ((1, '1'), (2, '2'), (3, '3'), (4, '4'), (5, '5'), (10, '10'), (15, '15'), (20, '20'))
    output_dir = models.FilePathField(path=str(os.path.join(settings.BASE_DIR, 'static'),), allow_files=False, allow_folders=True, null=True, recursive=True)
    show_unknown_protocols = models.IntegerField(default=0, choices=((0, 'No'), (1, 'Yes')))
    update_report = models.IntegerField(default=0)
    theme = models.IntegerField(default=0, choices=THEME_CHOICES)
    skip_old_report = models.IntegerField(default=0, choices=REPORT_CHOICES)
    edge_width = models.IntegerField(default=1, choices=EDGE_WIDTH_CHOICES)

    def __str__(self):
        return self.output_dir

    def get_theme(self):
        defaults = Default.objects.get(id=1)
        theme = {}
        if defaults.theme == 0:
            theme = {
                "bg_color": "#000"
            }
        elif defaults.theme == 1:
            theme = {
                "bg_color": "#fff"
            }
        elif defaults.theme == 2:
            theme = {
                "bg_color": "#C0C0C0"
            }
        else:
            theme = {
                "bg_color": "#000"
            }
        return theme

    def get_edge_width(self):
        defaults = Default.objects.get(id=1)
        return defaults.edge_width


class Tor(models.Model):
    node = models.CharField(max_length=100)
    date_created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.node

