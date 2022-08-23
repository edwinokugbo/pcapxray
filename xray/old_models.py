from datetime import datetime
from django.db import models
import json


class Packet(models.Model):
    session_key = models.CharField(max_length=255, null=True)
    ethernet = models.CharField(max_length=75, null=True)
    forward = models.TextField(null=True)
    reverse = models.TextField(null=True)
    covert = models.CharField(max_length=10)
    file_signatures = models.CharField(max_length=255, null=True)
    ether_src = models.CharField(max_length=20, null=True)
    ether_dst = models.CharField(max_length=20, null=True)
    ip_src = models.CharField(max_length=20, null=True)
    ip_dst = models.CharField(max_length=20, null=True)
    ip = models.CharField(max_length=7, null=True)
    protocol = models.CharField(max_length=10, null=True)
    packet_time = models.DateTimeField(null=True)

    def __str__(self):
        return self.session_key + " : " + self.ethernet

    def get_record(self):
        return self.objects.get()

    @staticmethod
    def delete_all():
        """ empty table o we can fill with new packets data from user selected file """
        return Packet.objects.all().delete()

    @staticmethod
    def save_batch_data(data):
        """ save batch packets to DB """
        return Packet.objects.bulk_create(data)

    @staticmethod
    def get_sources():
        """ Get the list of source and destination IPs for source and destination combo boxes """
        src_list = set(Packet.objects.values_list('ether_src', flat=True))
        dest_list = set(Packet.objects.values_list('ether_dst', flat=True))
        return src_list, dest_list

    def src(self):
        ether = json.loads(self.ethernet)
        return ether['src']

    def dst(self):
        ether = json.loads(self.ethernet)
        return ether.get('dst')

    def ipsrc(self):
        sk = self.session_key.split('/')
        return sk[0]

    def ipdst(self):
        sk = self.session_key.split('/')
        return sk[1]

    def ipport(self):
        sk = self.session_key.split('/')
        return sk[2]


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
    src = models.CharField(max_length=25, null=True)
    dst = models.CharField(max_length=25, null=True)
    ip_version = models.CharField(max_length=7, null=True)

    def __str__(self):
        return self.src + ' / ' + self.dst

    @staticmethod
    def delete_all():
        """ empty table so we can fill with new hosts data from user selected file """
        return Host.objects.all().delete()

    @staticmethod
    def save_batch_data(data):
        """ save batch packets to DB """
        return Host.objects.bulk_create(data)