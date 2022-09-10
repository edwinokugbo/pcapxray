import django_tables2 as tables
from django_tables2.utils import A

from .models import Packet, Host


class PacketTable(tables.Table):
    class Meta:
        model = Packet
        template_name = 'django_tables2/bootstrap.html'
        fields = ('name', 'packet_time', 'ether_src', 'ether_dst', 'src_port', 'dst_port', 'ip_src', 'ip_dst', 'port', 'port_type', 'ip_version', 'protocol', 'packet_length', 'covert', 'summary', 'payload')
        # sequence = ('packet_time', 'ether_src', 'ether_dst', 'ip_src', 'ip_dst', 'src_port', 'dst_port', 'ip_version', 'protocol', 'packet_length', 'covert', 'summary')


class HostTable(tables.Table):
    class Meta:
        model = Host
        template_name = 'django_tables2/bootstrap.html'
        fields = ('src', 'dst', 'ip_version')
