import django_tables2 as tables
from django_tables2.utils import A

from .models import Packet, Host


class PacketTable(tables.Table):
    # Ether_src = tables.Column(
    #     accessor=A('src'),
    # )
    # Ether_dst = tables.Column(
    #     accessor=A('dst'),
    # )
    # # port = tables.Column(
    # #     accessor=A('port'),
    # # )
    # IP_src = tables.Column(
    #     accessor=A('ipsrc'),
    # )
    # IP_dst = tables.Column(
    #     accessor=A('ipdst'),
    # )
    # IP_port = tables.Column(
    #     accessor=A('ipport'),
    # )
    class Meta:
        model = Packet
        template_name = 'django_tables2/bootstrap.html'
        fields = ('name', 'packet_time', 'ether_src', 'ether_dst', 'ip_src', 'ip_dst', 'src_port', 'dst_port', 'ip_version', 'protocol', 'packet_length', 'covert', 'summary', 'payload')
        # sequence = ('packet_time', 'ether_src', 'ether_dst', 'ip_src', 'ip_dst', 'src_port', 'dst_port', 'ip_version', 'protocol', 'packet_length', 'covert', 'summary')


class HostTable(tables.Table):
    class Meta:
        model = Host
        template_name = 'django_tables2/bootstrap.html'
        fields = ('src', 'dst', 'ip_version')
