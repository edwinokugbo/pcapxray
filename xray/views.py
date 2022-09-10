from django.views.generic import TemplateView, View
from django.shortcuts import render, redirect
from django.http import HttpResponse
from scapy.all import *
from django.views.decorators.csrf import csrf_exempt
import os, json
from django.conf import settings
from xray.libs.packet_reader import PacketProcessor
import pprint

from .forms import DefaultForm
from .models import Packet, Host, Pcap, Default, Tor
from .tables import PacketTable, HostTable
from django_tables2 import SingleTableView
# from .defaults import asset_folder
from xray.libs.util_helpers import UtilHelpers
from xray.libs.network_plotter import PlotNetwork

asset_folder = str(os.path.join(settings.BASE_DIR, 'assets/'), )
pcapFilesPath = str(os.path.join(settings.BASE_DIR, 'assets'), )
staticFilesPath = str(os.path.join(settings.BASE_DIR, 'static'), )
templateFilesPath = str(os.path.join(settings.BASE_DIR, 'templates'), )
dataFilesPath = str(os.path.join(settings.BASE_DIR, 'xray/data'), )
htmlFilesPath = str(os.path.join(settings.BASE_DIR, 'xray/templates'), )


class Home(TemplateView):
    template_name = 'dashboard.html'

    def get_context_data(self, **kwargs):
        context = super(Home, self).get_context_data()
        context['pcaps'] = os.listdir(pcapFilesPath)
        context['filter_options'] = ['All', 'HTTP', 'HTTPS', 'ICMP', 'DNS', 'Tor', 'Malicious']
        return context

class ViewMap(TemplateView):
    # template_name = 'report.html'
    template_name = 'interactive_map_20.html'
    selected_pcap = None
    packet_filter = 'All'

    def get_context_data(self, *args, **kwargs):
        self.selected_pcap = self.kwargs.get('pcap', None)
        self.packet_filter = self.kwargs.get('filter_packet', None)
        context = super(ViewMap, self).get_context_data(*args, **kwargs)

        defaults = Default()
        theme = defaults.get_theme()
        edge_width = defaults.get_edge_width()

        packet_filter = 'All'
        utils = UtilHelpers()

        nodes, edges = utils.make_dynamic_map_data(self.selected_pcap, self.packet_filter, edge_width)

        context['theme'] = theme
        context['nodes'] = nodes
        context['edges'] = edges
        context['selected_pcap'] = self.selected_pcap

        return context

@csrf_exempt
def browse_pcap_file(request):
    """ This function opens the user selected pcap file returns the data to user page for display  """
    # Using scapy library, load the user selected pcap file from assets folder and read
    pcaps = os.listdir(pcapFilesPath)

    if request.POST:
        selected_pcap = request.POST.get('selected_pcap')
        recreate_table = request.POST.get('recreate_table')
        filter_packet = request.POST.get('filter_packet')

        pcap_table = Pcap()
        pcap_status = pcap_table.check_pcap_loaded(selected_pcap)
        if pcap_status > 0 and recreate_table is None:
            print('Pcap was already loaded...')
            update_report = Default.objects.get(id=1)
            update_report.update_report = 1
            update_report.save()
            return redirect('/packets_dashboard/' + selected_pcap + '/' + filter_packet)

        # rdpcap comes from scapy and loads in our pcap file        
        try:
            # Load the packets from the selected pcap file
            packets = rdpcap(asset_folder + selected_pcap)

            # Load the utility helper library and Get Hosts from packets
            util_helpers = UtilHelpers()

            # Get Tor traffic modes from remote
            # util_helpers.get_tor_data()

            # Create hosts list and save to DB
            util_helpers.create_hosts(packets, selected_pcap)

            # Read the packets from the pcap file and save to DB
            util_helpers.packet_reader(packets, selected_pcap)

            # Save the list of pcap files already loaded and processed so there is no
            # need to read it all over again, except explicitly requested by user.
            pcap_table.store_pcap(selected_pcap)

            # UtilHelpers.create_packets_details(netdata, selected_pcap)

            return redirect('/packets_dashboard/' + selected_pcap + '/' + filter_packet)

        except FileExistsError:
            # If there is an error reading the file, raise it and go back to dashboard
            print('Error loading file')
            context = {'pcaps': pcaps, 'selected_pcap': selected_pcap}
            return render(request, 'dashboard.html', context)

    context = {'pcaps': pcaps}
    return render(request, 'dashboard.html', context)


class DashboardListView(SingleTableView):
    """ Dashboad view to display pcap data after extraction and processing """
    model = Packet
    table_class = PacketTable
    template_name = 'dashboard.html'
    slug = None
    filter_packet = 'All'

    def get_queryset(self, **kwargs):
        self.slug = self.kwargs.get('pcap', None)
        self.filter_packet = self.kwargs.get('filter_packet', None)
        slug = self.slug
        util_helpers = UtilHelpers()
        if self.filter_packet == 'All':
            filtered_packets = super().get_queryset().filter(name=slug)
        else:
            # filtered_packets = super().get_queryset().filter(name=slug, port=util_helpers.get_port_number(self.filter_packet))
            filtered_packets = super().get_queryset().filter(name=slug, port_type=self.filter_packet)
        return filtered_packets

    def get_context_data(self, *args, **kwargs):
        """ pepare the hosts, destinations, map url, and list of pcap files in assets folder """

        defaults = Default.objects.get(id=1)
        # print(update_report.update_report)

        file_name = self.slug.replace(".pcap", "")

        # Check if settings is set to (re)create reports and do accordingly
        if defaults.update_report == 1:

            # Check if settings is further set to (re)create old interactive reports.
            # This feature may be useful for slow internet onnetions and you just want to get the
            # new interactive report very fast
            if defaults.skip_old_report == 0:
                # Create the graph data from the read packets
                plot_network = PlotNetwork(file_name, staticFilesPath, self.filter_packet)

                # Plot the graph image and interactive html
                plot_network.draw_graph(self.filter_packet)

            print('Time to create map for...' + self.slug)
            util_helper = UtilHelpers()
            util_helper.make_dynamic_map(dataFilesPath, templateFilesPath, self.slug, self.filter_packet, defaults.theme)
            defaults.update_report = 0
            defaults.save()

        # Build the page context data
        context = super(DashboardListView, self).get_context_data(*args, **kwargs)
        context['pcaps'] = pcaps = os.listdir(pcapFilesPath)
        context['selected_pcap'] = self.slug
        context['sources'] = Packet.get_sources(self.slug)[0]
        context['dests'] = Packet.get_sources(self.slug)[0]
        context['map_url'] = 'report/' + file_name + "_" + self.filter_packet + "_All_All.png"
        context['filter_packet'] = self.filter_packet
        context['filter_options'] = ['All', 'HTTP', 'HTTPS', 'ICMP', 'DNS', 'Tor', 'Malicious']

        templ_file = 'report/' + file_name + "_" + self.filter_packet + "_All_All.html"
        if os.path.isfile(staticFilesPath + '/' + templ_file):
            context['map_html'] = templ_file
        else:
            context['map_html'] = "404.html"

        context['table_hosts'] = HostTable(
            Host.objects.filter(name=self.slug))
        return context


def visualize_map(request):
    """ Function to create and visualise the pcap map image """
    pcaps = os.listdir(pcapFilesPath)

    context = {'pcaps': pcaps}
    return render(request, 'dashboard.html', context)


class default_settings(TemplateView):
    """ Edit default settings """
    template_name = 'default_settings.html'

    # context = {}

    def get(self, request):

        try:
            sett = Default.objects.get(id=1)
        except:
            sett = None

        if sett is None:
            self.context['form'] = DefaultForm()
        else:
            default = Default.objects.get(id=1)
            form = DefaultForm(instance=default)

        context = {
            'form': form
        }
        return render(request, 'default_settings.html', context)

    def post(self, request):
        context = DefaultForm

        default = Default.objects.get(id=1)
        form = DefaultForm(request.POST, instance=default)

        if form.is_valid():
            form.save()
            print('Form Saved')
            return redirect('/edit_defaults')

        return redirect('edit_defaults', context)


class GetMapReport(View):
    """ Get map report for interactive map view 2.0 """

    def get(self, request):
        ipaddr = request.GET.get('ipaddr', '')
        name = request.GET.get('name', '')
        report = self.make_map_report(ipaddr, name)
        print(name)
        resp = {'html': report}
        return HttpResponse(json.dumps(resp), content_type="application/json")

    def make_map_report(self, ip, name):

        # Call the generate map report from packets model
        packets = Packet()
        report = packets.generate_map_report(ip, name)

        return report
