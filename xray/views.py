from django.views.generic import TemplateView
from django.shortcuts import render, redirect
from scapy.all import *
from django.views.decorators.csrf import csrf_exempt
import os, json
from django.conf import settings
from xray.libs.packet_reader import PacketProcessor
import pprint

from .forms import DefaultForm
from .models import Packet, Host, Pcap, Default
from .tables import PacketTable, HostTable
from django_tables2 import SingleTableView
from .defaults import asset_folder
from xray.libs.util_helpers import UtilHelpers
from xray.libs.network_plotter import PlotNetwork

pcapFilesPath = str(os.path.join(settings.BASE_DIR, 'assets'),)
staticFilesPath = str(os.path.join(settings.BASE_DIR, 'static'),)
staticFilesPath = str(os.path.join(settings.BASE_DIR, 'static'),)
templateFilesPath = str(os.path.join(settings.BASE_DIR, 'templates'),)


class Home(TemplateView):
    template_name = 'dashboard.html'

    def get_context_data(self, **kwargs):
        context = super(Home, self).get_context_data()
        context['pcaps'] = os.listdir(pcapFilesPath)
        return context


@csrf_exempt
def browse_pcap_file(request):
    """ This function opens the user selected pcap file returns the data to user page for display  """
    # Using scapy library, load the user selected pcap file from assets folder and read
    pcaps = os.listdir(pcapFilesPath)

    if request.POST:
        selected_pcap = request.POST.get('selected_pcap')
        recreate_table = request.POST.get('recreate_table')
        # print(type(recreate_table))

        pcap_table = Pcap()
        pcap_status = pcap_table.check_pcap_loaded(selected_pcap)
        if pcap_status > 0  and recreate_table is None:
            print('Pcap was already loaded...')
            return redirect('/packets_dashboard/' + selected_pcap)

        # rdpcap comes from scapy and loads in our pcap file        
        try:
            # Load the packets from the selected pcap file
            packets = rdpcap(asset_folder + selected_pcap)

            # Load the utility helper library and Get Hosts from packets
            util_helpers = UtilHelpers()
            util_helpers.create_hosts(packets, selected_pcap)

            # Read the packets from the pcap file and save to DB
            util_helpers.packet_reader(packets, selected_pcap)

            # Save the list of pcap files already loaded and processed so there is no
            # need to read it all over again, except explicitly requested by user.
            pcap_table.store_pcap(selected_pcap)

            # UtilHelpers.create_packets_details(netdata, selected_pcap)

            return redirect('/packets_dashboard/' + selected_pcap)

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

    def get_queryset(self, **kwargs):
        self.slug = self.kwargs.get('pcap', None)
        slug = self.slug
        return super().get_queryset().filter(name=slug)

    def get_context_data(self, *args, **kwargs):
        """ pepare the hosts, destinations, map url, and list of pcap files in assets folder """

        file_name = self.slug.replace(".pcap", "")

        # Load the utility library
        util_helper = UtilHelpers()

        # read the packets fro DB and build a dictionary of packets
        graph_dict = util_helper.build_graph_packets(self.slug)

        # Plot the grpah data from the read packets
        plot_network = PlotNetwork(file_name, staticFilesPath, 'plot')

        # Plot the graph image and interactive html
        plot_network.draw_graph()

        # Duild the page context data
        context = super(DashboardListView, self).get_context_data(*args,**kwargs)
        context['pcaps'] = pcaps = os.listdir(pcapFilesPath)
        context['selected_pcap'] = self.slug
        context['sources'] = Packet.get_sources(self.slug)[0]
        context['dests'] = Packet.get_sources(self.slug)[0]
        context['map_url'] = 'report/' + file_name + "_plot_All_All.png"

        templ_file = 'report/' + file_name + "_plot_All_All.html"
        if os.path.isfile(staticFilesPath + '/' + templ_file):
            context['map_html'] = templ_file
        else:
            context['map_html'] = "404.html"

        context['table_hosts'] = HostTable(
            Host.objects.all())
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

        print(sett)
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
