from django.test import TestCase, Client
from django.urls import reverse
from xray.views import Home, browse_pcap_file, DashboardListView


class TestViews(TestCase):

    def test_browse_pcap_file_POST(self):
        client = Client()

        response = client.get(reverse('xray:browse_pcap'))

        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard.html')

    def test_browse_pcap_file_POST(self):
        client = Client()

        response = client.get(reverse('xray:packets_dashboard', args=['pcap-file-name']))

        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard.html')
