from django.test import SimpleTestCase
from django.urls import reverse, resolve
from xray.views import Home, browse_pcap_file, DashboardListView


class TestUrls(SimpleTestCase):

    def test_index_url_is_resolved(self):
        url = reverse('xray:index')
        # print(resolve(url))
        self.assertEquals(resolve(url).func.view_class, Home)

    def test_browse_pcap_url_is_resolved(self):
        url = reverse('xray:browse_pcap')
        self.assertEquals(resolve(url).func, browse_pcap_file)

    def test_dashboard_url_is_resolved(self):
        url = reverse('xray:packets_dashboard', args=['pcap-file-name'])
        # print(resolve(url))
        self.assertEquals(resolve(url).func.view_class, DashboardListView)