from django.urls import path, include, re_path
from .views import Home, DashboardListView, default_settings, ViewMap, GetMapReport
from . import views

app_name = 'xray'

urlpatterns = [
    re_path(r'^$', Home.as_view(), name='index'),
    path('browse_pcap/', views.browse_pcap_file, name='browse_pcap'),
    path('packets_dashboard/<str:pcap>/<str:filter_packet>', DashboardListView.as_view(), name='packets_dashboard'),
    path('edit_defaults/', views.default_settings.as_view(), name='edit_defaults'),
    path('visualize_map/', views.visualize_map, name='visualize_map'),
    path('view_map/<str:pcap>/<str:filter_packet>', ViewMap.as_view(), name='view_map'),
    path('get_map_report/', GetMapReport.as_view(), name='get_map_report'),
]