from django.urls import path, include, re_path

from .views import DashboardListView
# SignupPageView
from . import views

app_name = 'xray'

urlpatterns = [
    re_path(r'^$', views.index, name='index'),
    path('browse_pcap/', views.browse_pcap_file, name='browse_pcap'),
    path('packets_dashboard/<str:pcap>/', DashboardListView.as_view(), name='packets_dashboard'),
    path('visualize_map/', views.visualize_map, name='visualize_map'),
    # path('browse_net_data/<str:pcap>/', views.myview, name='browse_net_data')
    # re_path('contact/', views.Contact.as_view(), name='contact'),
    # re_path('login/', views.loginPage, name="login"),
    # re_path('logout/', views.logoutPage, name="logout"),
    # re_path('signup/', SignupPageView.as_view(), name="home"),
    # path("home/", DashboardListView.as_view(), name="home")

]