from django.urls import path
from . import views

app_name = 'analyzer'
urlpatterns = [
    path('api/logs/', views.log_receiver, name='log_receiver'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('api/dashboard-data/', views.dashboard_data, name='dashboard_data'),
    path('api/kpi-insights/', views.generate_kpi_insights, name='generate_kpi_insights'),
    path('api/deep-analysis/', views.generate_deep_analysis, name='generate_deep_analysis'),
    path('api/reset-blocked-ips/', views.reset_blocked_ips, name='reset_blocked_ips'),
]
