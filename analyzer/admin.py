from django.contrib import admin
from .models import ThreatSource

@admin.register(ThreatSource)
class ThreatSourceAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'threat_score', 'status', 'last_seen')
    list_filter = ('status',)
    search_fields = ('ip_address',)