from django.db import models

class ThreatSource(models.Model):
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('blocked', 'Blocked'),
    )

    ip_address = models.CharField(max_length=45, unique=True)
    country = models.CharField(max_length=50, blank=True, null=True)
    threat_score = models.IntegerField(default=0)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.ip_address} ({self.country}) - Score: {self.threat_score}'

class Anomaly(models.Model):
    threat_source = models.ForeignKey(ThreatSource, on_delete=models.CASCADE, related_name='anomalies')
    timestamp = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=100)
    score_added = models.IntegerField()
    attacked_url = models.CharField(max_length=2048)
    details = models.CharField(max_length=255, blank=True, null=True)
    log_entry = models.TextField()

    def __str__(self):
        return f"Anomaly for {self.threat_source.ip_address} ({self.reason})"

class LogEntry(models.Model):
    threat_source = models.ForeignKey(ThreatSource, on_delete=models.CASCADE, null=True, blank=True, related_name='logs')
    ip_address = models.CharField(max_length=45)
    country = models.CharField(max_length=50, blank=True, null=True)
    url = models.CharField(max_length=2048)
    status_code = models.IntegerField()
    user_agent = models.CharField(max_length=255, blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    time_delta_ms = models.IntegerField(null=True, blank=True) # Новое поле

    def __str__(self):
        return f"Log from {self.ip_address} to {self.url} at {self.timestamp}"

class AIAnalysis(models.Model):
    widget_key = models.CharField(max_length=255, unique=True)
    analysis_text = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"AI Analysis for {self.widget_key} updated at {self.updated_at}"