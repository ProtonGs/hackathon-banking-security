import json
import os
import google.generativeai as genai
from datetime import timedelta
from django.utils import timezone
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Sum, Avg
from django.db.models.functions import TruncMinute
from .models import ThreatSource, Anomaly, LogEntry
from .services import analyze_log_entry

@csrf_exempt
def log_receiver(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            analyze_log_entry(data)
            return JsonResponse({"status": "ok"})
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
    return JsonResponse({"error": "Only POST method allowed"}, status=405)

@login_required
def dashboard(request):
    return render(request, 'analyzer/dashboard.html')

@login_required
def dashboard_data(request):
    now = timezone.now()
    last_24_hours = now - timedelta(hours=24)

    # --- KPIs ---
    total_requests = LogEntry.objects.filter(timestamp__gte=last_24_hours).count()
    blocked_threats = ThreatSource.objects.filter(status='blocked')
    kpis = {
        'total_requests': total_requests,
        'blocked_ips_count': blocked_threats.count(),
        'top_attacked_urls': list(Anomaly.objects.filter(timestamp__gte=last_24_hours).values('attacked_url').annotate(count=Count('id')).order_by('-count')[:5]),
        'top_countries': list(Anomaly.objects.filter(timestamp__gte=last_24_hours).values('threat_source__country').annotate(count=Count('id')).order_by('-count')[:5])
    }

    # --- Данные для модальных окон ---
    modal_data = {
        'blocked_ips': list(blocked_threats.values('ip_address', 'country', 'threat_score').order_by('-threat_score'))
    }

    # --- Данные для графиков ---
    threat_over_time = Anomaly.objects.filter(timestamp__gte=last_24_hours).annotate(minute=TruncMinute('timestamp')).values('minute').annotate(total_score=Sum('score_added')).order_by('minute')
    anomaly_types = Anomaly.objects.filter(timestamp__gte=last_24_hours).values('reason').annotate(count=Count('id')).order_by('-count')
    requests_by_country = LogEntry.objects.filter(timestamp__gte=last_24_hours).values('country').annotate(count=Count('id')).order_by('-count')[:10]
    avg_time_bot = LogEntry.objects.filter(threat_source__anomalies__isnull=False, time_delta_ms__isnull=False).aggregate(avg=Avg('time_delta_ms'))['avg'] or 0
    avg_time_human = LogEntry.objects.filter(threat_source__anomalies__isnull=True, time_delta_ms__isnull=False).aggregate(avg=Avg('time_delta_ms'))['avg'] or 0
    
    charts = {
        'threat_over_time': list(threat_over_time),
        'anomaly_types': list(anomaly_types),
        'requests_by_country': list(requests_by_country),
        'avg_request_time': {'bot': avg_time_bot, 'human': avg_time_human}
    }

    # --- Live Log Feed ---
    live_logs = list(LogEntry.objects.order_by('-timestamp')[:10].values('timestamp', 'ip_address', 'country', 'url'))
    for log in live_logs:
        log['timestamp'] = log['timestamp'].strftime('%H:%M:%S')

    return JsonResponse({'kpis': kpis, 'charts': charts, 'modal_data': modal_data, 'live_logs': live_logs})

def get_gemini_model():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not configured on server.")
    genai.configure(api_key=api_key)
    return genai.GenerativeModel('gemini-1.5-flash')

@login_required
def generate_kpi_insights(request):
    try:
        model = get_gemini_model()
        kpi_data = json.loads(request.body).get('kpis', {})
        prompt = f"""...""" # Prompt is unchanged
        response = model.generate_content(prompt)
        clean_response = response.text.strip().replace('```json', '').replace('```', '')
        return JsonResponse(json.loads(clean_response))
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@login_required
def generate_deep_analysis(request):
    try:
        model = get_gemini_model()
        chart_data = json.loads(request.body).get('charts', {})
        prompt = f"""...""" # Prompt is unchanged
        response = model.generate_content(prompt)
        return JsonResponse({"report": response.text})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)