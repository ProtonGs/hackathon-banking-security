import json
import os
import logging
import google.generativeai as genai
from datetime import timedelta
from django.utils import timezone
from django.http import JsonResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Sum, Avg
from django.db.models.functions import TruncMinute
from .models import ThreatSource, Anomaly, LogEntry, AIAnalysis
from .services import analyze_log_entry

logger = logging.getLogger(__name__)

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
    analyses = AIAnalysis.objects.all()
    context = {
        'ai_analyses': {analysis.widget_key: analysis.analysis_text for analysis in analyses}
    }
    return render(request, 'analyzer/dashboard.html', context)

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
    if not api_key or api_key == 'YOUR_GEMINI_API_KEY':
        raise ValueError("GEMINI_API_KEY not configured on server or is set to default.")
    genai.configure(api_key=api_key)
    return genai.GenerativeModel('gemini-2.5-flash')

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
        logger.error(f"Error in generate_kpi_insights: {e}")
        return JsonResponse({"error": str(e)}, status=500)

@login_required
def generate_deep_analysis(request):
    try:
        model = get_gemini_model()
        body = json.loads(request.body)
        analysis_type = body.get('analysis_type')
        data = body.get('data', {})
        
        prompt = ""
        # Prompt Factory
        if analysis_type == 'final_summary':
            cached_reports = data.get('cached_reports', {})
            prompt = f"""Выступи в роли главного аналитика по кибербезопасности. Тебе предоставлены индивидуальные анализы для каждого виджета на дашборде. Твоя задача — синтезировать их в один высокоуровневый, итоговый отчет.\n\n            Индивидуальные анализы:\n            ```json\n            {json.dumps(cached_reports, indent=2, ensure_ascii=False)}\n            ```\n\n            **Твоя задача:**\n            Напиши краткий, но емкий итоговый отчет (Executive Summary). Он должен включать:\n            1.  **Общая оценка угрозы (1-2 предложения):** Какова общая картина? (например, "Ситуация напряженная, зафиксирована скоординированная попытка сканирования уязвимостей...").\n            2.  **Ключевые наблюдения (список из 2-3 пунктов):** Укажи самые важные выводы из всех анализов (например, "- Основной вектор атаки направлен на эндпоинт /api/v2/payments.", "- Замечена аномальная активность из нетипичного для клиентов региона (Восточная Европа).").\n            3.  **Главная рекомендация (1 предложение):** Какое одно, самое важное действие нужно предпринять немедленно? (например, "Рекомендуется немедленно применить более строгие лимиты скорости запросов к /api/v2/payments и проверить логи на предмет успешных эксплойтов.").\n
            Отчет должен быть в формате Markdown, профессиональным и без воды."""
        else:
            kpis = data.get('kpis', {})
            charts = data.get('charts', {})
            if analysis_type == 'kpi_requests':
                prompt = f"Проанализируй как эксперт по кибербезопасности. Общее количество запросов за 24 часа: {kpis.get('total_requests')}. Это много, мало или нормально для банковского приложения? Есть ли признаки DDoS-атаки? Дай краткий, ясный вывод в формате Markdown."
            elif analysis_type == 'kpi_blocked':
                prompt = f"Проанализируй как эксперт по кибербезопасности. Количество заблокированных IP: {kpis.get('blocked_ips_count')}. Что это говорит о текущей ситуации? Это результат успешной защиты или признак массированной атаки? Дай краткий, ясный вывод в формате Markdown."
            # ... (other prompts remain the same, just add Markdown instruction)
            elif analysis_type == 'kpi_urls':
                prompt = f"Проанализируй как эксперт по кибербезопасности. Топ атакуемых URL: {json.dumps(kpis.get('top_attacked_urls'), indent=2)}. Какие уязвимости ищут атакующие, судя по этим URL? Являются ли эти атаки целевыми? Дай краткий, ясный вывод в формате Markdown."
            elif analysis_type == 'kpi_countries':
                prompt = f"Проанализируй как эксперт по кибербезопасности. Топ атакующих стран: {json.dumps(kpis.get('top_countries'), indent=2)}. Является ли распределение стран типичным? Есть ли геополитические или экономические причины для атак из этих регионов? Дай краткий, ясный вывод в формате Markdown."
            elif analysis_type == 'chart_threat':
                prompt = f"Проанализируй как эксперт по кибербезопасности. Данные графика 'Уровень угрозы во времени': {json.dumps(charts.get('threat_over_time')[:10])}... (показаны первые 10 точек). Есть ли на графике резкие пики? Если да, то в какое время? О чем говорят эти пики? Это скоординированная атака? Дай краткий, ясный вывод в формате Markdown."
            elif analysis_type == 'chart_anomaly':
                prompt = f"Проанализируй как эксперт по кибербезопасности. Распределение типов аномалий: {json.dumps(charts.get('anomaly_types'), indent=2)}. Какой тип атаки преобладает? (например, сканирование, кардинг, SQL-инъекции). Насколько это опасно для банковского приложения? Дай краткий, ясный вывод в формате Markdown."
            elif analysis_type == 'chart_country':
                prompt = f"Проанализируй как эксперт по кибербезопасности. Распределение запросов по странам: {json.dumps(charts.get('requests_by_country'), indent=2)}. Соответствует ли это распределение ожидаемой географии клиентов банка? Есть ли страны с аномально высоким количеством запросов, не являющиеся целевым рынком? Дай краткий, ясный вывод в формате Markdown."
            elif analysis_type == 'chart_speed':
                prompt = f"Проанализируй как эксперт по кибербезопасности. Среднее время между запросами: Человек - {charts.get('avg_request_time', {}).get('human'):.2f} мс, Бот - {charts.get('avg_request_time', {}).get('bot'):.2f} мс. Насколько показательна эта разница? Подтверждает ли это наличие автоматизированных атак? Дай краткий, ясный вывод в формате Markdown."

        if not prompt:
            return JsonResponse({"error": "Invalid analysis type"}, status=400)
        
        request_options = {"timeout": 30} # Increased timeout
        response = model.generate_content(prompt, request_options=request_options)

        # Save the analysis to the database
        AIAnalysis.objects.update_or_create(
            widget_key=analysis_type,
            defaults={'analysis_text': response.text}
        )

        return JsonResponse({"report": response.text})
    
    except Exception as e:
        logger.error(f"Error in generate_deep_analysis (type: {analysis_type}): {e}")
        return JsonResponse({"error": f"AI analysis failed: {e}"}, status=500)

@login_required
def reset_blocked_ips(request):
    if request.method == 'POST':
        ThreatSource.objects.filter(status='blocked').update(status='active', threat_score=0)
        return HttpResponseRedirect(reverse('analyzer:dashboard'))
    return HttpResponseRedirect(reverse('analyzer:dashboard'))