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
    avg_time_bot = LogEntry.objects.filter(threat_source__threat_score__gte=20, time_delta_ms__isnull=False).aggregate(avg=Avg('time_delta_ms'))['avg'] or 0
    avg_time_human = LogEntry.objects.filter(threat_source__threat_score__lt=20, time_delta_ms__isnull=False).aggregate(avg=Avg('time_delta_ms'))['avg'] or 0
    
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
        # Prompt Factory - V2 (Professional)
        if analysis_type == 'final_summary':
            cached_reports = data.get('cached_reports', {})
            prompt = f"""Выступи в роли главного аналитика по кибербезопасности (Lead Cyber Security Analyst). Тебе предоставлены индивидуальные анализы для каждого виджета на дашборде. Твоя задача — синтезировать их в один высокоуровневый, итоговый отчет для руководства (Executive Summary).\n\n            Индивидуальные анализы:\n            ```json\n            {json.dumps(cached_reports, indent=2, ensure_ascii=False)}\n            ```\n\n            **Твоя задача:**\n            Напиши краткий, но емкий итоговый отчет (Executive Summary) в формате Markdown. Он должен включать:\n            1.  **Общая оценка угрозы (1-2 предложения):** Какова общая картина? (например, "Ситуация напряженная, зафиксирована скоординированная попытка сканирования уязвимостей, нацеленная на платежные API...").\n            2.  **Ключевые наблюдения (список из 2-3 пунктов):** Укажи самые важные выводы из всех анализов (например, "- Основной вектор атаки направлен на эндпоинт /api/v2/payments, что указывает на попытки мошенничества.", "- Замечена аномальная активность из нетипичного для клиентов региона (Восточная Европа), совпадающая по времени с атаками.").\n            3.  **Главная рекомендация (1 предложение):** Какое одно, самое важное действие нужно предпринять немедленно? (например, "Рекомендуется немедленно применить более строгие лимиты скорости запросов к /api/v2/payments и провести аудит безопасности кода, отвечающего за обработку платежей.").\n
            Отчет должен быть профессиональным, без воды и ориентированным на принятие решений."""
        else:
            kpis = data.get('kpis', {})
            charts = data.get('charts', {})
            if analysis_type == 'kpi_requests':
                prompt = f"""**Анализ общего трафика.**\nОбщее количество запросов за 24 часа: **{kpis.get('total_requests')}**.\n\n*   Это соответствует обычному дневному трафику для нашего банковского приложения? \n*   Есть ли признаки начала DDoS-атаки (например, резкий рост по сравнению с предыдущим периодом, который не виден на других графиках)?\n*   Дай краткий вывод: трафик в норме, требует наблюдения или вызывает беспокойство? Предоставь ответ в формате Markdown."""
            elif analysis_type == 'kpi_blocked':
                prompt = f"""**Анализ блокировок.**\nКоличество заблокированных IP: **{kpis.get('blocked_ips_count')}**.\n\n*   Это число выросло, упало или осталось стабильным за последние несколько часов (на основе предыдущих данных, если они есть в твоем контексте)?\n*   Что это говорит о текущей ситуации: мы успешно отбиваем стандартные атаки, или это признак новой, массированной волны атак?\n*   Дай краткий вывод и оценку эффективности системы блокировки. Предоставь ответ в формате Markdown."""
            elif analysis_type == 'kpi_urls':
                prompt = f"""**Анализ векторов атак.**\nТоп-5 атакуемых URL-адресов:\n```\n{json.dumps(kpis.get('top_attacked_urls'), indent=2, ensure_ascii=False)}\n```\n\n*   **Определи намерения атакующих.** На что нацелены эти атаки? (например, `/.git/config` - поиск исходного кода; `/api/auth/login` - попытка подбора паролей; `/products?id='...` - попытка SQL-инъекции).\n*   Оцени критичность этих эндпоинтов. Являются ли они общедоступными или частью внутренней системы?\n*   Дай рекомендацию: какие из этих URL требуют немедленного внимания и проверки безопасности? Предоставь ответ в формате Markdown."""
            elif analysis_type == 'kpi_countries':
                prompt = f"""**Геоанализ угроз.**\nТоп-5 стран-источников атак:\n```\n{json.dumps(kpis.get('top_countries'), indent=2, ensure_ascii=False)}\n```\n\n*   Соответствует ли этот список географии наших реальных клиентов? \n*   Известны ли какие-либо из этих стран как источники киберугроз определенного типа (например, кардинг, спонсируемые государством атаки)?\n*   Дай вывод: является ли эта активность целевой атакой из определенных регионов или просто фоновым интернет-шумом? Предоставь ответ в формате Markdown."""
            elif analysis_type == 'chart_threat':
                prompt = f"""**Анализ динамики угроз.**\nДанные графика 'Уровень угрозы во времени' (показаны первые 10 точек):\n```\n{json.dumps(charts.get('threat_over_time')[:10], ensure_ascii=False)}\n```\n\n*   Выдели временные интервалы с пиковой активностью. Совпадают ли они с рабочими часами или, наоборот, с ночным временем?\n*   Являются ли пики короткими всплесками (сканирование) или продолжительными периодами (DDoS, брутфорс)?\n*   Дай оценку: это была скоординированная атака или случайные, не связанные события? Предоставь ответ в формате Markdown."""
            elif analysis_type == 'chart_anomaly':
                prompt = f"""**Анализ типов аномалий.**\nРаспределение типов зафиксированных аномалий:\n```\n{json.dumps(charts.get('anomaly_types'), indent=2, ensure_ascii=False)}\n```\n\n*   Какой тип атаки является доминирующим? (например, `Path Scanning`, `SQL Injection Attempt`, `Robotic Activity`).\n*   Оцени бизнес-риски от преобладающего типа атаки. Что является целью: кража данных, нарушение работы сервиса, мошенничество?\n*   Дай рекомендацию по противодействию наиболее частому типу аномалий. Предоставь ответ в формате Markdown."""
            elif analysis_type == 'chart_country':
                prompt = f"""**Анализ трафика по странам.**\nРаспределение всех запросов по странам:\n```\n{json.dumps(charts.get('requests_by_country'), indent=2, ensure_ascii=False)}\n```\n\n*   Сравни этот график с виджетом 'Топ атакующих стран'. Есть ли страны с большим количеством запросов, но низким уровнем угрозы (вероятно, легитимные пользователи)?\n*   Есть ли страны, которые не входят в топ по запросам, но генерируют много атак? Это указывает на целенаправленную вредоносную активность.\n*   Дай вывод о наличии подозрительных расхождений между общим трафиком и трафиком атак. Предоставь ответ в формате Markdown."""
            elif analysis_type == 'chart_speed':
                prompt = f"""**Анализ скорости запросов.**\nСреднее время между запросами: Человек - **{charts.get('avg_request_time', {}).get('human'):.2f} мс**, Бот - **{charts.get('avg_request_time', {}).get('bot'):.2f} мс**.\n\n*   Насколько значительна эта разница? Является ли она однозначным индикатором автоматизации?\n*   Если разница мала, может ли это означать, что боты имитируют поведение человека, используя большие задержки?\n*   Дай окончательный вывод: подтверждают ли эти данные наличие автоматизированных атак на систему? Предоставь ответ в формате Markdown."""

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
def reset_all_data(request):
    if request.method == 'POST':
        LogEntry.objects.all().delete()
        Anomaly.objects.all().delete()
        ThreatSource.objects.all().delete()
        AIAnalysis.objects.all().delete()
        return HttpResponseRedirect(reverse('analyzer:dashboard'))
    return HttpResponseRedirect(reverse('analyzer:dashboard'))