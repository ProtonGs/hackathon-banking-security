from .models import ThreatSource, Anomaly, LogEntry
import json
from django.utils import timezone
from datetime import timedelta

MIN_REQUEST_DELTA = timedelta(milliseconds=200)
BAD_USER_AGENTS = ['sqlmap', 'nmap', 'gobuster', 'nikto', 'wfuzz']

def luhn_checksum(card_number):
    # ... (luhn_checksum function remains the same)
    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = 0
    checksum += sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    return checksum % 10 == 0

def analyze_log_entry(log_data):
    ip_address = log_data.get('ip')
    if not ip_address:
        return

    # Получаем или создаем источник угрозы
    threat, created = ThreatSource.objects.get_or_create(
        ip_address=ip_address,
        defaults={'country': log_data.get('country', 'Unknown')}
    )

    # --- Вычисляем время с последнего запроса ---
    now = timezone.now()
    time_delta = now - threat.last_seen
    time_delta_ms = int(time_delta.total_seconds() * 1000)

    # Извлечение данных из лога
    url = log_data.get('url', '')
    status_code = int(log_data.get('status_code', 200))
    user_agent = log_data.get('user_agent', '')
    log_line = json.dumps(log_data)

    # 1. Записываем каждый лог, включая time_delta
    LogEntry.objects.create(
        threat_source=threat,
        ip_address=ip_address, 
        country=threat.country,
        url=url,
        status_code=status_code, 
        user_agent=user_agent,
        time_delta_ms=time_delta_ms if not created else None
    )

    if threat.status == 'blocked':
        threat.save() # Обновляем last_seen для заблокированных, но не анализируем
        return

    # --- Анализ ---
    # Правило 0: Временной анализ
    if not created and time_delta < MIN_REQUEST_DELTA:
        score = 25
        threat.threat_score += score
        details = f"Time between requests: {time_delta_ms}ms"
        Anomaly.objects.create(threat_source=threat, reason='Robotic Activity', score_added=score, attacked_url=url, details=details, log_entry=log_line)

    # Правило 1: Анализ User-Agent
    if any(bad_ua in user_agent.lower() for bad_ua in BAD_USER_AGENTS):
        score = 35
        threat.threat_score += score
        Anomaly.objects.create(threat_source=threat, reason='Malicious User-Agent', score_added=score, attacked_url=url, details=user_agent, log_entry=log_line)

    # ... (остальные правила: Path Scanning, Brute-force, и т.д.)

    # Проверка на блокировку
    if threat.threat_score >= 100:
        threat.status = 'blocked'

    threat.save()
