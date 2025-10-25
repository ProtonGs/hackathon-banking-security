from .models import ThreatSource, Anomaly, LogEntry
import json
import re
from django.utils import timezone
from datetime import timedelta

# --- Professional Configuration ---
MIN_REQUEST_DELTA_MS = 150  # Min time between requests in ms to be considered non-robotic
SCORE_DECAY_HOURS = 24      # Hours after which an inactive IP's score starts to decay
SCORE_DECAY_AMOUNT = 20     # Amount to decay the score by

# More sophisticated detection patterns
BAD_USER_AGENTS = ['sqlmap', 'nmap', 'gobuster', 'nikto', 'wfuzz', 'acunetix', 'netsparker']

PATH_SEVERITY_MAP = {
    # High Severity (Critical system files/configs)
    re.compile(r'^/\.git/'): 50,
    re.compile(r'^/\.env'): 50,
    re.compile(r'/etc/passwd'): 50,
    re.compile(r'\.ini$'): 40,  # Added '$' to match the end of the string

    # Medium Severity (Common admin/login paths)
    re.compile(r'/admin|/admin\.php|/wp-admin'): 30, # Corrected string formatting and path separators
    re.compile(r'/login|/auth'): 25, # Corrected string formatting and path separators

    # Low Severity (Common scanning noise)
    re.compile(r'\.php$'): 20,  # Added '$' to match the end of the string
}

# Regex for SQLi and XSS
SQLI_PATTERNS = re.compile(r"('|%27)|(\s*--(?:\s|$))|(\s*(?:OR|AND)\s+\d+=\d+)|(UNION\s+SELECT)", re.IGNORECASE)
XSS_PATTERNS = re.compile(r"<script>|<img src=x onerror=|onload=|", re.IGNORECASE)

def luhn_checksum(card_number):
    def digits_of(n):
        return [int(d) for d in str(n)]
    try:
        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))
        return checksum % 10 == 0
    except (ValueError, TypeError):
        return False

def analyze_log_entry(log_data):
    ip_address = log_data.get('ip')
    if not ip_address:
        return

    threat, created = ThreatSource.objects.get_or_create(
        ip_address=ip_address,
        defaults={'country': log_data.get('country', 'Unknown')}
    )

    # --- Score Decay Logic ---
    if not created and (timezone.now() - threat.last_seen) > timedelta(hours=SCORE_DECAY_HOURS):
        threat.threat_score = max(0, threat.threat_score - SCORE_DECAY_AMOUNT)

    # --- Time Delta Calculation ---
    now = timezone.now()
    time_delta = now - threat.last_seen
    time_delta_ms = int(time_delta.total_seconds() * 1000)

    url = log_data.get('url', '')
    status_code = int(log_data.get('status_code', 200))
    user_agent = log_data.get('user_agent', '')
    post_data = log_data.get('post_data', '')
    log_line = json.dumps(log_data)

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
        threat.save() # Update last_seen
        return

    # --- Professional Analysis Rules ---
    # Rule 1: Robotic Activity (very fast requests)
    if not created and time_delta_ms < MIN_REQUEST_DELTA_MS:
        score = 25
        threat.threat_score += score
        Anomaly.objects.create(threat_source=threat, reason='Robotic Activity', score_added=score, attacked_url=url, details=f"Time between requests: {time_delta_ms}ms", log_entry=log_line)

    # Rule 2: Malicious User-Agent
    if any(bad_ua in user_agent.lower() for bad_ua in BAD_USER_AGENTS):
        score = 40 # Increased score
        threat.threat_score += score
        Anomaly.objects.create(threat_source=threat, reason='Malicious Scanner UA', score_added=score, attacked_url=url, details=user_agent, log_entry=log_line)

    # Rule 3: Path Scanning with Severity
    for pattern, score in PATH_SEVERITY_MAP.items():
        if pattern.search(url):
            threat.threat_score += score
            Anomaly.objects.create(threat_source=threat, reason='Path Scanning', score_added=score, attacked_url=url, details=f"Matched pattern: {pattern.pattern}", log_entry=log_line)
            break # Stop after first match

    # Rule 4: SQL Injection Attempts (in URL or POST data)
    if SQLI_PATTERNS.search(url) or SQLI_PATTERNS.search(post_data):
        score = 80 # High severity
        threat.threat_score += score
        Anomaly.objects.create(threat_source=threat, reason='SQL Injection Attempt', score_added=score, attacked_url=url, details=f"Payload: {url if SQLI_PATTERNS.search(url) else post_data}", log_entry=log_line)

    # Rule 5: XSS Attempts (in URL or POST data)
    if XSS_PATTERNS.search(url) or XSS_PATTERNS.search(post_data):
        score = 60 # High severity
        threat.threat_score += score
        Anomaly.objects.create(threat_source=threat, reason='XSS Attempt', score_added=score, attacked_url=url, details=f"Payload: {url if XSS_PATTERNS.search(url) else post_data}", log_entry=log_line)

    # Rule 6: Brute-force on login
    if 'login' in url and status_code == 401:
        score = 15
        threat.threat_score += score
        Anomaly.objects.create(threat_source=threat, reason='Login Brute-force', score_added=score, attacked_url=url, details="Failed login attempt", log_entry=log_line)

    # Rule 7: Invalid Card Number (Luhn check)
    if 'payment' in url and post_data and not luhn_checksum(post_data):
        score = 30
        threat.threat_score += score
        Anomaly.objects.create(threat_source=threat, reason='Invalid Card Number', score_added=score, attacked_url=url, details=f"Failed Luhn check for: {post_data}", log_entry=log_line)

    # --- Finalization ---
    if threat.threat_score >= 100:
        threat.status = 'blocked'

    threat.save()
