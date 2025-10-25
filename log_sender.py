import requests
import time
import random

API_ENDPOINT = 'http://127.0.0.1:8000/api/logs/'

IPS = {
    # Scanners
    '81.200.150.1': {'country': 'RU', 'persona': 'scanner'},
    '203.0.113.55': {'country': 'CN', 'persona': 'scanner'},
    '198.51.100.12': {'country': 'US', 'persona': 'scanner'},
    '5.188.210.101': {'country': 'DE', 'persona': 'scanner'},
    '45.9.20.157': {'country': 'NL', 'persona': 'scanner'},

    # Brute-force
    '203.0.113.10': {'country': 'CN', 'persona': 'brute-force'},
    '185.220.101.43': {'country': 'UA', 'persona': 'brute-force'},
    '194.32.76.119': {'country': 'GB', 'persona': 'brute-force'},
    '103.195.4.21': {'country': 'IN', 'persona': 'brute-force'},
    '181.214.87.4': {'country': 'BR', 'persona': 'brute-force'},

    # Carders
    '185.143.223.5': {'country': 'NL', 'persona': 'carder'},
    '91.219.212.2': {'country': 'RU', 'persona': 'carder'},
    '198.49.23.141': {'country': 'US', 'persona': 'carder'},
    '179.107.18.1': {'country': 'BR', 'persona': 'carder'},
    '103.86.124.1': {'country': 'ID', 'persona': 'carder'},

    # Normal users
    '8.8.8.8': {'country': 'US', 'persona': 'normal'},
    '1.1.1.1': {'country': 'AU', 'persona': 'normal'},
    '91.108.23.10': {'country': 'GB', 'persona': 'normal'},
    '195.8.215.1': {'country': 'DE', 'persona': 'normal'},
    '200.10.10.1': {'country': 'MX', 'persona': 'normal'},
    '152.58.10.1': {'country': 'FR', 'persona': 'normal'},
    '139.130.4.5': {'country': 'JP', 'persona': 'normal'},
    '88.198.10.1': {'country': 'ES', 'persona': 'normal'},
    '62.116.10.1': {'country': 'IT', 'persona': 'normal'},
    '212.102.32.1': {'country': 'PL', 'persona': 'normal'},
}

USER_AGENTS = {
    'normal': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15'
    ],
    'scanner': [
        'sqlmap/1.6.6',
        'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)',
        'gobuster/3.4.0',
        'Nikto/2.1.6'
    ]
}
# Для кардеров и брутфорсеров будем использовать обычные User-Agent, чтобы они маскировались
USER_AGENTS['carder'] = USER_AGENTS['normal']
USER_AGENTS['brute-force'] = USER_AGENTS['normal']

PERSONA_ACTIONS = {
    'normal': [
        {'url': '/', 'status': 200, 'post_data': ''},
        {'url': '/account/38102', 'status': 200, 'post_data': ''},
        {'url': '/account/9912/history', 'status': 200, 'post_data': ''},
        {'url': '/api/auth/login', 'status': 200, 'post_data': 'user=john'}
    ],
    'scanner': [
        # Path Scanning
        {'url': '/.git/config', 'status': 404, 'post_data': ''},
        {'url': '/.env', 'status': 404, 'post_data': ''},
        {'url': '/api/v1/users', 'status': 403, 'post_data': ''},
        {'url': '/admin.php', 'status': 404, 'post_data': ''},
        # SQLi
        {'url': "/products?category=1' OR 1=1 --", 'status': 500, 'post_data': ''},
        # XSS
        {'url': "/search?q=<script>alert('XSS')</script>", 'status': 200, 'post_data': ''},
    ],
    'brute-force': [
        {'url': '/api/auth/login', 'status': 401, 'post_data': 'user=admin&pass=12345'},
        {'url': '/api/auth/login', 'status': 401, 'post_data': 'user=admin&pass=root'},
        {'url': '/api/auth/login', 'status': 401, 'post_data': 'user=admin&pass=password'},
        {'url': '/api/auth/login', 'status': 401, 'post_data': 'user=admin&pass=admin'},
    ],
    'carder': [
        # Valid Luhn
        {'url': '/api/payment/transfer', 'status': 200, 'post_data': '49927398716'},
        # Invalid Luhn
        {'url': '/api/payment/transfer', 'status': 400, 'post_data': '4111111111111112'},
        {'url': '/api/payment/transfer', 'status': 400, 'post_data': '5555444433332221'},
        # XSS in post
        {'url': '/api/payment/transfer', 'status': 400, 'post_data': '<script>alert(1)</script>'},
    ]
}

def generate_log_line():
    ip = random.choice(list(IPS.keys()))
    ip_info = IPS[ip]
    persona = ip_info['persona']
    action = random.choice(PERSONA_ACTIONS[persona])
    user_agent = random.choice(USER_AGENTS[persona])
    
    return {
        "ip": ip,
        "country": ip_info['country'],
        "url": action['url'],
        "status_code": action['status'],
        "post_data": action['post_data'],
        "user_agent": user_agent
    }

if __name__ == "__main__":
    print(f"Starting advanced log sender to {API_ENDPOINT}")
    while True:
        log_data = generate_log_line()
        try:
            print(f"Log: {log_data['country']}:{log_data['ip']} UA: {log_data['user_agent'][:20]}... -> {log_data['url']}")
            requests.post(API_ENDPOINT, json=log_data, timeout=2)
        except requests.RequestException as e:
            print(f"Could not send log: {e}")
        
        persona = IPS[log_data['ip']]['persona']
        sleep_time = 0.15 if persona != 'normal' else random.uniform(1, 3)
        time.sleep(sleep_time)