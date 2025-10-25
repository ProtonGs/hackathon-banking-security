let apiDataCache = {}; // Cache for modal data
let chartInstances = {}; // To hold all chart objects

function initializeCharts() {
    const chartsToInit = {
        threat: { id: 'threat-over-time-chart', type: 'line', options: { responsive: true, plugins: { title: { display: true, text: 'Уровень угрозы во времени' } } } },
        anomaly: { id: 'anomaly-types-chart', type: 'doughnut', options: { responsive: true, plugins: { title: { display: true, text: 'Типы аномалий' } } } },
        country: { id: 'requests-by-country-chart', type: 'bar', options: { indexAxis: 'y', responsive: true, plugins: { title: { display: true, text: 'Топ-10 стран по запросам' } } } },
        speed: { id: 'avg-request-time-chart', type: 'bar', options: { responsive: true, plugins: { title: { display: true, text: 'Скорость (мс): Человек vs Бот' } } } }
    };
    for (const key in chartsToInit) {
        if (document.getElementById(chartsToInit[key].id)) {
            const ctx = document.getElementById(chartsToInit[key].id).getContext('2d');
            chartInstances[key] = new Chart(ctx, { type: chartsToInit[key].type, options: chartsToInit[key].options });
        }
    }
}

function updateDashboard() {
    fetch(DASHBOARD_DATA_URL)
        .then(response => response.json())
        .then(data => {
            apiDataCache = data; // Cache all data
            updateKpis(data.kpis);
            updateCharts(data.charts);
            updateLogFeed(data.live_logs);
        });
}

function updateKpis(kpis) {
    document.getElementById('kpi-total-requests').textContent = kpis.total_requests;
    document.getElementById('kpi-blocked-ips').textContent = kpis.blocked_ips_count;
    document.getElementById('kpi-top-url').textContent = kpis.top_attacked_urls.length ? kpis.top_attacked_urls[0].attacked_url : 'N/A';
    document.getElementById('kpi-top-country').textContent = kpis.top_countries.length ? kpis.top_countries[0].threat_source__country : 'N/A';
}

function updateCharts(charts) {
    // Threat over time
    if (chartInstances.threat) {
        chartInstances.threat.data.labels = charts.threat_over_time.map(d => new Date(d.minute).toLocaleTimeString());
        chartInstances.threat.data.datasets = [{ label: 'Суммарный уровень угрозы', data: charts.threat_over_time.map(d => d.total_score), borderColor: '#dc3545', fill: false, tension: 0.2 }];
        chartInstances.threat.update();
    }
    // Anomaly types
    if (chartInstances.anomaly) {
        chartInstances.anomaly.data.labels = charts.anomaly_types.map(d => d.reason);
        chartInstances.anomaly.data.datasets = [{ data: charts.anomaly_types.map(d => d.count), backgroundColor: ['#ff6384', '#36a2eb', '#ffce56', '#4bc0c0', '#9966ff', '#ff9f40'] }];
        chartInstances.anomaly.update();
    }
    // Requests by country
    if (chartInstances.country) {
        chartInstances.country.data.labels = charts.requests_by_country.map(d => d.country);
        chartInstances.country.data.datasets = [{ label: 'Всего запросов', data: charts.requests_by_country.map(d => d.count), backgroundColor: '#36a2eb' }];
        chartInstances.country.update();
    }
    // Avg request time
    if (chartInstances.speed) {
        chartInstances.speed.data.labels = ['Человек', 'Бот'];
        chartInstances.speed.data.datasets = [{ label: 'Среднее время (мс)', data: [charts.avg_request_time.human, charts.avg_request_time.bot], backgroundColor: ['#4bc0c0', '#ff6384'] }];
        chartInstances.speed.update();
    }
}

function updateLogFeed(logs) {
    const feed = document.getElementById('log-feed');
    feed.innerHTML = logs.map(log => `<p><span style="color:#888">${log.timestamp}</span> <span style="color:#ffce56">${log.country}</span> ${log.ip_address} <span style="color:#4bc0c0">${log.url}</span></p>`).join('');
}

// --- Modal Logic ---
const detailsModal = document.getElementById('details-modal');
document.querySelector('.details-close-btn').onclick = () => detailsModal.style.display = "none";
window.addEventListener('click', (event) => {
    if (event.target == detailsModal) { detailsModal.style.display = "none"; }
    if (event.target == aiModal) { aiModal.style.display = "none"; }
});

function openDetailsModal(title, content) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = content;
    detailsModal.style.display = "block";
}

document.getElementById('kpi-card-blocked').addEventListener('click', () => {
    const data = apiDataCache.modal_data.blocked_ips;
    let content = '<table><thead><tr><th>IP</th><th>Country</th><th>Score</th></tr></thead><tbody>';
    data.forEach(ip => { content += `<tr><td>${ip.ip_address}</td><td>${ip.country}</td><td>${ip.threat_score}</td></tr>`; });
    content += '</tbody></table>';
    openDetailsModal('Заблокированные IP-адреса', content);
});
// ... other kpi card click listeners ...

// --- AI Modal Logic ---
const aiModal = document.getElementById('ai-modal');
document.querySelector('.ai-close-btn').onclick = () => aiModal.style.display = "none";

function openAiModal(widgetElement, analysisType) {
    const widgetContainer = document.getElementById('ai-modal-widget-container');
    const analysisContainer = document.getElementById('ai-modal-analysis-container');
    
    widgetContainer.innerHTML = '';
    widgetContainer.appendChild(widgetElement);
    analysisContainer.innerHTML = '<p>Генерация анализа...</p>';
    aiModal.style.display = 'block';

    fetch(DEEP_ANALYSIS_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
        body: JSON.stringify({ analysis_type: analysisType, data: apiDataCache })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.error) {
            analysisContainer.innerHTML = `<p style="color: red;">Ошибка: ${data.error}</p>`;
        } else {
            analysisContainer.innerHTML = data.report ? `<div>${data.report.replace(/\n/g, '<br>')}</div>` : '<p>Не удалось получить анализ.</p>';
        }
    })
    .catch(e => {
        analysisContainer.innerHTML = `<p style="color: red;">Не удалось выполнить запрос: ${e.message}</p>`;
    });
}

document.querySelectorAll('.ai-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const widgetId = e.target.dataset.widgetId;
        const analysisType = e.target.dataset.analysisType;
        const widgetElement = document.getElementById(widgetId).cloneNode(true);
        widgetElement.querySelector('.ai-btn').remove();
        if(widgetElement.querySelector('canvas')) {
            const title = widgetElement.querySelector('h3') ? widgetElement.querySelector('h3').textContent : 'График';
            widgetElement.innerHTML = `<h3>${title}</h3><p>(Визуализация графика в модальном окне не поддерживается)</p>`;
        }
        openAiModal(widgetElement, analysisType);
    });
});

document.getElementById('generate-report-btn').addEventListener('click', () => {
    const widgetContainer = document.getElementById('ai-modal-widget-container');
    const analysisContainer = document.getElementById('ai-modal-analysis-container');
    
    document.getElementById('ai-modal-title').textContent = "Общий отчет по кибербезопасности";
    widgetContainer.innerHTML = '<h2>Общий отчет</h2><p>На основе всех данных дашборда.</p>';
    analysisContainer.innerHTML = '<p>Генерация отчета...</p>';
    aiModal.style.display = 'block';

    fetch(DEEP_ANALYSIS_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
        body: JSON.stringify({ analysis_type: 'general_report', data: apiDataCache })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.error) {
            analysisContainer.innerHTML = `<p style="color: red;">Ошибка: ${data.error}</p>`;
        } else {
            analysisContainer.innerHTML = data.report ? `<div>${data.report.replace(/\n/g, '<br>')}</div>` : '<p>Не удалось сгенерировать отчет.</p>';
        }
    })
    .catch(e => {
        analysisContainer.innerHTML = `<p style="color: red;">Не удалось выполнить запрос: ${e.message}</p>`;
    });
});

// --- Initial Load ---
document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    updateDashboard();
    setInterval(updateDashboard, 5000);
});
