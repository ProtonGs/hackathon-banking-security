let apiDataCache = {};
let chartInstances = {};
let aiReportCache = {};
let modalChartInstance;
let currentAnalysisInfo = {};

function loadInitialAiAnalyses() {
    try {
        const analysisDataElement = document.getElementById('ai-analyses-json');
        if (analysisDataElement) {
            const analyses = JSON.parse(analysisDataElement.textContent);
            aiReportCache = analyses;
            // Pre-fill insights on the dashboard
            for (const [key, value] of Object.entries(analyses)) {
                const insightElement = document.querySelector(`[data-analysis-type='${key}']`);
                if (insightElement && value) {
                    const parentCard = insightElement.closest('.kpi-card, .chart-container');
                    if (parentCard) {
                        // Ensure the button is marked as having a report
                        insightElement.classList.add('has-report');
                    }
                }
            }
        }
    } catch (e) {
        console.error("Error loading initial AI analyses:", e);
    }
}

function initializeCharts() {
    const chartsToInit = {
        threat: { id: 'threat-over-time-chart', type: 'line', options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Уровень угрозы во времени' } } } },
        anomaly: { id: 'anomaly-types-chart', type: 'doughnut', options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Типы аномалий' } } } },
        country: { id: 'requests-by-country-chart', type: 'bar', options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Топ-10 стран по запросам' } } } },
        speed: { id: 'avg-request-time-chart', type: 'bar', options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Скорость (мс): Человек vs Бот' } } } }
    };
    for (const key in chartsToInit) {
        if (document.getElementById(chartsToInit[key].id)) {
            const ctx = document.getElementById(chartsToInit[key].id).getContext('2d');
            chartInstances[key] = new Chart(ctx, { type: chartsToInit[key].type, data: {}, options: chartsToInit[key].options });
        }
    }
}

function updateDashboard() {
    fetch(DASHBOARD_DATA_URL)
        .then(response => response.json())
        .then(data => {
            apiDataCache = data;
            updateKpis(data.kpis);
            updateCharts(data.charts);
            updateLogFeed(data.live_logs);
        }).catch(e => console.error("Error updating dashboard:", e));
}

function updateKpis(kpis) {
    document.getElementById('kpi-total-requests').textContent = kpis.total_requests;
    document.getElementById('kpi-blocked-ips').textContent = kpis.blocked_ips_count;
    document.getElementById('kpi-top-url').textContent = kpis.top_attacked_urls.length ? kpis.top_attacked_urls[0].attacked_url : 'N/A';
    document.getElementById('kpi-top-country').textContent = kpis.top_countries.length ? kpis.top_countries[0].threat_source__country : 'N/A';
}

function updateCharts(charts) {
    if (!chartInstances.threat) return;
    chartInstances.threat.config.data = { labels: charts.threat_over_time.map(d => new Date(d.minute).toLocaleTimeString()), datasets: [{ label: 'Суммарный уровень угрозы', data: charts.threat_over_time.map(d => d.total_score), borderColor: '#dc3545', fill: false, tension: 0.2 }] };
    chartInstances.threat.update();

    chartInstances.anomaly.config.data = { labels: charts.anomaly_types.map(d => d.reason), datasets: [{ data: charts.anomaly_types.map(d => d.count), backgroundColor: ['#ff6384', '#36a2eb', '#ffce56', '#4bc0c0', '#9966ff', '#ff9f40'] }] };
    chartInstances.anomaly.update();

    chartInstances.country.config.data = { labels: charts.requests_by_country.map(d => d.country), datasets: [{ label: 'Всего запросов', data: charts.requests_by_country.map(d => d.count), backgroundColor: '#36a2eb' }] };
    chartInstances.country.update();

    chartInstances.speed.config.data = { labels: ['Человек', 'Бот'], datasets: [{ label: 'Среднее время (мс)', data: [charts.avg_request_time.human, charts.avg_request_time.bot], backgroundColor: ['#4bc0c0', '#ff6384'] }] };
    chartInstances.speed.update();
}

function updateLogFeed(logs) {
    const feed = document.getElementById('log-feed');
    feed.innerHTML = logs.map(log => `<p><span style="color:#888">${log.timestamp}</span> <span style="color:#ffce56">${log.country}</span> ${log.ip_address} <span style="color:#4bc0c0">${log.url}</span></p>`).join('');
}

function setupModals() {
    const detailsModal = document.getElementById('details-modal');
    const aiModal = document.getElementById('ai-modal');
    document.querySelector('.details-close-btn').onclick = () => detailsModal.style.display = "none";
    document.querySelector('.ai-close-btn').onclick = () => aiModal.style.display = "none";
    window.addEventListener('click', (event) => {
        if (event.target == detailsModal) detailsModal.style.display = "none";
        if (event.target == aiModal) aiModal.style.display = "none";
    });
}

function openDetailsModal(title, content) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = content;
    document.getElementById('details-modal').style.display = "block";
}

function fetchAndRenderAiAnalysis(analysisType, forceRegenerate = false) {
    const analysisContentEl = document.getElementById('ai-analysis-content');
    
    if (!forceRegenerate && aiReportCache[analysisType]) {
        analysisContentEl.innerHTML = marked.parse(aiReportCache[analysisType]);
        return Promise.resolve();
    }

    analysisContentEl.innerHTML = '<p>Генерация анализа...</p>';

    let payload = { analysis_type: analysisType, data: {} };
    if (analysisType === 'final_summary') {
        payload.data = { cached_reports: aiReportCache };
    } else {
        payload.data = apiDataCache;
    }

    return fetch(DEEP_ANALYSIS_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
        body: JSON.stringify(payload)
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) { throw new Error(data.error); }
        aiReportCache[analysisType] = data.report;
        if (document.getElementById('ai-modal').style.display === 'block' && currentAnalysisInfo.analysisType === analysisType) {
            analysisContentEl.innerHTML = marked.parse(data.report);
        }
    })
    .catch(e => {
        if (document.getElementById('ai-modal').style.display === 'block' && currentAnalysisInfo.analysisType === analysisType) {
            analysisContentEl.innerHTML = `<div class="error-message"><strong>Ошибка анализа:</strong><br>${e.message}</div>`;
        }
        throw e; // Re-throw for Promise.all to catch it
    });
}

function openAiModal(widgetId, chartId, analysisType) {
    currentAnalysisInfo = { widgetId, chartId, analysisType };
    const aiModal = document.getElementById('ai-modal');
    const listContainer = document.getElementById('ai-modal-list-container');
    const modalChartCanvas = document.getElementById('ai-modal-chart');
    
    // Clear previous dynamic content and hide containers
    listContainer.innerHTML = '';
    listContainer.style.display = 'none';
    modalChartCanvas.style.display = 'none';

    if (modalChartInstance) {
        modalChartInstance.destroy();
        modalChartInstance = null;
    }

    const listWidgets = {
        'kpi_blocked': {
            title: 'Заблокированные IP-адреса',
            data: apiDataCache.modal_data?.blocked_ips,
            formatter: (item) => `<li>${item.ip_address} (${item.country || 'N/A'}) - Score: ${item.threat_score}</li>`
        },
        'kpi_urls': {
            title: 'Топ атакуемых URL',
            data: apiDataCache.kpis?.top_attacked_urls,
            formatter: (item) => `<li>${item.attacked_url} (${item.count} times)</li>`
        },
        'kpi_countries': {
            title: 'Топ атакующих стран',
            data: apiDataCache.kpis?.top_countries,
            formatter: (item) => `<li>${item.threat_source__country} (${item.count} times)</li>`
        }
    };

    if (analysisType in listWidgets) {
        const config = listWidgets[analysisType];
        document.getElementById('ai-modal-title').textContent = `Анализ: ${config.title}`;
        listContainer.style.display = 'block';
        
        let content = `<h3>${config.title} (до 10)</h3>`;
        if (config.data && config.data.length > 0) {
            content += '<ul>';
            config.data.slice(0, 10).forEach(item => {
                content += config.formatter(item);
            });
            content += '</ul>';
        } else {
            content += '<p>Нет данных для отображения.</p>';
        }
        listContainer.innerHTML = content;

    } else if (analysisType === 'final_summary') {
        document.getElementById('ai-modal-title').textContent = "Общий отчет по кибербезопасности";
        listContainer.style.display = 'block';
        listContainer.innerHTML = '<h2>Общий отчет</h2><p>На основе всех сгенерированных анализов.</p>';
    } else if (chartId && chartInstances[chartId]) {
        document.getElementById('ai-modal-title').textContent = "Анализ графика";
        modalChartCanvas.style.display = 'block';
        const originalChart = chartInstances[chartId];
        modalChartInstance = new Chart(modalChartCanvas.getContext('2d'), originalChart.config);
    } else {
        document.getElementById('ai-modal-title').textContent = "Анализ виджета";
        listContainer.style.display = 'block';
        const widgetElement = document.getElementById(widgetId).cloneNode(true);
        widgetElement.querySelector('.ai-btn').remove();
        listContainer.appendChild(widgetElement);
    }

    aiModal.style.display = 'block';
    fetchAndRenderAiAnalysis(analysisType, false);
}

function setupEventListeners() {
    document.getElementById('kpi-card-blocked').addEventListener('click', () => {
        const data = apiDataCache.modal_data.blocked_ips;
        let content = '<table><thead><tr><th>IP</th><th>Country</th><th>Score</th></tr></thead><tbody>';
        data.forEach(ip => { content += `<tr><td>${ip.ip_address}</td><td>${ip.country}</td><td>${ip.threat_score}</td></tr>`; });
        content += '</tbody></table>';
        openDetailsModal('Заблокированные IP-адреса', content);
    });

    document.querySelectorAll('.ai-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const widgetId = e.target.dataset.widgetId;
            const chartId = e.target.dataset.chartId;
            const analysisType = e.target.dataset.analysisType;
            openAiModal(widgetId, chartId, analysisType);
        });
    });

    document.getElementById('regenerate-ai-btn').addEventListener('click', () => {
        if (currentAnalysisInfo.analysisType) {
            fetchAndRenderAiAnalysis(currentAnalysisInfo.analysisType, true);
        }
    });
    
    document.getElementById('generate-all-btn').addEventListener('click', (e) => {
        const btn = e.target;
        const originalText = btn.textContent;
        btn.textContent = 'Генерация... (0%)';
        btn.disabled = true;

        const analysisTypes = [...new Set(Array.from(document.querySelectorAll('.ai-btn')).map(b => b.dataset.analysisType))];
        let completed = 0;

        const promises = analysisTypes.map(type => 
            fetchAndRenderAiAnalysis(type, true).then(() => {
                completed++;
                btn.textContent = `Генерация... (${Math.round((completed / analysisTypes.length) * 100)}%)`;
            })
        );

        Promise.all(promises).then(() => {
            btn.textContent = 'Все анализы сгенерированы';
            setTimeout(() => { btn.textContent = originalText; btn.disabled = false; }, 2000);
        }).catch(err => {
            console.error("Error generating all analyses:", err);
            btn.textContent = 'Ошибка!';
            setTimeout(() => { btn.textContent = originalText; btn.disabled = false; }, 3000);
        });
    });

    document.getElementById('generate-report-btn').addEventListener('click', () => {
        if (Object.keys(aiReportCache).length === 0) {
            alert("Сначала сгенерируйте хотя бы один анализ виджета с помощью кнопки 'Сгенерировать все анализы'.");
            return;
        }
        openAiModal(null, null, 'final_summary');
    });
}

// --- Initial Load ---
document.addEventListener('DOMContentLoaded', () => {
    loadInitialAiAnalyses();
    initializeCharts();
    setupModals();
    setupEventListeners();
    updateDashboard();
    setInterval(updateDashboard, 5000);
});
