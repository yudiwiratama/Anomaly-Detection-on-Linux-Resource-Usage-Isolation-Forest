// Dashboard JavaScript untuk Conntrack
const API_BASE = '';

let charts = {};
let allConnections = [];
let filteredConnections = [];
let displayedConnections = [];
let autoRefreshInterval = null;
let currentSort = { column: null, direction: 'asc' };
let currentLimit = 1000; // Default lebih besar untuk better UX, tapi tetap manageable
let timeseriesDatasets = []; // Store datasets for toggle functionality
let isLoading = false; // Prevent multiple simultaneous requests
let loadingTimeout = null; // For loading indicator timeout

// Define loadAnomalies early so it's available for onclick handlers
window.loadAnomalies = async function loadAnomalies() {
    console.log('🚀 loadAnomalies() called');
    const tbody = document.getElementById('anomaliesTableBody');
    if (!tbody) {
        console.error('✗ anomaliesTableBody not found');
        alert('Error: anomaliesTableBody element not found. Please refresh the page.');
        return;
    }
    
    console.log('✓ anomaliesTableBody found');
    
    try {
        console.log('Showing loading indicator...');
        if (typeof showLoading === 'function') {
            showLoading(true);
        }
        tbody.innerHTML = '<tr><td colspan="10" class="loading">Detecting anomalies...</td></tr>';
        console.log('Loading message set');
        
        const limitSelect = document.getElementById('anomalyLimitSelect');
        const minScoreInput = document.getElementById('minScoreInput');
        const contaminationInput = document.getElementById('contaminationInput');
        const nEstimatorsInput = document.getElementById('nEstimatorsInput');
        
        const limit = limitSelect && limitSelect.value !== 'all' ? parseInt(limitSelect.value) : null;
        const minScore = minScoreInput && minScoreInput.value ? parseFloat(minScoreInput.value) : null;
        const contamination = contaminationInput && contaminationInput.value ? parseFloat(contaminationInput.value) : null;
        const nEstimators = nEstimatorsInput && nEstimatorsInput.value ? parseInt(nEstimatorsInput.value) : null;
        
        const params = new URLSearchParams();
        if (limit) params.append('limit', limit);
        if (minScore !== null && !isNaN(minScore)) params.append('min_score', minScore);
        if (contamination !== null && !isNaN(contamination) && contamination >= 0.01 && contamination <= 0.5) {
            params.append('contamination', contamination);
        }
        if (nEstimators !== null && !isNaN(nEstimators) && nEstimators >= 10 && nEstimators <= 500) {
            params.append('n_estimators', nEstimators);
        }
        
        const url = `${API_BASE}/api/anomalies${params.toString() ? '?' + params.toString() : ''}`;
        console.log('Fetching anomalies from:', url);
        
        const response = await fetch(url);
        console.log('Response status:', response.status);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        console.log('Anomaly detection result:', result);
        
        if (result.success) {
            if (result.data && result.data.length > 0) {
                if (typeof displayAnomalies === 'function') {
                    displayAnomalies(result.data, result);
                } else {
                    console.error('displayAnomalies function not found');
                    tbody.innerHTML = '<tr><td colspan="10" class="loading">Error: displayAnomalies function not found</td></tr>';
                }
            } else {
                const message = result.message || 'Tidak ada anomaly yang terdeteksi';
                tbody.innerHTML = `<tr><td colspan="10" class="loading">${message}</td></tr>`;
                // Hide stats if no anomalies
                const statsDiv = document.getElementById('anomalyStats');
                if (statsDiv) statsDiv.style.display = 'none';
            }
        } else {
            const errorMsg = result.error || result.message || 'Unknown error';
            console.error('Anomaly detection error:', errorMsg);
            tbody.innerHTML = `<tr><td colspan="10" class="loading" style="color: #ea4335;">Error: ${errorMsg}</td></tr>`;
        }
    } catch (error) {
        console.error('Error loading anomalies:', error);
        const errorMsg = error.message || 'Failed to load anomalies';
        tbody.innerHTML = `<tr><td colspan="10" class="loading" style="color: #ea4335;">Error: ${errorMsg}. Pastikan backend berjalan di ${API_BASE || 'http://localhost:8000'}</td></tr>`;
    } finally {
        if (typeof showLoading === 'function') {
            showLoading(false);
        }
    }
};

// Inisialisasi dashboard
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM Content Loaded, initializing dashboard...');
    initializeCharts();
    loadData();
    setupEventListeners();
    setupLegendControls();
    startAutoRefresh();
    
    // Pause auto-refresh saat tab tidak visible
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            stopAutoRefresh();
        } else {
            const autoRefreshCheckbox = document.getElementById('autoRefresh');
            if (autoRefreshCheckbox && autoRefreshCheckbox.checked) {
                startAutoRefresh();
            }
        }
    });
    
    // Debug: Check if anomaly detection elements exist
    console.log('Checking anomaly detection elements:');
    console.log('detectAnomaliesBtn:', document.getElementById('detectAnomaliesBtn'));
    console.log('anomaliesSection:', document.getElementById('anomaliesSection'));
    console.log('anomaliesTableBody:', document.getElementById('anomaliesTableBody'));
});

function setupEventListeners() {
    document.getElementById('refreshBtn').addEventListener('click', loadData);
    document.getElementById('autoRefresh').addEventListener('change', (e) => {
        if (e.target.checked) {
            startAutoRefresh();
        } else {
            stopAutoRefresh();
        }
    });
    
    document.getElementById('searchInput').addEventListener('input', applyFilters);
    document.getElementById('filterProtocol').addEventListener('change', applyFilters);
    document.getElementById('filterState').addEventListener('change', applyFilters);
    // Setup limit selector
    const limitSelect = document.getElementById('limitSelect');
    if (limitSelect) {
        // Initialize limit from select value
        const initialValue = limitSelect.value;
        currentLimit = initialValue === 'all' ? Infinity : parseInt(initialValue);
        
        // Add event listener
        limitSelect.addEventListener('change', (e) => {
            const value = e.target.value;
            currentLimit = value === 'all' ? Infinity : parseInt(value);
            applyFilters();
        });
    }
    
    // Setup sorting untuk setiap kolom
    document.querySelectorAll('.sortable').forEach(th => {
        th.addEventListener('click', () => {
            const column = th.getAttribute('data-sort');
            sortTable(column);
        });
    });
    
    // Setup time series controls
    document.getElementById('loadTimeseriesBtn').addEventListener('click', loadTimeSeries);
    document.getElementById('timeseriesMetricType').addEventListener('change', updateTimeseriesMetricKeys);
    
    // Setup anomaly detection
    const detectBtn = document.getElementById('detectAnomaliesBtn');
    if (detectBtn) {
        detectBtn.addEventListener('click', () => {
            if (typeof window.loadAnomalies === 'function') {
                window.loadAnomalies();
            }
        });
    }
    const anomalyLimitSelect = document.getElementById('anomalyLimitSelect');
    if (anomalyLimitSelect) {
        anomalyLimitSelect.addEventListener('change', () => {
            if (document.getElementById('anomaliesSection').style.display !== 'none') {
                if (typeof window.loadAnomalies === 'function') {
                    window.loadAnomalies();
                }
            }
        });
    }
    const minScoreInput = document.getElementById('minScoreInput');
    if (minScoreInput) {
        minScoreInput.addEventListener('change', () => {
            const anomaliesSection = document.getElementById('anomaliesSection');
            if (anomaliesSection && anomaliesSection.classList.contains('active')) {
                if (typeof window.loadAnomalies === 'function') {
                    window.loadAnomalies();
                }
            }
        });
    }
    
    // Setup advanced parameters toggle
    const toggleParamsBtn = document.getElementById('toggleParamsBtn');
    const paramsPanel = document.getElementById('anomalyParamsPanel');
    const toggleParamsText = document.getElementById('toggleParamsText');
    if (toggleParamsBtn && paramsPanel) {
        toggleParamsBtn.addEventListener('click', () => {
            const isVisible = paramsPanel.style.display !== 'none';
            paramsPanel.style.display = isVisible ? 'none' : 'block';
            if (toggleParamsText) {
                toggleParamsText.textContent = isVisible ? '⚙️ Advanced Parameters' : '▼ Advanced Parameters';
            }
        });
    }
    
    // Setup reset parameters button
    const resetParamsBtn = document.getElementById('resetParamsBtn');
    if (resetParamsBtn) {
        resetParamsBtn.addEventListener('click', () => {
            const contaminationInput = document.getElementById('contaminationInput');
            const nEstimatorsInput = document.getElementById('nEstimatorsInput');
            if (contaminationInput) contaminationInput.value = '0.1';
            if (nEstimatorsInput) nEstimatorsInput.value = '100';
        });
    }
    
    // Setup grouping tabs
    document.querySelectorAll('.grouping-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all tabs
            document.querySelectorAll('.grouping-tab').forEach(t => t.classList.remove('active'));
            // Add active class to clicked tab
            tab.classList.add('active');
            // Load grouping data
            loadGroupingData(tab.getAttribute('data-group'));
        });
    });
    
    // Load initial grouping data
    loadGroupingData('by_protocol');
    
    // Setup main navigation tabs
    document.querySelectorAll('.main-nav-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const section = tab.getAttribute('data-section');
            switchSection(section);
        });
    });
    
    // Setup grouping search and limit
    document.getElementById('groupingSearchInput').addEventListener('input', applyGroupingFilters);
    document.getElementById('groupingLimitSelect').addEventListener('change', applyGroupingFilters);
}

function switchSection(sectionName) {
    // Hide all sections
    document.querySelectorAll('.main-section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Remove active class from all tabs
    document.querySelectorAll('.main-nav-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Show selected section
    const targetSection = document.getElementById(`${sectionName}Section`);
    if (targetSection) {
        targetSection.classList.add('active');
    }
    
    // Add active class to clicked tab
    document.querySelector(`.main-nav-tab[data-section="${sectionName}"]`).classList.add('active');
    
    // If switching to timeseries, update metric keys
    if (sectionName === 'timeseries') {
        updateTimeseriesMetricKeys();
    } else if (sectionName === 'anomalies') {
        // Auto-load anomalies saat section dibuka
        loadAnomalies();
    }
}

function startAutoRefresh() {
    if (autoRefreshInterval) clearInterval(autoRefreshInterval);
    // Increase interval untuk large datasets (10 detik instead of 5)
    const interval = allConnections.length > 10000 ? 10000 : 5000;
    autoRefreshInterval = setInterval(() => {
        // Only refresh if not currently loading and page is visible
        if (!isLoading && !document.hidden) {
            loadData();
        }
    }, interval);
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

function showLoading(show = true) {
    isLoading = show;
    const loadingIndicator = document.getElementById('loadingIndicator');
    if (loadingIndicator) {
        loadingIndicator.style.display = show ? 'block' : 'none';
    }
    
    // Set timeout untuk hide loading jika terlalu lama (10 detik)
    if (show) {
        if (loadingTimeout) clearTimeout(loadingTimeout);
        loadingTimeout = setTimeout(() => {
            showLoading(false);
            console.warn('Loading timeout - request taking too long');
        }, 10000);
    } else {
        if (loadingTimeout) {
            clearTimeout(loadingTimeout);
            loadingTimeout = null;
        }
    }
}

async function loadData() {
    // Prevent multiple simultaneous requests
    if (isLoading) {
        console.log('Already loading, skipping...');
        return;
    }
    
    try {
        showLoading(true);
        const response = await fetch(`${API_BASE}/api/summary`);
        const result = await response.json();
        
        let summaryData = null;
        if (result.success) {
            summaryData = result.data;
            updateDashboard(summaryData);
        } else {
            // Handle error dari API
            const errorMsg = result.data?.error || 'Tidak ada data yang ditemukan';
            showError(errorMsg);
            summaryData = result.data || { total_connections: 0 };
            updateDashboard(summaryData);
        }
        
        // Load detailed connections dengan limit agresif untuk large datasets
        const totalConnections = summaryData ? (summaryData.total_connections || 0) : 0;
        const shouldLimit = totalConnections > 5000;
        // Limit lebih agresif: max 5000 untuk datasets besar
        const maxConnections = shouldLimit ? 5000 : 10000;
        const limitParam = shouldLimit ? `?limit=${maxConnections}` : '';
        
        const connResponse = await fetch(`${API_BASE}/api/connections${limitParam}`);
        const connResult = await connResponse.json();
        
        if (connResult.success) {
            allConnections = connResult.data || [];
            // Reset filters dan apply limit
            filteredConnections = allConnections;
            displayedConnections = [];
            // Pastikan limit di-initialize dari select
            const limitSelect = document.getElementById('limitSelect');
            if (limitSelect) {
                const limitValue = limitSelect.value;
                currentLimit = limitValue === 'all' ? Infinity : parseInt(limitValue);
                // Force limit untuk large datasets - lebih agresif
                if (shouldLimit) {
                    if (currentLimit > maxConnections) {
                        currentLimit = maxConnections;
                        limitSelect.value = maxConnections.toString();
                    }
                    // Set default ke 1000 untuk large datasets
                    if (limitValue === 'all' || currentLimit === Infinity) {
                        currentLimit = 1000;
                        limitSelect.value = '1000';
                    }
                }
            }
            // Use requestIdleCallback untuk non-critical updates dengan delay lebih lama
            if ('requestIdleCallback' in window) {
                requestIdleCallback(() => {
                    applyFilters();
                    updateFilters();
                    updateBytesStats();
                }, { timeout: 2000 });
            } else {
                setTimeout(() => {
                    applyFilters();
                    updateFilters();
                    updateBytesStats();
                }, 500);
            }
        } else {
            // Handle error dari connections API
            const errorMsg = connResult.error || connResult.message || 'Tidak ada koneksi yang ditemukan';
            if (connResult.error) {
                showError(errorMsg);
            }
            allConnections = [];
            filteredConnections = [];
            displayedConnections = [];
            updateConnectionsTable();
        }
        
        updateLastUpdate();
    } catch (error) {
        console.error('Error loading data:', error);
        showError(`Gagal memuat data: ${error.message}. Pastikan backend berjalan di http://localhost:8000`);
    } finally {
        showLoading(false);
    }
}

function updateDashboard(summary) {
    if (!summary) {
        summary = { total_connections: 0, by_protocol: {}, by_state: {} };
    }
    
    // Update stats
    document.getElementById('totalConnections').textContent = (summary.total_connections || 0).toLocaleString();
    document.getElementById('activeProtocols').textContent = Object.keys(summary.by_protocol || {}).length;
    document.getElementById('uniqueStates').textContent = Object.keys(summary.by_state || {}).length;
    document.getElementById('updateTime').textContent = summary.timestamp ? 
        (() => {
            const date = new Date(summary.timestamp);
            const wibDate = new Date(date.getTime() + (7 * 60 * 60 * 1000));
            return wibDate.toLocaleTimeString('id-ID', { 
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        })() : '-';
    
    // Bytes will be updated by updateBytesStats() after connections are loaded
    
    // Update charts (hanya jika ada data)
    if (summary.by_protocol && Object.keys(summary.by_protocol).length > 0) {
        updateProtocolChart(summary.by_protocol);
    }
    if (summary.by_state && Object.keys(summary.by_state).length > 0) {
        updateStateChart(summary.by_state);
    }
    if (summary.top_source_ips && summary.top_source_ips.length > 0) {
        updateSourceIpChart(summary.top_source_ips);
    }
    if (summary.top_destination_ips && summary.top_destination_ips.length > 0) {
        updateDestIpChart(summary.top_destination_ips);
    }
    if (summary.top_destination_ports && summary.top_destination_ports.length > 0) {
        updateDestPortChart(summary.top_destination_ports);
    }
    if (summary.protocol_state_matrix && Object.keys(summary.protocol_state_matrix).length > 0) {
        updateProtocolStateChart(summary.protocol_state_matrix);
    }
}

function initializeCharts() {
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: {
                position: 'bottom',
            }
        }
    };
    
    // Protocol Chart
    charts.protocol = new Chart(document.getElementById('protocolChart'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
        options: chartOptions
    });
    
    // State Chart
    charts.state = new Chart(document.getElementById('stateChart'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Jumlah', data: [], backgroundColor: '#667eea' }] },
        options: { ...chartOptions, indexAxis: 'y' }
    });
    
    // Source IP Chart
    charts.sourceIp = new Chart(document.getElementById('sourceIpChart'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Koneksi', data: [], backgroundColor: '#764ba2' }] },
        options: chartOptions
    });
    
    // Destination IP Chart
    charts.destIp = new Chart(document.getElementById('destIpChart'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Koneksi', data: [], backgroundColor: '#f093fb' }] },
        options: chartOptions
    });
    
    // Destination Port Chart
    charts.destPort = new Chart(document.getElementById('destPortChart'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Koneksi', data: [], backgroundColor: '#4facfe' }] },
        options: chartOptions
    });
    
    // Protocol-State Matrix Chart
    charts.protocolState = new Chart(document.getElementById('protocolStateChart'), {
        type: 'bar',
        data: { labels: [], datasets: [] },
        options: { ...chartOptions, scales: { x: { stacked: true }, y: { stacked: true } } }
    });
    
    // Time Series Chart
    const timeseriesCanvas = document.getElementById('timeseriesChart');
    if (timeseriesCanvas) {
        charts.timeseries = new Chart(timeseriesCanvas, {
            type: 'line',
            data: {
                labels: [],
                datasets: []
            },
            options: {
                ...chartOptions,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Count'
                        }
                    }
                },
                interaction: {
                    intersect: false,
                    mode: 'index'
                },
                plugins: {
                    ...chartOptions.plugins,
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                }
            }
        });
    }
    
}

function updateProtocolChart(data) {
    const labels = Object.keys(data);
    const values = Object.values(data);
    const colors = generateColors(labels.length);
    
    // Use requestAnimationFrame untuk smooth updates
    requestAnimationFrame(() => {
        if (charts.protocol) {
            charts.protocol.data.labels = labels;
            charts.protocol.data.datasets[0].data = values;
            charts.protocol.data.datasets[0].backgroundColor = colors;
            charts.protocol.update('none'); // 'none' mode untuk no animation (faster)
        }
    });
}

function updateStateChart(data) {
    const labels = Object.keys(data);
    const values = Object.values(data);
    
    // Limit untuk large datasets (max 30 states untuk performance)
    const maxItems = 30;
    if (labels.length > maxItems) {
        // Sort by value dan ambil top N
        const sorted = labels.map((label, idx) => ({ label, value: values[idx] }))
            .sort((a, b) => b.value - a.value)
            .slice(0, maxItems);
        const limitedLabels = sorted.map(item => item.label);
        const limitedValues = sorted.map(item => item.value);
        
        requestAnimationFrame(() => {
            if (charts.state) {
                charts.state.data.labels = limitedLabels;
                charts.state.data.datasets[0].data = limitedValues;
                charts.state.update('none');
            }
        });
    } else {
        requestAnimationFrame(() => {
            if (charts.state) {
                charts.state.data.labels = labels;
                charts.state.data.datasets[0].data = values;
                charts.state.update('none');
            }
        });
    }
}

function updateSourceIpChart(data) {
    // Limit to max 20 items untuk performance
    const limitedData = data.slice(0, 20);
    const labels = limitedData.map(item => item.ip);
    const values = limitedData.map(item => item.count);
    
    requestAnimationFrame(() => {
        if (charts.sourceIp) {
            charts.sourceIp.data.labels = labels;
            charts.sourceIp.data.datasets[0].data = values;
            charts.sourceIp.update('none');
        }
    });
}

function updateDestIpChart(data) {
    // Limit to max 20 items untuk performance
    const limitedData = data.slice(0, 20);
    const labels = limitedData.map(item => item.ip);
    const values = limitedData.map(item => item.count);
    
    requestAnimationFrame(() => {
        if (charts.destIp) {
            charts.destIp.data.labels = labels;
            charts.destIp.data.datasets[0].data = values;
            charts.destIp.update('none');
        }
    });
}

function updateDestPortChart(data) {
    // Limit to max 20 items untuk performance
    const limitedData = data.slice(0, 20);
    const labels = limitedData.map(item => `Port ${item.port}`);
    const values = limitedData.map(item => item.count);
    
    requestAnimationFrame(() => {
        if (charts.destPort) {
            charts.destPort.data.labels = labels;
            charts.destPort.data.datasets[0].data = values;
            charts.destPort.update('none');
        }
    });
}

function updateProtocolStateChart(data) {
    // Limit protocols dan states untuk performance
    const protocols = Object.keys(data).slice(0, 15); // Max 15 protocols
    const allStates = new Set();
    
    protocols.forEach(protocol => {
        Object.keys(data[protocol]).forEach(state => allStates.add(state));
    });
    
    const states = Array.from(allStates).slice(0, 10); // Max 10 states
    const colors = generateColors(states.length);
    
    const datasets = states.map((state, index) => ({
        label: state,
        data: protocols.map(protocol => data[protocol][state] || 0),
        backgroundColor: colors[index]
    }));
    
    requestAnimationFrame(() => {
        if (charts.protocolState) {
            charts.protocolState.data.labels = protocols;
            charts.protocolState.data.datasets = datasets;
            charts.protocolState.update('none');
        }
    });
}

function generateColors(count) {
    const colors = [
        '#667eea', '#764ba2', '#f093fb', '#4facfe', '#00f2fe',
        '#43e97b', '#fa709a', '#fee140', '#30cfd0', '#a8edea',
        '#fed6e3', '#ffecd2', '#fcb69f', '#ff9a9e', '#fecfef'
    ];
    
    const result = [];
    for (let i = 0; i < count; i++) {
        result.push(colors[i % colors.length]);
    }
    return result;
}

function sortTable(column) {
    // Toggle direction jika kolom yang sama diklik
    if (currentSort.column === column) {
        currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
    } else {
        currentSort.column = column;
        currentSort.direction = 'asc';
    }
    
    // Sort filtered connections
    filteredConnections.sort((a, b) => {
        let aVal = a[column] || '';
        let bVal = b[column] || '';
        
        // Handle numeric values untuk port, mark, use, bytes
        if (column === 'sport' || column === 'dport' || column === 'mark' || column === 'use' || 
            column === 'bytes_sent' || column === 'bytes_recv' || column === 'total_bytes') {
            aVal = parseInt(aVal) || 0;
            bVal = parseInt(bVal) || 0;
            return currentSort.direction === 'asc' ? aVal - bVal : bVal - aVal;
        }
        
        // Handle IP addresses (sort numerically)
        if (column === 'src' || column === 'dst') {
            // Convert IP to number for proper sorting
            const ipToNum = (ip) => {
                if (!ip || ip === '-') return 0;
                const parts = ip.split('.');
                if (parts.length === 4) {
                    return parseInt(parts[0]) * 256**3 + 
                           parseInt(parts[1]) * 256**2 + 
                           parseInt(parts[2]) * 256 + 
                           parseInt(parts[3]);
                }
                return 0;
            };
            aVal = ipToNum(aVal);
            bVal = ipToNum(bVal);
            return currentSort.direction === 'asc' ? aVal - bVal : bVal - aVal;
        }
        
        // String comparison untuk protocol, state, dan flags
        // Handle empty values untuk flags
        if (column === 'flags') {
            aVal = aVal === '-' || !aVal ? '' : String(aVal).toLowerCase();
            bVal = bVal === '-' || !bVal ? '' : String(bVal).toLowerCase();
        } else {
            aVal = String(aVal).toLowerCase();
            bVal = String(bVal).toLowerCase();
        }
        
        if (aVal < bVal) return currentSort.direction === 'asc' ? -1 : 1;
        if (aVal > bVal) return currentSort.direction === 'asc' ? 1 : -1;
        return 0;
    });
    
    // Update sort indicators
    document.querySelectorAll('.sortable').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        if (th.getAttribute('data-sort') === column) {
            th.classList.add(currentSort.direction === 'asc' ? 'sort-asc' : 'sort-desc');
        }
    });
    
    // Update table
    updateConnectionsTable();
}

function updateConnectionsTable() {
    const tbody = document.getElementById('connectionsTableBody');
    
    if (filteredConnections.length === 0) {
        tbody.innerHTML = '<tr><td colspan="12" class="loading">Tidak ada data yang sesuai filter</td></tr>';
        return;
    }
    
    // Apply limit - lebih agresif untuk large datasets
    let limit = currentLimit === Infinity ? filteredConnections.length : currentLimit;
    // Hard limit untuk rendering performance
    if (limit > 5000) {
        limit = 5000;
    }
    displayedConnections = filteredConnections.slice(0, limit);
    
    // Build HTML string (faster than individual DOM operations)
    const rowsHTML = displayedConnections.map(conn => {
        const protocol = (conn.protocol || 'unknown').toUpperCase();
        const protocolLower = protocol.toLowerCase();
        const state = conn.state || 'UNKNOWN';
        const src = conn.src || '-';
        const sport = conn.sport || '-';
        const dst = conn.dst || '-';
        const dport = conn.dport || '-';
        const flags = conn.flags || '-';
        const mark = conn.mark || '-';
        const use = conn.use || '-';
        const bytesSent = parseInt(conn.bytes_sent || 0);
        const bytesRecv = parseInt(conn.bytes_recv || 0);
        const totalBytes = bytesSent + bytesRecv;

        // Pastikan class protocol ada (untuk protocol yang belum didefinisikan, akan menggunakan default)
        const protocolClass = ['tcp', 'udp', 'icmp', 'icmpv6', 'gre', 'esp', 'ah'].includes(protocolLower)
            ? `protocol-${protocolLower}`
            : 'protocol-other';

        // Format flags dengan badge jika ada
        let flagsDisplay = '-';
        if (flags !== '-') {
            const flagParts = flags.split(',').map(f => f.trim());
            flagsDisplay = flagParts.map(flag => {
                const flagLower = flag.toLowerCase();
                return `<span class="flag-badge flag-${flagLower}">${flag}</span>`;
            }).join(' ');
        }

        return `
            <tr>
                <td><span class="protocol-badge ${protocolClass}">${protocol}</span></td>
                <td><span class="state-badge state-${state.toLowerCase().replace(/_/g, '-')}">${state}</span></td>
                <td>${src}</td>
                <td>${sport}</td>
                <td>${dst}</td>
                <td>${dport}</td>
                <td>${flagsDisplay}</td>
                <td>${mark}</td>
                <td>${use}</td>
                <td>${formatBytes(totalBytes)}</td>
                <td>${formatBytes(bytesSent)}</td>
                <td>${formatBytes(bytesRecv)}</td>
            </tr>
        `;
    }).join('');
    
    // Set innerHTML sekali (single DOM operation)
    tbody.innerHTML = rowsHTML;
    
    // Add info row jika ada limit dan masih ada data yang tidak ditampilkan
    if (currentLimit !== Infinity && filteredConnections.length > currentLimit) {
        const remaining = filteredConnections.length - currentLimit;
        const infoRow = document.createElement('tr');
        infoRow.innerHTML = `
            <td colspan="12" class="loading" style="text-align: center; padding: 15px !important; color: rgba(232, 234, 246, 0.7);">
                Menampilkan ${displayedConnections.length} dari ${filteredConnections.length} koneksi. 
                ${remaining} koneksi lainnya tidak ditampilkan. 
                <span style="color: #4285f4; cursor: pointer; text-decoration: underline;" onclick="document.getElementById('limitSelect').value='5000'; document.getElementById('limitSelect').dispatchEvent(new Event('change'));">
                    Tampilkan lebih banyak
                </span>
            </td>
        `;
        tbody.appendChild(infoRow);
    } else if (filteredConnections.length > 0 && displayedConnections.length === filteredConnections.length) {
        const infoRow = document.createElement('tr');
        infoRow.innerHTML = `
            <td colspan="12" class="loading" style="text-align: center; padding: 10px !important; color: rgba(232, 234, 246, 0.6); font-size: 0.9em;">
                Menampilkan ${displayedConnections.length} koneksi${displayedConnections.length !== allConnections.length ? ` (dari ${allConnections.length} total)` : ''}
            </td>
        `;
        tbody.appendChild(infoRow);
    }
}

// Throttle untuk updateFilters
let filterUpdateTimeout = null;
function updateFilters() {
    // Clear previous timeout
    if (filterUpdateTimeout) {
        clearTimeout(filterUpdateTimeout);
    }
    
    // Throttle filter updates untuk large datasets
    filterUpdateTimeout = setTimeout(() => {
        updateFiltersImmediate();
    }, allConnections.length > 10000 ? 500 : 200);
}

function updateFiltersImmediate() {
    // Update protocol filter - limit untuk performance
    const protocols = [...new Set(allConnections.slice(0, 10000).map(c => c.protocol).filter(Boolean))];
    const protocolSelect = document.getElementById('filterProtocol');
    if (protocolSelect) {
        const currentProtocol = protocolSelect.value;
        
        protocolSelect.innerHTML = '<option value="">Semua Protocol</option>' +
            protocols.map(p => `<option value="${p}">${p.toUpperCase()}</option>`).join('');
        
        if (currentProtocol && protocols.includes(currentProtocol)) {
            protocolSelect.value = currentProtocol;
        }
    }
    
    // Update state filter - limit untuk performance
    const states = [...new Set(allConnections.slice(0, 10000).map(c => c.state).filter(Boolean))];
    const stateSelect = document.getElementById('filterState');
    if (stateSelect) {
        const currentState = stateSelect.value;
        
        stateSelect.innerHTML = '<option value="">Semua State</option>' +
            states.map(s => `<option value="${s}">${s}</option>`).join('');
        
        if (currentState && states.includes(currentState)) {
            stateSelect.value = currentState;
        }
    }
}

// Throttle untuk applyFilters
let filterTimeout = null;
function applyFilters() {
    // Clear previous timeout
    if (filterTimeout) {
        clearTimeout(filterTimeout);
    }
    
    // Throttle filter application untuk large datasets
    filterTimeout = setTimeout(() => {
        applyFiltersImmediate();
    }, allConnections.length > 10000 ? 300 : 100);
}

function applyFiltersImmediate() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const protocolFilter = document.getElementById('filterProtocol').value;
    const stateFilter = document.getElementById('filterState').value;
    
    filteredConnections = allConnections.filter(conn => {
        const matchSearch = !searchTerm || 
            (conn.src && conn.src.toLowerCase().includes(searchTerm)) ||
            (conn.dst && conn.dst.toLowerCase().includes(searchTerm)) ||
            (conn.sport && conn.sport.toString().includes(searchTerm)) ||
            (conn.dport && conn.dport.toString().includes(searchTerm)) ||
            (conn.protocol && conn.protocol.toLowerCase().includes(searchTerm)) ||
            (conn.state && conn.state.toLowerCase().includes(searchTerm));
        
        const matchProtocol = !protocolFilter || conn.protocol === protocolFilter;
        const matchState = !stateFilter || conn.state === stateFilter;
        
        return matchSearch && matchProtocol && matchState;
    });
    
    // Re-apply sorting jika ada
    if (currentSort.column) {
        sortTable(currentSort.column);
    } else {
        updateConnectionsTable();
    }
}

function updateLastUpdate() {
    const now = new Date();
    // Convert to WIB: get UTC time and add 7 hours
    const utcTime = now.getTime() + (now.getTimezoneOffset() * 60 * 1000);
    const wibTime = new Date(utcTime + (7 * 60 * 60 * 1000));
    document.getElementById('lastUpdate').textContent = 
        `Terakhir update: ${wibTime.toLocaleTimeString('id-ID', { 
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        })}`;
}

function showError(message) {
    const tbody = document.getElementById('connectionsTableBody');
    tbody.innerHTML = `<tr><td colspan="12" class="loading" style="color: #d32f2f; font-weight: bold; padding: 30px !important;">
        <div style="text-align: center;">
            <div style="font-size: 2em; margin-bottom: 10px;">⚠️</div>
            <div>${message}</div>
            <div style="margin-top: 15px; font-size: 0.9em; color: #666;">
                💡 Tips: Jalankan server dengan <code>sudo python app.py</code>
            </div>
        </div>
    </td></tr>`;
    
    // Update stats untuk menunjukkan error
    document.getElementById('totalConnections').textContent = '0';
    document.getElementById('activeProtocols').textContent = '0';
    document.getElementById('uniqueStates').textContent = '0';
    document.getElementById('totalBytes').textContent = '0 B';
    document.getElementById('bytesSent').textContent = '0 B';
    document.getElementById('bytesReceived').textContent = '0 B';
}

async function loadTimeSeries() {
    try {
        const metricType = document.getElementById('timeseriesMetricType').value;
        const metricKey = document.getElementById('timeseriesMetricKey').value || null;
        const hours = parseInt(document.getElementById('timeseriesHours').value);
        const intervalMinutes = parseInt(document.getElementById('timeseriesInterval').value);
        
        // Jika All Metrics, ambil semua metric keys dan tampilkan semuanya
        if (!metricKey) {
            // Get available keys first
            const groupByParam = metricType.replace('by_', '');
            const keysResponse = await fetch(`/api/groupings/${groupByParam}`);
            const keysResult = await keysResponse.json();
            
            if (keysResult.success) {
                const allKeys = Object.keys(keysResult.data);
                // Ambil top 10 untuk menghindari terlalu banyak lines
                const topKeys = allKeys.slice(0, 10);
                
                // Load time series untuk setiap key
                const promises = topKeys.map(key => 
                    fetch(`/api/timeseries/${metricType}?hours=${hours}&interval_minutes=${intervalMinutes}&metric_key=${encodeURIComponent(key)}`)
                        .then(r => r.json())
                );
                
                const results = await Promise.all(promises);
                updateTimeSeriesChartAllMetrics(results, topKeys, hours, intervalMinutes);
                return;
            }
        }
        
        // Single metric key
        const url = `/api/timeseries/${metricType}?hours=${hours}&interval_minutes=${intervalMinutes}` + 
                   (metricKey ? `&metric_key=${encodeURIComponent(metricKey)}` : '');
        
        const response = await fetch(url);
        const result = await response.json();
        
        if (result.success) {
            updateTimeSeriesChart(result.data, metricType, metricKey);
        }
    } catch (error) {
        console.error('Error loading time series:', error);
    }
}

function updateTimeSeriesChart(data, metricType, metricKey) {
    if (!data || data.length === 0) {
        charts.timeseries.data.labels = [];
        charts.timeseries.data.datasets = [];
        charts.timeseries.update();
        updateTimeseriesLegend([]);
        return;
    }
    
    const labels = data.map(d => {
        // Timestamp dari database adalah UTC, convert ke WIB
        const date = new Date(d.timestamp);
        // Add 7 hours for WIB (UTC+7)
        const wibDate = new Date(date.getTime() + (7 * 60 * 60 * 1000));
        return wibDate.toLocaleTimeString('id-ID', { 
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    });
    
    // Always show both count and bytes for single metric
    const datasets = [
        {
            label: `${metricKey || 'All'} - Count`,
            data: data.map(d => d.count || 0),
            borderColor: '#4285f4',
            backgroundColor: 'rgba(66, 133, 244, 0.1)',
            tension: 0.4,
            yAxisID: 'y',
            hidden: false
        },
        {
            label: `${metricKey || 'All'} - Bytes Sent`,
            data: data.map(d => d.bytes_sent || 0),
            borderColor: '#ea4335',
            backgroundColor: 'rgba(234, 67, 53, 0.1)',
            tension: 0.4,
            yAxisID: 'y1',
            hidden: false
        },
        {
            label: `${metricKey || 'All'} - Bytes Received`,
            data: data.map(d => d.bytes_recv || 0),
            borderColor: '#fbbc04',
            backgroundColor: 'rgba(251, 188, 4, 0.1)',
            tension: 0.4,
            yAxisID: 'y1',
            hidden: false
        },
        {
            label: `${metricKey || 'All'} - Total Bytes`,
            data: data.map(d => d.total_bytes || 0),
            borderColor: '#34a853',
            backgroundColor: 'rgba(52, 168, 83, 0.1)',
            tension: 0.4,
            yAxisID: 'y1',
            hidden: false
        }
    ];
    
    charts.timeseries.data.labels = labels;
    charts.timeseries.data.datasets = datasets;
    timeseriesDatasets = datasets;
    
    // Setup dual y-axis
    charts.timeseries.options.scales = {
        y: {
            beginAtZero: true,
            title: {
                display: true,
                text: 'Count'
            },
            position: 'left'
        },
        y1: {
            type: 'linear',
            display: true,
            position: 'right',
            beginAtZero: true,
            title: {
                display: true,
                text: 'Bytes'
            },
            grid: {
                drawOnChartArea: false
            }
        }
    };
    
    charts.timeseries.update();
    updateTimeseriesLegend(datasets);
}

function updateTimeSeriesChartAllMetrics(results, keys, hours, intervalMinutes) {
    // Collect all timestamps from all results
    const allTimestamps = new Set();
    results.forEach(result => {
        if (result.success && result.data) {
            result.data.forEach(d => allTimestamps.add(d.timestamp));
        }
    });
    
    const sortedTimestamps = Array.from(allTimestamps).sort();
    
    if (sortedTimestamps.length === 0) {
        charts.timeseries.data.labels = [];
        charts.timeseries.data.datasets = [];
        charts.timeseries.update();
        return;
    }
    
    const labels = sortedTimestamps.map(ts => {
        // Timestamp dari database adalah UTC, convert ke WIB
        const date = new Date(ts);
        // Add 7 hours for WIB (UTC+7)
        const wibDate = new Date(date.getTime() + (7 * 60 * 60 * 1000));
        return wibDate.toLocaleTimeString('id-ID', { 
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    });
    
    // Color palette untuk multiple lines
    const colors = [
        '#4285f4', '#ea4335', '#fbbc04', '#34a853', '#9c27b0',
        '#00bcd4', '#ff9800', '#4caf50', '#e91e63', '#2196f3'
    ];
    
    // Helper function to convert hex to rgba
    const hexToRgba = (hex, alpha) => {
        const r = parseInt(hex.slice(1, 3), 16);
        const g = parseInt(hex.slice(3, 5), 16);
        const b = parseInt(hex.slice(5, 7), 16);
        return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    };
    
    const datasets = [];
    
    // Create datasets for each metric key
    keys.forEach((key, idx) => {
        const result = results[idx];
        if (result && result.success && result.data) {
            // Create a map for quick lookup
            const dataMap = new Map();
            result.data.forEach(d => {
                dataMap.set(d.timestamp, d);
            });
            
            // Get data for each timestamp
            const countData = sortedTimestamps.map(ts => {
                const d = dataMap.get(ts);
                return d ? d.count : 0;
            });
            
            const bytesData = sortedTimestamps.map(ts => {
                const d = dataMap.get(ts);
                return d ? (d.total_bytes || 0) : 0;
            });
            
            const color = colors[idx % colors.length];
            
            // Add count line
            datasets.push({
                label: `${key} - Count`,
                data: countData,
                borderColor: color,
                backgroundColor: hexToRgba(color, 0.1),
                tension: 0.4,
                yAxisID: 'y',
                borderWidth: 2
            });
            
            // Add bytes line
            datasets.push({
                label: `${key} - Total Bytes`,
                data: bytesData,
                borderColor: hexToRgba(color, 0.6),
                backgroundColor: hexToRgba(color, 0.05),
                tension: 0.4,
                yAxisID: 'y1',
                borderWidth: 1.5,
                borderDash: [5, 5]
            });
        }
    });
    
    charts.timeseries.data.labels = labels;
    charts.timeseries.data.datasets = datasets;
    timeseriesDatasets = datasets;
    
    // Setup dual y-axis
    charts.timeseries.options.scales = {
        y: {
            beginAtZero: true,
            title: {
                display: true,
                text: 'Count'
            },
            position: 'left'
        },
        y1: {
            type: 'linear',
            display: true,
            position: 'right',
            beginAtZero: true,
            title: {
                display: true,
                text: 'Bytes'
            },
            grid: {
                drawOnChartArea: false
            }
        }
    };
    
    charts.timeseries.update();
    updateTimeseriesLegend(datasets);
}

function updateTimeseriesLegend(datasets) {
    const legendContainer = document.getElementById('timeseriesLegend');
    
    if (!datasets || datasets.length === 0) {
        legendContainer.innerHTML = '<div class="loading">No data</div>';
        return;
    }
    
    // Store datasets globally for filtering
    window.timeseriesDatasets = datasets;
    
    renderLegendItems(datasets);
    setupLegendEventListeners();
}

function renderLegendItems(datasets) {
    const legendContainer = document.getElementById('timeseriesLegend');
    const searchInput = document.getElementById('legendSearchInput');
    const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
    
    // Filter datasets based on search term
    const filteredDatasets = datasets.filter((dataset, idx) => {
        if (!searchTerm) return true;
        return dataset.label.toLowerCase().includes(searchTerm);
    });
    
    legendContainer.innerHTML = filteredDatasets.map((dataset, filteredIdx) => {
        // Find original index in full datasets array
        const originalIdx = datasets.findIndex(d => d === dataset);
        const checkboxId = `legend-${originalIdx}`;
        const isHidden = dataset.hidden || false;
        
        return `
            <div class="timeseries-legend-item ${isHidden ? 'disabled' : ''}" data-index="${originalIdx}" data-label="${dataset.label.toLowerCase()}">
                <input type="checkbox" id="${checkboxId}" ${!isHidden ? 'checked' : ''} data-index="${originalIdx}">
                <label for="${checkboxId}">
                    <span class="timeseries-legend-color" style="background-color: ${dataset.borderColor}"></span>
                    <span>${dataset.label}</span>
                </label>
            </div>
        `;
    }).join('');
    
    // Show message if no results
    if (filteredDatasets.length === 0 && searchTerm) {
        legendContainer.innerHTML = '<div class="loading">Tidak ada metric yang sesuai</div>';
    }
}

function setupLegendEventListeners() {
    const legendContainer = document.getElementById('timeseriesLegend');
    
    // Add event listeners for toggling individual checkboxes
    legendContainer.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
        checkbox.addEventListener('change', (e) => {
            const index = parseInt(e.target.getAttribute('data-index'));
            const dataset = charts.timeseries.data.datasets[index];
            const legendItem = e.target.closest('.timeseries-legend-item');
            
            if (dataset) {
                const meta = charts.timeseries.getDatasetMeta(index);
                meta.hidden = !e.target.checked;
                dataset.hidden = !e.target.checked;
                
                if (e.target.checked) {
                    legendItem.classList.remove('disabled');
                } else {
                    legendItem.classList.add('disabled');
                }
                
                charts.timeseries.update();
            }
        });
    });
}

function setupLegendControls() {
    const searchInput = document.getElementById('legendSearchInput');
    const selectAllBtn = document.getElementById('legendSelectAll');
    const deselectAllBtn = document.getElementById('legendDeselectAll');
    
    // Search functionality
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            if (window.timeseriesDatasets) {
                renderLegendItems(window.timeseriesDatasets);
                setupLegendEventListeners();
            }
        });
    }
    
    // Select All functionality
    if (selectAllBtn) {
        selectAllBtn.addEventListener('click', () => {
            if (!charts.timeseries || !window.timeseriesDatasets) return;
            
            const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
            const filteredDatasets = window.timeseriesDatasets.filter(dataset => {
                if (!searchTerm) return true;
                return dataset.label.toLowerCase().includes(searchTerm);
            });
            
            filteredDatasets.forEach(dataset => {
                const index = window.timeseriesDatasets.findIndex(d => d === dataset);
                if (index !== -1) {
                    const meta = charts.timeseries.getDatasetMeta(index);
                    meta.hidden = false;
                    dataset.hidden = false;
                }
            });
            
            charts.timeseries.update();
            renderLegendItems(window.timeseriesDatasets);
            setupLegendEventListeners();
        });
    }
    
    // Deselect All functionality
    if (deselectAllBtn) {
        deselectAllBtn.addEventListener('click', () => {
            if (!charts.timeseries || !window.timeseriesDatasets) return;
            
            const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
            const filteredDatasets = window.timeseriesDatasets.filter(dataset => {
                if (!searchTerm) return true;
                return dataset.label.toLowerCase().includes(searchTerm);
            });
            
            filteredDatasets.forEach(dataset => {
                const index = window.timeseriesDatasets.findIndex(d => d === dataset);
                if (index !== -1) {
                    const meta = charts.timeseries.getDatasetMeta(index);
                    meta.hidden = true;
                    dataset.hidden = true;
                }
            });
            
            charts.timeseries.update();
            renderLegendItems(window.timeseriesDatasets);
            setupLegendEventListeners();
        });
    }
}

async function updateTimeseriesMetricKeys() {
    const metricType = document.getElementById('timeseriesMetricType').value;
    const select = document.getElementById('timeseriesMetricKey');
    
    try {
        // Get available keys from latest groupings
        const groupByParam = metricType.replace('by_', '');
        const response = await fetch(`/api/groupings/${groupByParam}`);
        const result = await response.json();
        
        if (result.success) {
            const keys = Object.keys(result.data).sort();
            select.innerHTML = '<option value="">All Metrics</option>' +
                keys.map(key => `<option value="${key}">${key}</option>`).join('');
        }
    } catch (error) {
        console.error('Error loading metric keys:', error);
    }
}

let allGroupingData = {};
let currentGroupBy = 'by_protocol';

async function loadGroupingData(groupBy) {
    try {
        currentGroupBy = groupBy;
        const groupByParam = groupBy.replace('by_', '');
        const response = await fetch(`/api/groupings/${groupByParam}`);
        const result = await response.json();
        
        if (result.success) {
            allGroupingData = result.data;
            applyGroupingFilters();
        }
    } catch (error) {
        console.error('Error loading grouping data:', error);
    }
}

function applyGroupingFilters() {
    const searchTerm = document.getElementById('groupingSearchInput').value.toLowerCase();
    const limitValue = document.getElementById('groupingLimitSelect').value;
    const limit = limitValue === 'all' ? Infinity : parseInt(limitValue);
    
    // Filter data
    let filtered = Object.entries(allGroupingData);
    
    if (searchTerm) {
        filtered = filtered.filter(([key, stats]) => {
            return key.toLowerCase().includes(searchTerm);
        });
    }
    
    // Sort by count descending
    filtered.sort((a, b) => b[1].count - a[1].count);
    
    // Apply limit
    const limited = filtered.slice(0, limit);
    
    // Convert back to object for display
    const filteredData = Object.fromEntries(limited);
    
    displayGroupingStats(filteredData, currentGroupBy, filtered.length, limit);
}

function displayGroupingStats(data, groupBy, totalCount = null, limit = null) {
    const grid = document.getElementById('groupingStatsGrid');
    
    if (!data || Object.keys(data).length === 0) {
        grid.innerHTML = '<div class="loading">Tidak ada data</div>';
        return;
    }
    
    // Data sudah di-sort dan di-limit di applyGroupingFilters
    const sorted = Object.entries(data);
    
    let html = sorted.map(([key, stats]) => {
        // Ensure bytes values are numbers
        const bytesSent = parseInt(stats.bytes_sent || 0);
        const bytesRecv = parseInt(stats.bytes_recv || 0);
        const totalBytes = parseInt(stats.total_bytes || 0);
        
        return `
            <div class="grouping-stat-card">
                <div class="grouping-stat-key">${key}</div>
                <div class="grouping-stat-value">
                    <div class="stat-item">
                        <span class="stat-label">Connections:</span>
                        <span class="stat-number">${(stats.count || 0).toLocaleString()}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Bytes Sent:</span>
                        <span class="stat-number">${formatBytes(bytesSent)}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Bytes Received:</span>
                        <span class="stat-number">${formatBytes(bytesRecv)}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Total Bytes:</span>
                        <span class="stat-number">${formatBytes(totalBytes)}</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
    
    // Add info row if there's a limit
    if (totalCount !== null && limit !== null && totalCount > limit) {
        html += `
            <div class="grouping-info-row">
                Menampilkan ${sorted.length} dari ${totalCount} items.
                ${totalCount - sorted.length} items lainnya tidak ditampilkan.
            </div>
        `;
    } else if (totalCount !== null) {
        html += `
            <div class="grouping-info-row">
                Menampilkan semua ${totalCount} items.
            </div>
        `;
    }
    
    grid.innerHTML = html;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function updateBytesStats() {
    // Calculate and update bytes from all connections
    let totalBytes = 0;
    let bytesSent = 0;
    let bytesRecv = 0;
    
    if (allConnections && allConnections.length > 0) {
        allConnections.forEach(conn => {
            bytesSent += parseInt(conn.bytes_sent || 0);
            bytesRecv += parseInt(conn.bytes_recv || 0);
        });
        totalBytes = bytesSent + bytesRecv;
    }
    
    document.getElementById('totalBytes').textContent = formatBytes(totalBytes);
    document.getElementById('bytesSent').textContent = formatBytes(bytesSent);
    document.getElementById('bytesReceived').textContent = formatBytes(bytesRecv);
}

// Anomaly Detection Functions - Function already defined at top of file
// This is just a reference comment

function displayAnomalies(anomalies, metadata) {
    const tbody = document.getElementById('anomaliesTableBody');
    const statsDiv = document.getElementById('anomalyStats');
    
    // Update stats
    if (metadata) {
        document.getElementById('anomalyCount').textContent = (metadata.count || 0).toLocaleString();
        const rate = (metadata.anomaly_rate || 0) * 100;
        document.getElementById('anomalyRate').textContent = `${rate.toFixed(2)}%`;
        document.getElementById('anomalyTotalConnections').textContent = (metadata.total_connections || 0).toLocaleString();
        statsDiv.style.display = 'flex';
    }
    
    if (!anomalies || anomalies.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10" class="loading">Tidak ada anomaly yang terdeteksi</td></tr>';
        return;
    }
    
    tbody.innerHTML = anomalies.map(anomaly => {
        const protocol = (anomaly.protocol || 'unknown').toUpperCase();
        const protocolLower = protocol.toLowerCase();
        const state = anomaly.state || 'UNKNOWN';
        const src = anomaly.src || '-';
        const sport = anomaly.sport || '-';
        const dst = anomaly.dst || '-';
        const dport = anomaly.dport || '-';
        const totalBytes = anomaly.total_bytes || 0;
        const bytesSent = anomaly.bytes_sent || 0;
        const bytesRecv = anomaly.bytes_recv || 0;
        const score = anomaly.anomaly_score || 0;
        
        // Color code berdasarkan score (lower = more anomalous)
        let scoreColor = '#ea4335'; // Red for very anomalous
        if (score > -0.3) scoreColor = '#fbbc04'; // Yellow
        if (score > -0.1) scoreColor = '#34a853'; // Green (less anomalous)
        
        const protocolClass = ['tcp', 'udp', 'icmp', 'icmpv6', 'gre', 'esp', 'ah'].includes(protocolLower) 
            ? `protocol-${protocolLower}` 
            : 'protocol-other';
        
        return `
            <tr style="background: ${score < -0.3 ? 'rgba(234, 67, 53, 0.1)' : score < -0.1 ? 'rgba(251, 188, 4, 0.1)' : 'rgba(52, 168, 83, 0.1)'};">
                <td>
                    <span style="color: ${scoreColor}; font-weight: bold;">
                        ${score.toFixed(4)}
                    </span>
                </td>
                <td><span class="protocol-badge ${protocolClass}">${protocol}</span></td>
                <td><span class="state-badge state-${state.toLowerCase().replace(/_/g, '-')}">${state}</span></td>
                <td>${src}</td>
                <td>${sport}</td>
                <td>${dst}</td>
                <td>${dport}</td>
                <td>${formatBytes(totalBytes)}</td>
                <td>${formatBytes(bytesSent)}</td>
                <td>${formatBytes(bytesRecv)}</td>
            </tr>
        `;
    }).join('');
}


