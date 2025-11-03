// Dashboard JavaScript - Real-time network traffic analyzer

let protocolChart, portsChart, bandwidthChart;
let eventSource = null;
let bandwidthData = [];
let bandwidthLabels = [];
const MAX_BANDWIDTH_POINTS = 30;

// Initialize charts
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    loadInterfaces();
    setupEventListeners();
});

function initializeCharts() {
    // Protocol Distribution Chart
    const protocolCtx = document.getElementById('protocol-chart').getContext('2d');
    protocolChart = new Chart(protocolCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#0d6efd', // TCP - Blue
                    '#198754', // UDP - Green
                    '#ffc107', // HTTP - Yellow
                    '#dc3545', // DNS - Red
                    '#6c757d'  // Other - Gray
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });

    // Top Ports Chart
    const portsCtx = document.getElementById('ports-chart').getContext('2d');
    portsChart = new Chart(portsCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets',
                data: [],
                backgroundColor: '#0d6efd'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });

    // Bandwidth Chart
    const bandwidthCtx = document.getElementById('bandwidth-chart').getContext('2d');
    bandwidthChart = new Chart(bandwidthCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Throughput (Mbps)',
                data: [],
                borderColor: '#0d6efd',
                backgroundColor: 'rgba(13, 110, 253, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

function loadInterfaces() {
    fetch('/api/interfaces')
        .then(response => response.json())
        .then(data => {
            const select = document.getElementById('interface-select');
            data.interfaces.forEach(iface => {
                const option = document.createElement('option');
                option.value = iface;
                option.textContent = iface;
                select.appendChild(option);
            });
        })
        .catch(error => {
            console.error('Error loading interfaces:', error);
        });
}

function setupEventListeners() {
    document.getElementById('start-btn').addEventListener('click', startCapture);
    document.getElementById('stop-btn').addEventListener('click', stopCapture);
    document.getElementById('reset-btn').addEventListener('click', resetDashboard);
    document.getElementById('export-csv-btn').addEventListener('click', exportCSV);
    document.getElementById('export-json-btn').addEventListener('click', exportJSON);
    document.getElementById('export-pcap-btn').addEventListener('click', exportPCAP);
}

function startCapture() {
    const interface = document.getElementById('interface-select').value;
    const filter = document.getElementById('filter-input').value;
    
    fetch('/api/capture/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            interface: interface || null,
            filter: filter
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'started') {
            document.getElementById('start-btn').disabled = true;
            document.getElementById('stop-btn').disabled = false;
            document.getElementById('status-badge').textContent = 'Capturing';
            document.getElementById('status-badge').className = 'badge bg-success';
            startStreaming();
        } else {
            alert('Error: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error starting capture:', error);
        alert('Failed to start capture. Make sure you have proper permissions.');
    });
}

function showError(message) {
    // Create or update error alert
    let errorAlert = document.getElementById('error-alert');
    if (!errorAlert) {
        errorAlert = document.createElement('div');
        errorAlert.id = 'error-alert';
        errorAlert.className = 'alert alert-danger alert-dismissible fade show';
        errorAlert.innerHTML = `
            <strong>Error:</strong> <span id="error-message"></span>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        const container = document.querySelector('.container-fluid');
        container.insertBefore(errorAlert, container.firstChild);
    }
    document.getElementById('error-message').textContent = message;
    errorAlert.style.display = 'block';
}

function stopCapture() {
    fetch('/api/capture/stop', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'stopped') {
            document.getElementById('start-btn').disabled = false;
            document.getElementById('stop-btn').disabled = true;
            document.getElementById('status-badge').textContent = 'Stopped';
            document.getElementById('status-badge').className = 'badge bg-secondary';
            stopStreaming();
        }
    })
    .catch(error => {
        console.error('Error stopping capture:', error);
    });
}

function resetDashboard() {
    protocolChart.data.labels = [];
    protocolChart.data.datasets[0].data = [];
    protocolChart.update();
    
    portsChart.data.labels = [];
    portsChart.data.datasets[0].data = [];
    portsChart.update();
    
    bandwidthChart.data.labels = [];
    bandwidthChart.data.datasets[0].data = [];
    bandwidthChart.update();
    
    bandwidthData = [];
    bandwidthLabels = [];
    
    updateMetrics({
        total_packets: 0,
        throughput_mbps: 0,
        packets_per_second: 0,
        total_bytes: 0
    });
    
    document.getElementById('anomalies-list').innerHTML = '<p class="text-muted">No anomalies detected</p>';
    document.getElementById('packets-table').innerHTML = '<tr><td colspan="6" class="text-center text-muted">No packets captured yet</td></tr>';
}

function startStreaming() {
    if (eventSource) {
        eventSource.close();
    }
    
    eventSource = new EventSource('/api/stream');
    
    eventSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        updateDashboard(data);
    };
    
    eventSource.onerror = function(error) {
        console.error('SSE error:', error);
        eventSource.close();
        // Try to reconnect after a delay
        setTimeout(startStreaming, 2000);
    };
}

function stopStreaming() {
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
}

function updateDashboard(data) {
    // Check for errors
    if (data.stats && data.stats.error) {
        showError(data.stats.error);
        document.getElementById('status-badge').textContent = 'Error';
        document.getElementById('status-badge').className = 'badge bg-danger';
        document.getElementById('start-btn').disabled = false;
        document.getElementById('stop-btn').disabled = true;
        return;
    }
    
    // Hide error if capture is working
    const errorAlert = document.getElementById('error-alert');
    if (errorAlert) {
        errorAlert.style.display = 'none';
    }
    
    if (!data.is_capturing) {
        return;
    }
    
    const stats = data.stats;
    
    // Update metrics
    updateMetrics(stats);
    
    // Update protocol chart
    if (stats.protocol_distribution) {
        const protocolData = stats.protocol_distribution;
        protocolChart.data.labels = Object.keys(protocolData);
        protocolChart.data.datasets[0].data = Object.values(protocolData);
        protocolChart.update();
    }
    
    // Update ports chart
    if (stats.port_activity) {
        const portEntries = Object.entries(stats.port_activity).slice(0, 10);
        portsChart.data.labels = portEntries.map(([port]) => port);
        portsChart.data.datasets[0].data = portEntries.map(([, count]) => count);
        portsChart.update();
    }
    
    // Update bandwidth chart
    const timestamp = new Date().toLocaleTimeString();
    bandwidthLabels.push(timestamp);
    bandwidthData.push(stats.throughput_mbps || 0);
    
    if (bandwidthLabels.length > MAX_BANDWIDTH_POINTS) {
        bandwidthLabels.shift();
        bandwidthData.shift();
    }
    
    bandwidthChart.data.labels = bandwidthLabels;
    bandwidthChart.data.datasets[0].data = bandwidthData;
    bandwidthChart.update();
    
    // Update recent packets
    if (data.recent_packets) {
        updatePacketsTable(data.recent_packets);
    }
    
    // Update anomalies
    if (data.anomalies) {
        updateAnomalies(data.anomalies);
    }
}

function updateMetrics(stats) {
    document.getElementById('total-packets').textContent = stats.total_packets || 0;
    document.getElementById('throughput').textContent = (stats.throughput_mbps || 0).toFixed(2) + ' Mbps';
    document.getElementById('packets-per-sec').textContent = (stats.packets_per_second || 0).toFixed(2);
    
    const totalBytesMB = (stats.total_bytes || 0) / (1024 * 1024);
    document.getElementById('total-bytes').textContent = totalBytesMB.toFixed(2) + ' MB';
}

function updatePacketsTable(packets) {
    const tbody = document.getElementById('packets-table');
    
    if (packets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No packets captured yet</td></tr>';
        return;
    }
    
    // Reverse to show newest first
    const reversed = [...packets].reverse();
    tbody.innerHTML = reversed.map(packet => {
        const time = new Date(packet.timestamp).toLocaleTimeString();
        const protocol = packet.protocol || 'Unknown';
        const protocolClass = protocol.toLowerCase();
        
        return `
            <tr>
                <td>${time}</td>
                <td><span class="protocol-badge ${protocolClass}">${protocol}</span></td>
                <td>${packet.src_ip || '-'}</td>
                <td>${packet.dst_ip || '-'}</td>
                <td>${packet.dst_port || '-'}</td>
                <td>${formatBytes(packet.size)}</td>
            </tr>
        `;
    }).join('');
}

function updateAnomalies(anomalies) {
    const container = document.getElementById('anomalies-list');
    
    if (anomalies.length === 0) {
        container.innerHTML = '<p class="text-muted">No anomalies detected</p>';
        return;
    }
    
    // Reverse to show newest first
    const reversed = [...anomalies].reverse();
    container.innerHTML = reversed.map(anomaly => {
        const severityClass = anomaly.severity?.toLowerCase() || 'medium';
        const time = new Date(anomaly.timestamp).toLocaleTimeString();
        
        return `
            <div class="anomaly-item ${severityClass}">
                <strong>${anomaly.type}</strong> - ${time}<br>
                <small>Source: ${anomaly.source_ip}</small><br>
                <small>Ports scanned: ${anomaly.ports_scanned} | Severity: ${anomaly.severity}</small>
            </div>
        `;
    }).join('');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function exportCSV() {
    window.location.href = '/api/export/csv';
}

function exportJSON() {
    window.location.href = '/api/export/json';
}

function exportPCAP() {
    window.location.href = '/api/export/pcap';
}

