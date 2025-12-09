// Dashboard JavaScript - Real-time network traffic analyzer

let protocolChart, portsChart, bandwidthChart;
let eventSource = null;
let bandwidthData = [];
let bandwidthLabels = [];
let recentPackets = [];
const MAX_BANDWIDTH_POINTS = 30;

document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    loadInterfaces();
    setupEventListeners();
    startStreaming();
    console.log('Dashboard initialized');
});

function initializeCharts() {
    Chart.defaults.color = '#64748b';
    Chart.defaults.borderColor = '#e2e8f0';
    
    const protocolCtx = document.getElementById('protocol-chart').getContext('2d');
    protocolChart = new Chart(protocolCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['#3b82f6', '#22c55e', '#eab308', '#ef4444', '#a855f7', '#06b6d4'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            cutout: '60%',
            plugins: {
                legend: { position: 'bottom', labels: { padding: 15, usePointStyle: true } }
            }
        }
    });

    const portsCtx = document.getElementById('ports-chart').getContext('2d');
    portsChart = new Chart(portsCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets',
                data: [],
                backgroundColor: '#3b82f6',
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: { beginAtZero: true, grid: { color: '#e2e8f0' } },
                x: { grid: { display: false } }
            },
            plugins: { legend: { display: false } }
        }
    });

    const bandwidthCtx = document.getElementById('bandwidth-chart').getContext('2d');
    bandwidthChart = new Chart(bandwidthCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Throughput (Mbps)',
                data: [],
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.4,
                fill: true,
                pointRadius: 0,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: { beginAtZero: true, grid: { color: '#e2e8f0' } },
                x: { grid: { display: false }, ticks: { maxTicksLimit: 10 } }
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
        .catch(error => console.error('Error loading interfaces:', error));
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
    const iface = document.getElementById('interface-select').value;
    const filter = document.getElementById('filter-input').value;
    
    fetch('/api/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: iface || null, filter: filter })
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

function stopCapture() {
    fetch('/api/capture/stop', { method: 'POST' })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'stopped') {
            document.getElementById('start-btn').disabled = false;
            document.getElementById('stop-btn').disabled = true;
            document.getElementById('status-badge').textContent = 'Stopped';
            document.getElementById('status-badge').className = 'badge bg-secondary';
        }
    })
    .catch(error => console.error('Error stopping capture:', error));
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
    recentPackets = [];
    
    updateMetrics({ total_packets: 0, throughput_mbps: 0, packets_per_second: 0, total_bytes: 0 });
    document.getElementById('anomalies-list').innerHTML = '<p class="text-muted">No anomalies detected</p>';
    document.getElementById('packets-table').innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">No packets captured yet</td></tr>';
}

function startStreaming() {
    if (eventSource) eventSource.close();
    
    eventSource = new EventSource('/api/stream');
    eventSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        updateDashboard(data);
    };
    eventSource.onerror = function(error) {
        console.error('SSE error:', error);
        eventSource.close();
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
    if (data.stats && data.stats.error) {
        document.getElementById('status-badge').textContent = 'Error';
        document.getElementById('status-badge').className = 'badge bg-danger';
        document.getElementById('start-btn').disabled = false;
        document.getElementById('stop-btn').disabled = true;
        return;
    }
    
    if (data.anomalies) updateAnomalies(data.anomalies);
    updateMLStatus(data.ml_available, data.ml_stats);
    
    if (!data.is_capturing) return;
    
    const stats = data.stats;
    updateMetrics(stats);
    
    if (stats.protocol_distribution) {
        protocolChart.data.labels = Object.keys(stats.protocol_distribution);
        protocolChart.data.datasets[0].data = Object.values(stats.protocol_distribution);
        protocolChart.update();
    }
    
    if (stats.port_activity) {
        const portEntries = Object.entries(stats.port_activity).slice(0, 10);
        portsChart.data.labels = portEntries.map(([port]) => port);
        portsChart.data.datasets[0].data = portEntries.map(([, count]) => count);
        portsChart.update();
    }
    
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
    
    if (data.recent_packets) {
        recentPackets = data.recent_packets;
        updatePacketsTable(data.recent_packets);
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
    
    if (!packets || packets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">No packets captured yet</td></tr>';
        return;
    }
    
    const reversed = [...packets].reverse();
    tbody.innerHTML = reversed.map((packet, index) => {
        const time = new Date(packet.timestamp).toLocaleTimeString('en-US', { 
            hour12: false, 
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit' 
        });
        const protocol = (packet.protocol || 'Unknown').toLowerCase();
        
        return `
            <tr onclick="showPacketDetails(${packets.length - 1 - index})">
                <td><span class="packet-time">${time}</span></td>
                <td><span class="protocol-badge ${protocol}">${packet.protocol || 'UNK'}</span></td>
                <td><span class="packet-ip">${packet.src_ip || '-'}</span></td>
                <td><span class="packet-ip">${packet.dst_ip || '-'}</span></td>
                <td><span class="packet-port">${packet.dst_port || '-'}</span></td>
                <td><span class="packet-size">${formatBytes(packet.size)}</span></td>
            </tr>
        `;
    }).join('');
}

function showPacketDetails(index) {
    const packet = recentPackets[index];
    if (!packet) return;
    
    const details = document.getElementById('packet-details');
    const time = new Date(packet.timestamp).toLocaleString();
    const flags = packet.flags || '';
    const flagList = ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG'];
    const activeFlags = flagList.filter(f => flags.includes(f[0]));
    
    details.innerHTML = `
        <div class="detail-item">
            <div class="detail-label">Timestamp</div>
            <div class="detail-value">${time}</div>
        </div>
        <div class="detail-item">
            <div class="detail-label">Protocol</div>
            <div class="detail-value highlight">${packet.protocol || 'Unknown'}</div>
        </div>
        <div class="detail-item">
            <div class="detail-label">Source IP</div>
            <div class="detail-value"><code>${packet.src_ip || 'N/A'}</code></div>
        </div>
        <div class="detail-item">
            <div class="detail-label">Destination IP</div>
            <div class="detail-value"><code>${packet.dst_ip || 'N/A'}</code></div>
        </div>
        <div class="detail-item">
            <div class="detail-label">Source Port</div>
            <div class="detail-value">${packet.src_port || 'N/A'}</div>
        </div>
        <div class="detail-item">
            <div class="detail-label">Destination Port</div>
            <div class="detail-value highlight">${packet.dst_port || 'N/A'}</div>
        </div>
        <div class="detail-item">
            <div class="detail-label">Packet Size</div>
            <div class="detail-value">${packet.size || 0} bytes</div>
        </div>
        <div class="detail-item">
            <div class="detail-label">TCP Flags</div>
            <div class="detail-value">
                <div class="packet-flags">
                    ${flagList.map(f => `<span class="flag-badge ${activeFlags.includes(f) ? 'active' : ''}">${f}</span>`).join('')}
                </div>
            </div>
        </div>
        ${packet.dns_query ? `
        <div class="detail-item" style="grid-column: span 2;">
            <div class="detail-label">DNS Query</div>
            <div class="detail-value highlight">${packet.dns_query}</div>
        </div>` : ''}
        ${packet.http_method ? `
        <div class="detail-item">
            <div class="detail-label">HTTP Method</div>
            <div class="detail-value highlight">${packet.http_method}</div>
        </div>` : ''}
        ${packet.http_host ? `
        <div class="detail-item">
            <div class="detail-label">HTTP Host</div>
            <div class="detail-value">${packet.http_host}</div>
        </div>` : ''}
    `;
    
    const modal = new bootstrap.Modal(document.getElementById('packetModal'));
    modal.show();
}

function updateAnomalies(anomalies) {
    const container = document.getElementById('anomalies-list');
    
    if (!anomalies || anomalies.length === 0) {
        container.innerHTML = '<p class="text-muted">No anomalies detected</p>';
        return;
    }
    
    const getSeverityInfo = (severity) => {
        if (typeof severity === 'number') {
            if (severity >= 4) return { class: 'critical', label: 'Critical' };
            if (severity >= 3) return { class: 'high', label: 'High' };
            if (severity >= 2) return { class: 'medium', label: 'Medium' };
            return { class: 'low', label: 'Low' };
        }
        const sev = String(severity || 'medium').toLowerCase();
        return { class: sev, label: severity || 'Medium' };
    };
    
    const reversed = [...anomalies].reverse();
    container.innerHTML = reversed.map(anomaly => {
        const sevInfo = getSeverityInfo(anomaly.severity);
        const time = anomaly.timestamp ? new Date(anomaly.timestamp).toLocaleTimeString() : 'Now';
        const isML = anomaly.detection_method === 'ml' || (anomaly.type && anomaly.type.startsWith('ML:'));
        
        let confidence = '';
        if (anomaly.confidence) {
            const conf = typeof anomaly.confidence === 'number' && anomaly.confidence <= 1 
                ? (anomaly.confidence * 100).toFixed(0) 
                : anomaly.confidence;
            confidence = `${conf}%`;
        }
        
        let destination = '';
        if (anomaly.destination_ip) {
            destination = ` → ${anomaly.destination_ip}`;
            if (anomaly.destination_port) destination += `:${anomaly.destination_port}`;
        }
        
        return `
            <div class="anomaly-item ${sevInfo.class}">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="anomaly-type">${anomaly.type || 'Unknown'}</div>
                    <span class="severity-badge ${sevInfo.class}">${sevInfo.label}</span>
                </div>
                <div class="anomaly-source">${anomaly.source_ip || 'Unknown'}${destination}</div>
                <div class="anomaly-meta">
                    <span>${time}</span>
                    ${confidence ? `<span>${confidence}</span>` : ''}
                    <span>${isML ? 'ML' : 'Rule'}</span>
                </div>
                ${anomaly.description ? `<small class="text-muted d-block mt-1">${anomaly.description}</small>` : ''}
            </div>
        `;
    }).join('');
}

function updateMLStatus(mlAvailable, mlStats) {
    const mlBadge = document.getElementById('ml-status-badge');
    const mlThreatsCount = document.getElementById('ml-threats-count');
    
    if (mlBadge) {
        if (mlAvailable && mlStats) {
            const threats = mlStats.total_threats || 0;
            if (threats > 0) {
                mlBadge.className = 'badge bg-danger ms-2';
                mlBadge.textContent = `ML: ${threats} threats`;
            } else {
                mlBadge.className = 'badge bg-success ms-2';
                mlBadge.textContent = 'ML Active';
            }
        } else if (mlAvailable) {
            mlBadge.className = 'badge bg-warning ms-2';
            mlBadge.textContent = 'ML Loading...';
        } else {
            mlBadge.className = 'badge bg-secondary ms-2';
            mlBadge.textContent = 'ML Disabled';
        }
    }
    
    if (mlThreatsCount) {
        const threats = mlStats?.total_threats || 0;
        mlThreatsCount.textContent = threats;
        
        if (threats > 10) {
            mlThreatsCount.className = 'card-title text-danger';
        } else if (threats > 0) {
            mlThreatsCount.className = 'card-title text-warning';
        } else {
            mlThreatsCount.className = 'card-title text-success';
        }
    }
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
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
