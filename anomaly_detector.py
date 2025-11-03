"""
Anomaly Detector - Detects suspicious network activity
Implements port scan detection
"""

from collections import defaultdict
from datetime import datetime, timedelta
import time


class AnomalyDetector:
    def __init__(self):
        self.port_scan_threshold = 10  # Ports per host per time window
        self.time_window = 5  # seconds
        self.scan_suspects = defaultdict(lambda: {'ports': set(), 'first_seen': None, 'last_seen': None})
        
    def reset(self):
        """Reset all detection state"""
        self.scan_suspects.clear()
        
    def detect_port_scan(self, packet_info):
        """
        Detect potential port scans
        Returns anomaly info if detected, None otherwise
        """
        if packet_info['dst_port'] is None or packet_info['src_ip'] == 'Unknown':
            return None
            
        current_time = time.time()
        src_ip = packet_info['src_ip']
        dst_port = packet_info['dst_port']
        
        # Initialize or update suspect entry
        if src_ip not in self.scan_suspects:
            self.scan_suspects[src_ip]['first_seen'] = current_time
            
        suspect = self.scan_suspects[src_ip]
        suspect['ports'].add(dst_port)
        suspect['last_seen'] = current_time
        
        # Clean old entries (outside time window)
        elapsed = current_time - suspect['first_seen']
        if elapsed > self.time_window:
            # Check if this looks like a scan
            if len(suspect['ports']) >= self.port_scan_threshold:
                # Port scan detected!
                anomaly = {
                    'type': 'Port Scan',
                    'source_ip': src_ip,
                    'ports_scanned': len(suspect['ports']),
                    'ports': list(suspect['ports'])[:20],  # Limit to first 20
                    'duration': round(elapsed, 2),
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'High' if len(suspect['ports']) > 20 else 'Medium'
                }
                # Remove this suspect after detection
                del self.scan_suspects[src_ip]
                return anomaly
            
            # Reset if time window expired without detection
            self.scan_suspects[src_ip] = {'ports': {dst_port}, 'first_seen': current_time, 'last_seen': current_time}
        
        return None
    
    def get_active_suspects(self):
        """Get currently active scan suspects"""
        current_time = time.time()
        active = []
        
        for ip, suspect in list(self.scan_suspects.items()):
            if current_time - suspect['first_seen'] < self.time_window:
                active.append({
                    'source_ip': ip,
                    'ports_scanned': len(suspect['ports']),
                    'time_elapsed': round(current_time - suspect['first_seen'], 2)
                })
        
        return active

