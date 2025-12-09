"""
ML-Enhanced Anomaly Detector
Combines rule-based detection with ML-based threat classification
"""

import os
import sys
from collections import defaultdict
from datetime import datetime
import time
from typing import Dict, List, Optional

# Import existing anomaly detector
from anomaly_detector import AnomalyDetector

# Try to import ML module
ML_AVAILABLE = False
try:
    from ml.flask_integration import MLThreatDetector, get_detector
    ML_AVAILABLE = True
except ImportError:
    print("ML module not available. Using rule-based detection only.")


class MLAnomalyDetector:
    """
    Enhanced anomaly detector with ML-based threat detection
    Falls back to rule-based detection if ML model is not available
    """
    
    def __init__(self, use_ml: bool = True):
        """
        Initialize the detector
        
        Args:
            use_ml: Whether to use ML-based detection (if available)
        """
        # Rule-based detector (always available)
        self.rule_detector = AnomalyDetector()
        
        # ML detector (optional)
        self.ml_detector: Optional[MLThreatDetector] = None
        self.use_ml = use_ml and ML_AVAILABLE
        
        if self.use_ml:
            try:
                self.ml_detector = get_detector()
                if not self.ml_detector.is_ready:
                    print("ML model not trained. Using rule-based detection.")
                    self.use_ml = False
            except Exception as e:
                print(f"Could not initialize ML detector: {e}")
                self.use_ml = False
        
        # Detection history
        self.anomalies: List[Dict] = []
        self.max_history = 100
        
        # Flow tracking for ML features
        self.flow_tracker = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'start_time': None,
            'last_time': None,
            'dst_ports': set(),
            'flags': defaultdict(int)
        })
    
    @property
    def ml_available(self) -> bool:
        """Check if ML detection is available and ready"""
        return self.use_ml and self.ml_detector is not None and self.ml_detector.is_ready
    
    def reset(self):
        """Reset all detection state"""
        self.rule_detector.reset()
        self.anomalies.clear()
        self.flow_tracker.clear()
        if self.ml_detector:
            self.ml_detector.reset_statistics()
    
    def analyze_packet(self, packet_info: Dict) -> Optional[Dict]:
        """
        Analyze a packet for anomalies using both rule-based and ML detection
        
        Args:
            packet_info: Packet information dictionary from PacketAnalyzer
            
        Returns:
            Anomaly dictionary if detected, None otherwise
        """
        anomaly = None
        
        # Update flow tracking
        flow_features = self._update_flow(packet_info)
        
        # 1. Rule-based detection (port scan)
        rule_anomaly = self.rule_detector.detect_port_scan(packet_info)
        if rule_anomaly:
            anomaly = rule_anomaly
            anomaly['detection_method'] = 'rule-based'
        
        # 2. ML-based detection
        if self.ml_available and flow_features:
            try:
                ml_result = self.ml_detector.analyze_packet(flow_features)
                
                if ml_result.get('is_threat', False):
                    # Only report if high confidence or rule-based also detected
                    if ml_result.get('confidence', 0) > 0.7 or anomaly is not None:
                        ml_anomaly = {
                            'type': ml_result['prediction'],
                            'source_ip': packet_info.get('src_ip', 'Unknown'),
                            'destination_ip': packet_info.get('dst_ip', 'Unknown'),
                            'destination_port': packet_info.get('dst_port'),
                            'confidence': ml_result['confidence'],
                            'severity': self._severity_to_text(ml_result['severity']),
                            'description': ml_result['description'],
                            'timestamp': datetime.now().isoformat(),
                            'detection_method': 'ml'
                        }
                        
                        # If both detected, merge info
                        if anomaly:
                            anomaly['ml_prediction'] = ml_result['prediction']
                            anomaly['ml_confidence'] = ml_result['confidence']
                            anomaly['detection_method'] = 'hybrid'
                        else:
                            anomaly = ml_anomaly
            except Exception as e:
                # Silently fail ML detection, fall back to rule-based
                pass
        
        # Store anomaly if detected
        if anomaly:
            self.anomalies.append(anomaly)
            if len(self.anomalies) > self.max_history:
                self.anomalies.pop(0)
        
        return anomaly
    
    def _update_flow(self, packet_info: Dict) -> Dict:
        """
        Update flow tracking and return features for ML
        """
        src_ip = packet_info.get('src_ip', 'Unknown')
        dst_ip = packet_info.get('dst_ip', 'Unknown')
        
        if src_ip == 'Unknown':
            return {}
        
        flow_key = f"{src_ip}->{dst_ip}"
        current_time = time.time()
        
        flow = self.flow_tracker[flow_key]
        
        # Initialize or update
        if flow['start_time'] is None:
            flow['start_time'] = current_time
        
        flow['packets'] += 1
        flow['bytes'] += packet_info.get('size', 0)
        flow['last_time'] = current_time
        
        if packet_info.get('dst_port'):
            flow['dst_ports'].add(packet_info['dst_port'])
        
        # Track flags
        flags = packet_info.get('flags')
        if flags:
            flags_str = str(flags)
            if 'S' in flags_str:
                flow['flags']['syn'] += 1
            if 'A' in flags_str:
                flow['flags']['ack'] += 1
            if 'F' in flags_str:
                flow['flags']['fin'] += 1
            if 'R' in flags_str:
                flow['flags']['rst'] += 1
            if 'P' in flags_str:
                flow['flags']['psh'] += 1
        
        # Calculate features for ML
        duration = (flow['last_time'] - flow['start_time']) * 1000000  # microseconds
        
        features = {
            'destination_port': packet_info.get('dst_port', 0) or 0,
            'flow_duration': duration,
            'total_fwd_packets': flow['packets'],
            'total_length_fwd_packets': flow['bytes'],
            'fwd_packet_length_mean': flow['bytes'] / flow['packets'] if flow['packets'] > 0 else 0,
            'flow_bytes_per_s': flow['bytes'] / (duration / 1000000) if duration > 0 else 0,
            'flow_packets_per_s': flow['packets'] / (duration / 1000000) if duration > 0 else 0,
            'syn_flag_count': flow['flags']['syn'],
            'ack_flag_count': flow['flags']['ack'],
            'fin_flag_count': flow['flags']['fin'],
            'rst_flag_count': flow['flags']['rst'],
            'psh_flag_count': flow['flags']['psh'],
            'min_packet_length': packet_info.get('size', 0),
            'max_packet_length': packet_info.get('size', 0),
            'packet_length_mean': packet_info.get('size', 0),
            'init_win_bytes_forward': 65535,  # Default TCP window
        }
        
        return features
    
    def _severity_to_text(self, severity: int) -> str:
        """Convert numeric severity to text"""
        if severity <= 1:
            return 'Low'
        elif severity <= 2:
            return 'Medium'
        elif severity <= 3:
            return 'High'
        else:
            return 'Critical'
    
    def get_anomalies(self, limit: int = 20) -> List[Dict]:
        """Get recent anomalies"""
        return self.anomalies[-limit:]
    
    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        stats = {
            'rule_based': {
                'active_suspects': self.rule_detector.get_active_suspects()
            },
            'total_anomalies': len(self.anomalies),
            'ml_available': self.ml_available
        }
        
        if self.ml_available:
            stats['ml'] = self.ml_detector.get_statistics()
        
        return stats


# Factory function
def create_detector(use_ml: bool = True) -> MLAnomalyDetector:
    """Create an anomaly detector instance"""
    return MLAnomalyDetector(use_ml=use_ml)


if __name__ == "__main__":
    # Test the detector
    print("Testing ML-Enhanced Anomaly Detector...")
    
    detector = create_detector()
    
    print(f"\nML Available: {detector.ml_available}")
    
    # Simulate some packets
    test_packets = [
        {'src_ip': '192.168.1.100', 'dst_ip': '10.0.0.1', 'dst_port': 22, 'size': 64, 'flags': 'S'},
        {'src_ip': '192.168.1.100', 'dst_ip': '10.0.0.1', 'dst_port': 23, 'size': 64, 'flags': 'S'},
        {'src_ip': '192.168.1.100', 'dst_ip': '10.0.0.1', 'dst_port': 80, 'size': 1500, 'flags': 'SA'},
        {'src_ip': '192.168.1.100', 'dst_ip': '10.0.0.1', 'dst_port': 443, 'size': 1500, 'flags': 'A'},
    ]
    
    for packet in test_packets:
        result = detector.analyze_packet(packet)
        if result:
            print(f"\nAnomaly Detected: {result}")
    
    print(f"\nStatistics: {detector.get_statistics()}")
