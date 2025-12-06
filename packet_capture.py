"""
Packet Capture Module - Handles real-time packet capture using Scapy
"""

from scapy.all import sniff, get_if_list
from scapy.error import Scapy_Exception
import threading
import queue
import time
from collections import defaultdict
from packet_analyzer import PacketAnalyzer
from anomaly_detector import AnomalyDetector

# ML Integration
try:
    from ml.flask_integration import get_detector
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


class PacketCapture:
    def __init__(self):
        self.is_capturing = False
        self.analyzer = PacketAnalyzer()
        self.detector = AnomalyDetector()
        self.capture_thread = None
        self.packet_queue = queue.Queue()
        self.filter_string = None
        self.interface = None
        self.anomalies = []
        self.stored_packets = []  # Store raw packets for PCAP export
        self.max_stored_packets = 10000  # Limit stored packets to prevent memory issues
        self.last_error = None  # Store last error message
        
        # ML Integration
        self.ml_detector = None
        self.use_ml = ML_AVAILABLE
        if ML_AVAILABLE:
            try:
                self.ml_detector = get_detector()
                if self.ml_detector.is_ready:
                    print("✅ ML threat detection enabled")
                else:
                    print("⚠️ ML model not loaded - using rule-based detection only")
                    self.use_ml = False
            except Exception as e:
                print(f"⚠️ ML initialization failed: {e}")
                self.use_ml = False
        
        # Flow tracking for ML features
        self.flow_tracker = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'fwd_packets': 0,
            'bwd_packets': 0,
            'start_time': None,
            'last_time': None,
            'flags': defaultdict(int),
            'dst_ports': set()
        })
        
    def get_interfaces(self):
        """Get list of available network interfaces"""
        return get_if_list()
    
    def set_interface(self, interface):
        """Set the network interface to capture on"""
        # Convert empty string to None (auto-detect)
        self.interface = interface if interface and interface.strip() else None
        
    def set_filter(self, filter_string):
        """Set BPF filter string"""
        # Convert empty string to None (no filter)
        self.filter_string = filter_string if filter_string and filter_string.strip() else None
        
    def start_capture(self):
        """Start packet capture in a separate thread"""
        if self.is_capturing:
            return False
            
        self.is_capturing = True
        self.analyzer.reset_stats()
        self.detector.reset()
        self.anomalies.clear()
        self.stored_packets.clear()
        self.last_error = None  # Clear previous errors
        self.flow_tracker.clear()  # Reset flow tracking
        
        # Reset ML detector statistics
        if self.use_ml and self.ml_detector:
            self.ml_detector.reset_statistics()
        
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        return True
        
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
            
    def _capture_loop(self):
        """Main capture loop running in separate thread"""
        try:
            print(f"Starting capture on interface: {self.interface or 'auto-detect'}, filter: {self.filter_string or 'none'}")
            # Store packets for PCAP export (limited to prevent memory issues)
            sniff(
                iface=self.interface if self.interface else None,
                prn=self._process_packet,
                filter=self.filter_string,
                stop_filter=lambda x: not self.is_capturing,
                store=False  # Process immediately, store manually
            )
        except (PermissionError, Scapy_Exception) as e:
            error_msg = str(e)
            if "Permission denied" in error_msg or "root" in error_msg.lower():
                error_msg = "Permission denied: Root privileges required for packet capture. Please run with 'sudo python app.py'"
            print(f"Capture permission error: {error_msg}")
            self.is_capturing = False
            self.last_error = error_msg
        except OSError as e:
            error_msg = f"OS error (may need root privileges): {e}"
            print(f"Capture OS error: {error_msg}")
            self.is_capturing = False
            self.last_error = error_msg
        except Exception as e:
            error_msg = f"Capture error: {e}"
            print(error_msg)
            import traceback
            traceback.print_exc()
            self.is_capturing = False
            self.last_error = error_msg
            
    def _process_packet(self, packet):
        """Process each captured packet"""
        if not self.is_capturing:
            return
            
        try:
            # Store raw packet for PCAP export (limited buffer)
            if len(self.stored_packets) < self.max_stored_packets:
                self.stored_packets.append(packet)
            else:
                # Remove oldest packet (FIFO)
                self.stored_packets.pop(0)
                self.stored_packets.append(packet)
            
            # Analyze packet
            packet_info = self.analyzer.parse_packet(packet)
            
            # Debug: Print first few packets
            if self.analyzer.total_packets <= 3:
                print(f"Captured packet #{self.analyzer.total_packets}: {packet_info.get('protocol', 'Unknown')} from {packet_info.get('src_ip', '?')} to {packet_info.get('dst_ip', '?')}")
            
            # Check for anomalies (rule-based)
            anomaly = self.detector.detect_port_scan(packet_info)
            if anomaly:
                anomaly['detection_method'] = 'rule-based'
                self.anomalies.append(anomaly)
                print(f"🔍 Rule-based anomaly: {anomaly['type']} from {anomaly['source_ip']}")
            
            # ML-based threat detection
            if self.use_ml and self.ml_detector and self.ml_detector.is_ready:
                ml_features = self._extract_ml_features(packet_info)
                if ml_features:
                    ml_result = self.ml_detector.analyze_packet(ml_features)
                    
                    # Report high-confidence threats
                    if ml_result.get('is_threat') and ml_result.get('confidence', 0) > 0.75:
                        ml_anomaly = {
                            'type': f"ML: {ml_result['prediction']}",
                            'source_ip': packet_info.get('src_ip', 'Unknown'),
                            'destination_ip': packet_info.get('dst_ip', 'Unknown'),
                            'destination_port': packet_info.get('dst_port'),
                            'confidence': round(ml_result['confidence'], 2),
                            'severity': ml_result.get('severity', 'Medium'),
                            'description': ml_result.get('description', ''),
                            'timestamp': packet_info.get('timestamp'),
                            'detection_method': 'ml'
                        }
                        self.anomalies.append(ml_anomaly)
                        
                        # Only print significant threats
                        if ml_result['confidence'] > 0.9:
                            print(f"🤖 ML threat detected: {ml_result['prediction']} (confidence: {ml_result['confidence']:.2f})")
            
            # Keep only last 100 anomalies
            if len(self.anomalies) > 100:
                self.anomalies = self.anomalies[-100:]
            
            # Queue for potential export
            try:
                self.packet_queue.put_nowait(packet_info)
            except queue.Full:
                # Remove oldest if queue is full
                try:
                    self.packet_queue.get_nowait()
                except queue.Empty:
                    pass
                self.packet_queue.put_nowait(packet_info)
                
        except Exception as e:
            print(f"Packet processing error: {e}")
            import traceback
            traceback.print_exc()
    
    def _extract_ml_features(self, packet_info):
        """Extract ML features from packet info and flow tracking"""
        src_ip = packet_info.get('src_ip', 'Unknown')
        dst_ip = packet_info.get('dst_ip', 'Unknown')
        
        if src_ip == 'Unknown':
            return None
        
        flow_key = f"{src_ip}->{dst_ip}"
        current_time = time.time()
        
        flow = self.flow_tracker[flow_key]
        
        # Initialize or update flow
        if flow['start_time'] is None:
            flow['start_time'] = current_time
        
        flow['packets'] += 1
        flow['fwd_packets'] += 1
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
        
        # Calculate duration in microseconds
        duration = (flow['last_time'] - flow['start_time']) * 1000000
        
        # Build ML features
        features = {
            'destination_port': packet_info.get('dst_port', 0) or 0,
            'flow_duration': duration,
            'total_fwd_packets': flow['fwd_packets'],
            'total_bwd_packets': flow['bwd_packets'],
            'total_length_fwd_packets': flow['bytes'],
            'fwd_packet_length_mean': flow['bytes'] / flow['packets'] if flow['packets'] > 0 else 0,
            'fwd_packet_length_max': packet_info.get('size', 0),
            'fwd_packet_length_min': packet_info.get('size', 0),
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
            'average_packet_size': packet_info.get('size', 0),
            'init_win_bytes_forward': 65535,
            'fwd_header_length': 20,
        }
        
        return features
    
    def get_stats(self):
        """Get current statistics"""
        stats = self.analyzer.get_stats()
        
        # Add ML statistics
        stats['ml_enabled'] = self.use_ml and self.ml_detector is not None
        if self.use_ml and self.ml_detector and self.ml_detector.is_ready:
            ml_stats = self.ml_detector.get_statistics()
            stats['ml_threats_detected'] = ml_stats.get('total_threats', 0)
            stats['ml_threat_breakdown'] = ml_stats.get('threat_breakdown', {})
        
        return stats
    
    def get_recent_packets(self, limit=50):
        """Get recent packets"""
        return self.analyzer.get_recent_packets(limit)
    
    def get_anomalies(self, limit=20):
        """Get detected anomalies"""
        return self.anomalies[-limit:]
    
    def get_packet_queue(self):
        """Get packets from queue (for export)"""
        packets = []
        while not self.packet_queue.empty():
            try:
                packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets
    
    def get_stored_packets(self):
        """Get stored raw packets for PCAP export"""
        return self.stored_packets.copy()
    
    def get_last_error(self):
        """Get last error message if any"""
        return self.last_error
    
    def clear_error(self):
        """Clear last error message"""
        self.last_error = None

