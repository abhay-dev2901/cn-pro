"""
Packet Capture Module - Handles real-time packet capture using Scapy
"""

from scapy.all import sniff, get_if_list
from scapy.error import Scapy_Exception
import threading
import queue
from packet_analyzer import PacketAnalyzer
from anomaly_detector import AnomalyDetector


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
            
            # Check for anomalies
            anomaly = self.detector.detect_port_scan(packet_info)
            if anomaly:
                self.anomalies.append(anomaly)
                print(f"Anomaly detected: {anomaly['type']} from {anomaly['source_ip']}")
                # Keep only last 100 anomalies
                if len(self.anomalies) > 100:
                    self.anomalies.pop(0)
            
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
    
    def get_stats(self):
        """Get current statistics"""
        return self.analyzer.get_stats()
    
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

