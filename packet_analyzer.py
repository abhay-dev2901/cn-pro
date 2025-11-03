"""
Packet Analyzer - Parses and analyzes network packets
Supports TCP, UDP, HTTP, DNS protocols
"""

from scapy.all import IP, TCP, UDP, DNS, Raw, sniff
from collections import defaultdict
import time
from datetime import datetime


class PacketAnalyzer:
    def __init__(self):
        self.protocol_stats = defaultdict(int)
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_distribution = defaultdict(int)
        self.port_activity = defaultdict(int)
        self.start_time = None
        self.packet_buffer = []
        self.max_buffer_size = 1000
        
    def reset_stats(self):
        """Reset all statistics"""
        self.protocol_stats.clear()
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_distribution.clear()
        self.port_activity.clear()
        self.start_time = time.time()
        self.packet_buffer.clear()
        
    def parse_packet(self, packet):
        """Parse a single packet and extract information"""
        if self.start_time is None:
            self.start_time = time.time()
            
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'protocol': 'Unknown',
            'src_ip': 'Unknown',
            'dst_ip': 'Unknown',
            'src_port': None,
            'dst_port': None,
            'size': len(packet),
            'flags': None,
            'dns_query': None,
            'http_method': None,
            'http_host': None
        }
        
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['size'] = len(packet[IP])
            
            # TCP Analysis
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = packet[TCP].flags
                
                # HTTP Detection
                if Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if 'HTTP' in payload:
                        packet_info['protocol'] = 'HTTP'
                        lines = payload.split('\n')
                        for line in lines[:10]:  # Check first 10 lines
                            if line.startswith('GET') or line.startswith('POST') or \
                               line.startswith('PUT') or line.startswith('DELETE'):
                                packet_info['http_method'] = line.split()[0]
                                break
                            if line.startswith('Host:'):
                                packet_info['http_host'] = line.split(':', 1)[1].strip()
                
                self.port_activity[packet_info['dst_port']] += 1
                
            # UDP Analysis
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                
                # DNS Detection
                if DNS in packet:
                    packet_info['protocol'] = 'DNS'
                    if packet[DNS].qr == 0:  # Query
                        if packet[DNS].qd:
                            packet_info['dns_query'] = packet[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                    self.port_activity[53] += 1
                else:
                    self.port_activity[packet_info['dst_port']] += 1
                    
        # Update statistics
        self.total_packets += 1
        self.total_bytes += packet_info['size']
        self.protocol_distribution[packet_info['protocol']] += 1
        
        # Store in buffer (limit size)
        self.packet_buffer.append(packet_info)
        if len(self.packet_buffer) > self.max_buffer_size:
            self.packet_buffer.pop(0)
            
        return packet_info
    
    def get_stats(self):
        """Get current statistics"""
        elapsed_time = time.time() - self.start_time if self.start_time else 1
        
        # Calculate throughput
        throughput = self.total_bytes / elapsed_time if elapsed_time > 0 else 0  # bytes per second
        throughput_mbps = (throughput * 8) / (1024 * 1024)  # Mbps
        
        # Packets per second
        pps = self.total_packets / elapsed_time if elapsed_time > 0 else 0
        
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'throughput_mbps': round(throughput_mbps, 2),
            'throughput_bps': round(throughput, 2),
            'packets_per_second': round(pps, 2),
            'protocol_distribution': dict(self.protocol_distribution),
            'port_activity': dict(sorted(self.port_activity.items(), key=lambda x: x[1], reverse=True)[:20]),
            'elapsed_time': round(elapsed_time, 2)
        }
    
    def get_recent_packets(self, limit=50):
        """Get most recent packets"""
        return self.packet_buffer[-limit:]

