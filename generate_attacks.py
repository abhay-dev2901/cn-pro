#!/usr/bin/env python3
"""
Attack Traffic Generator
Simulates network attacks by sending attack patterns to the ML API
"""

import requests
import time
import random
import sys

# Default server URL
DEFAULT_SERVER = "http://127.0.0.1:8080"


def simulate_syn_flood(server_url, count=10):
    """Simulate SYN Flood attack"""
    print(f"Simulating SYN Flood ({count} attacks)...")
    
    for i in range(count):
        attack_data = {
            'source_ip': f'192.168.1.{random.randint(1, 254)}',
            'destination_ip': '10.0.0.1',
            'destination_port': 80,
            'total_fwd_packets': random.randint(50, 150),
            'total_bwd_packets': random.randint(0, 5),
            'syn_flag_count': random.randint(30, 100),
            'ack_flag_count': random.randint(0, 5),
            'flow_packets_per_s': random.randint(100, 500),
            'flow_bytes_per_s': random.randint(50000, 200000)
        }
        
        try:
            response = requests.post(f"{server_url}/api/ml/simulate", json=attack_data, timeout=5)
            result = response.json()
            if result.get('is_threat'):
                print(f"  [{i+1}/{count}] Detected: {result['prediction']} (confidence: {result['confidence']:.2f})")
        except Exception as e:
            print(f"  Error: {e}")
        
        time.sleep(0.2)
    
    print("SYN Flood simulation complete\n")


def simulate_http_flood(server_url, count=10):
    """Simulate HTTP Flood attack"""
    print(f"Simulating HTTP Flood ({count} attacks)...")
    
    for i in range(count):
        attack_data = {
            'source_ip': f'10.0.0.{random.randint(1, 254)}',
            'destination_ip': '10.0.0.1',
            'destination_port': random.choice([80, 443, 8080]),
            'total_fwd_packets': random.randint(40, 100),
            'total_bwd_packets': random.randint(20, 50),
            'psh_flag_count': random.randint(30, 80),
            'ack_flag_count': random.randint(30, 80),
            'flow_packets_per_s': random.randint(20, 100),
            'flow_bytes_per_s': random.randint(100000, 500000)
        }
        
        try:
            response = requests.post(f"{server_url}/api/ml/simulate", json=attack_data, timeout=5)
            result = response.json()
            if result.get('is_threat'):
                print(f"  [{i+1}/{count}] Detected: {result['prediction']} (confidence: {result['confidence']:.2f})")
        except Exception as e:
            print(f"  Error: {e}")
        
        time.sleep(0.2)
    
    print("HTTP Flood simulation complete\n")


def simulate_ssh_brute_force(server_url, count=10):
    """Simulate SSH Brute Force attack"""
    print(f"Simulating SSH Brute Force ({count} attacks)...")
    
    for i in range(count):
        attack_data = {
            'source_ip': f'172.16.0.{random.randint(1, 254)}',
            'destination_ip': '10.0.0.1',
            'destination_port': 22,
            'total_fwd_packets': random.randint(20, 50),
            'total_bwd_packets': random.randint(15, 40),
            'psh_flag_count': random.randint(15, 40),
            'ack_flag_count': random.randint(15, 40),
            'syn_flag_count': random.randint(5, 15),
            'flow_packets_per_s': random.randint(10, 50)
        }
        
        try:
            response = requests.post(f"{server_url}/api/ml/simulate", json=attack_data, timeout=5)
            result = response.json()
            if result.get('is_threat'):
                print(f"  [{i+1}/{count}] Detected: {result['prediction']} (confidence: {result['confidence']:.2f})")
        except Exception as e:
            print(f"  Error: {e}")
        
        time.sleep(0.2)
    
    print("SSH Brute Force simulation complete\n")


def simulate_ftp_brute_force(server_url, count=5):
    """Simulate FTP Brute Force attack"""
    print(f"Simulating FTP Brute Force ({count} attacks)...")
    
    for i in range(count):
        attack_data = {
            'source_ip': f'192.168.2.{random.randint(1, 254)}',
            'destination_ip': '10.0.0.1',
            'destination_port': 21,
            'total_fwd_packets': random.randint(10, 30),
            'total_bwd_packets': random.randint(8, 25),
            'psh_flag_count': random.randint(8, 20),
            'ack_flag_count': random.randint(8, 20),
            'syn_flag_count': random.randint(3, 10),
            'flow_packets_per_s': random.randint(5, 30)
        }
        
        try:
            response = requests.post(f"{server_url}/api/ml/simulate", json=attack_data, timeout=5)
            result = response.json()
            if result.get('is_threat'):
                print(f"  [{i+1}/{count}] Detected: {result['prediction']} (confidence: {result['confidence']:.2f})")
        except Exception as e:
            print(f"  Error: {e}")
        
        time.sleep(0.2)
    
    print("FTP Brute Force simulation complete\n")


def simulate_port_scan(server_url, count=10):
    """Simulate Port Scan attack"""
    print(f"Simulating Port Scan ({count} attacks)...")
    
    for i in range(count):
        attack_data = {
            'source_ip': f'10.10.10.{random.randint(1, 254)}',
            'destination_ip': '10.0.0.1',
            'destination_port': random.randint(1, 1024),
            'total_fwd_packets': random.randint(50, 150),
            'total_bwd_packets': random.randint(10, 50),
            'syn_flag_count': random.randint(40, 100),
            'ack_flag_count': random.randint(0, 10),
            'rst_flag_count': random.randint(15, 50),
            'flow_packets_per_s': random.randint(50, 200)
        }
        
        try:
            response = requests.post(f"{server_url}/api/ml/simulate", json=attack_data, timeout=5)
            result = response.json()
            if result.get('is_threat'):
                print(f"  [{i+1}/{count}] Detected: {result['prediction']} (confidence: {result['confidence']:.2f})")
        except Exception as e:
            print(f"  Error: {e}")
        
        time.sleep(0.2)
    
    print("Port Scan simulation complete\n")


def simulate_ddos(server_url, count=10):
    """Simulate DDoS attack"""
    print(f"Simulating DDoS ({count} attacks)...")
    
    for i in range(count):
        attack_data = {
            'source_ip': f'{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}',
            'destination_ip': '10.0.0.1',
            'destination_port': random.choice([80, 443, 8080]),
            'total_fwd_packets': random.randint(100, 500),
            'total_bwd_packets': random.randint(50, 200),
            'syn_flag_count': random.randint(50, 200),
            'ack_flag_count': random.randint(10, 50),
            'flow_packets_per_s': random.randint(100, 1000),
            'flow_bytes_per_s': random.randint(500000, 2000000)
        }
        
        try:
            response = requests.post(f"{server_url}/api/ml/simulate", json=attack_data, timeout=5)
            result = response.json()
            if result.get('is_threat'):
                print(f"  [{i+1}/{count}] Detected: {result['prediction']} (confidence: {result['confidence']:.2f})")
        except Exception as e:
            print(f"  Error: {e}")
        
        time.sleep(0.2)
    
    print("DDoS simulation complete\n")


def simulate_udp_flood(server_url, count=10):
    """Simulate UDP Flood to DNS"""
    print(f"Simulating UDP Flood ({count} attacks)...")
    
    for i in range(count):
        attack_data = {
            'source_ip': f'192.168.3.{random.randint(1, 254)}',
            'destination_ip': '10.0.0.1',
            'destination_port': 53,
            'total_fwd_packets': random.randint(60, 150),
            'total_bwd_packets': random.randint(0, 10),
            'flow_packets_per_s': random.randint(100, 500),
            'flow_bytes_per_s': random.randint(50000, 200000)
        }
        
        try:
            response = requests.post(f"{server_url}/api/ml/simulate", json=attack_data, timeout=5)
            result = response.json()
            if result.get('is_threat'):
                print(f"  [{i+1}/{count}] Detected: {result['prediction']} (confidence: {result['confidence']:.2f})")
        except Exception as e:
            print(f"  Error: {e}")
        
        time.sleep(0.2)
    
    print("UDP Flood simulation complete\n")


def run_all_attacks(server_url):
    """Run all attack simulations"""
    print("\n" + "="*60)
    print("  ATTACK SIMULATION")
    print(f"  Server: {server_url}")
    print("="*60 + "\n")
    
    simulate_syn_flood(server_url, 10)
    time.sleep(1)
    
    simulate_http_flood(server_url, 10)
    time.sleep(1)
    
    simulate_ssh_brute_force(server_url, 10)
    time.sleep(1)
    
    simulate_ftp_brute_force(server_url, 5)
    time.sleep(1)
    
    simulate_port_scan(server_url, 10)
    time.sleep(1)
    
    simulate_ddos(server_url, 10)
    time.sleep(1)
    
    simulate_udp_flood(server_url, 10)
    
    print("="*60)
    print("  ALL ATTACKS COMPLETE")
    print("  Check the dashboard for detected threats")
    print("="*60 + "\n")


if __name__ == "__main__":
    server = DEFAULT_SERVER
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help":
            print("""
Attack Simulation Tool

Usage:
    python generate_attacks.py [server_url] [attack_type]

Server URL:
    Default: http://127.0.0.1:8080
    Example: http://10.7.1.233:8080

Attack types:
    all         - Run all attacks (default)
    syn         - SYN Flood
    http        - HTTP Flood
    ssh         - SSH Brute Force
    ftp         - FTP Brute Force
    portscan    - Port Scan
    ddos        - DDoS
    udp         - UDP Flood

Examples:
    python generate_attacks.py                              # All attacks to localhost
    python generate_attacks.py http://10.7.1.233:8080      # All attacks to specific server
    python generate_attacks.py http://127.0.0.1:8080 syn   # SYN flood only
""")
            sys.exit(0)
        
        # Check if first arg is URL or attack type
        if sys.argv[1].startswith("http"):
            server = sys.argv[1]
        else:
            server = DEFAULT_SERVER
    
    attack_type = "all"
    if len(sys.argv) > 2:
        attack_type = sys.argv[2]
    elif len(sys.argv) > 1 and not sys.argv[1].startswith("http"):
        attack_type = sys.argv[1]
    
    print(f"\nServer: {server}")
    print(f"Attack: {attack_type}\n")
    
    if attack_type == "all":
        run_all_attacks(server)
    elif attack_type == "syn":
        simulate_syn_flood(server, 10)
    elif attack_type == "http":
        simulate_http_flood(server, 10)
    elif attack_type == "ssh":
        simulate_ssh_brute_force(server, 10)
    elif attack_type == "ftp":
        simulate_ftp_brute_force(server, 5)
    elif attack_type == "portscan":
        simulate_port_scan(server, 10)
    elif attack_type == "ddos":
        simulate_ddos(server, 10)
    elif attack_type == "udp":
        simulate_udp_flood(server, 10)
    else:
        print(f"Unknown attack type: {attack_type}")
        print("Use --help for usage information")
