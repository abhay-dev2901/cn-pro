#!/usr/bin/env python3
"""
Attack Traffic Generator
Generates network packets for testing the threat detection system
"""

import socket
import time
import random
import threading
import sys

def syn_flood(target_ip, target_port, count=100):
    """Send SYN packets without completing handshake"""
    print(f"Starting SYN Flood to {target_ip}:{target_port} ({count} packets)")
    
    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            s.settimeout(0.1)
            try:
                s.connect((target_ip, target_port))
            except (socket.timeout, BlockingIOError, ConnectionRefusedError):
                pass
            s.close()
        except Exception as e:
            pass
        
        if i % 20 == 0:
            print(f"  Sent {i}/{count} SYN packets...")
        time.sleep(0.01)
    
    print(f"SYN Flood complete - {count} packets sent")


def port_scan(target_ip, start_port=1, end_port=100):
    """Probe multiple ports rapidly"""
    print(f"Starting Port Scan on {target_ip} (ports {start_port}-{end_port})")
    
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
        
        if port % 20 == 0:
            print(f"  Scanned ports {start_port}-{port}...")
    
    print(f"Port Scan complete - Found {len(open_ports)} open ports: {open_ports}")


def ssh_brute_force(target_ip, attempts=20):
    """Multiple connection attempts to SSH port"""
    print(f"Starting SSH Brute Force to {target_ip}:22 ({attempts} attempts)")
    
    for i in range(attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target_ip, 22))
            # Send some data to simulate login attempt
            s.send(b"SSH-2.0-OpenSSH_8.0\r\n")
            try:
                s.recv(1024)
            except:
                pass
            s.close()
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        
        if i % 5 == 0:
            print(f"  Attempt {i}/{attempts}...")
        time.sleep(0.2)
    
    print(f"SSH Brute Force complete - {attempts} attempts")


def http_flood(target_ip, target_port=8080, count=50):
    """Send rapid HTTP requests"""
    print(f"Starting HTTP Flood to {target_ip}:{target_port} ({count} requests)")
    
    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target_ip, target_port))
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
            s.send(request.encode())
            try:
                s.recv(4096)
            except:
                pass
            s.close()
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        
        if i % 10 == 0:
            print(f"  Sent {i}/{count} HTTP requests...")
        time.sleep(0.05)
    
    print(f"HTTP Flood complete - {count} requests sent")


def ftp_brute_force(target_ip, attempts=10):
    """Multiple connection attempts to FTP port"""
    print(f"Starting FTP Brute Force to {target_ip}:21 ({attempts} attempts)")
    
    for i in range(attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target_ip, 21))
            s.send(b"USER admin\r\n")
            try:
                s.recv(1024)
            except:
                pass
            s.close()
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        
        time.sleep(0.2)
    
    print(f"FTP Brute Force complete - {attempts} attempts")


def udp_flood(target_ip, target_port=53, count=100):
    """Send many UDP packets"""
    print(f"Starting UDP Flood to {target_ip}:{target_port} ({count} packets)")
    
    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Random payload
            payload = bytes([random.randint(0, 255) for _ in range(64)])
            s.sendto(payload, (target_ip, target_port))
            s.close()
        except:
            pass
        
        if i % 20 == 0:
            print(f"  Sent {i}/{count} UDP packets...")
        time.sleep(0.01)
    
    print(f"UDP Flood complete - {count} packets sent")


def run_all_attacks(target_ip):
    """Run all attack simulations"""
    print("\n" + "="*60)
    print("  ATTACK TRAFFIC GENERATOR")
    print("  Target:", target_ip)
    print("  Make sure packet capture is running!")
    print("="*60 + "\n")
    
    attacks = [
        ("SYN Flood (DoS/DDoS)", lambda: syn_flood(target_ip, 80, 100)),
        ("Port Scan", lambda: port_scan(target_ip, 1, 100)),
        ("SSH Brute Force", lambda: ssh_brute_force(target_ip, 20)),
        ("HTTP Flood (DoS)", lambda: http_flood(target_ip, 8080, 50)),
        ("UDP Flood", lambda: udp_flood(target_ip, 53, 100)),
    ]
    
    for name, attack_func in attacks:
        print(f"\n--- {name} ---")
        try:
            attack_func()
        except Exception as e:
            print(f"  Error: {e}")
        time.sleep(1)
    
    print("\n" + "="*60)
    print("  ALL ATTACKS COMPLETE")
    print("  Check the dashboard for detected threats")
    print("="*60 + "\n")


if __name__ == "__main__":
    # Default target is localhost
    target = "127.0.0.1"
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help":
            print("""
Attack Traffic Generator

Usage:
    python generate_attacks.py [target_ip] [attack_type]

Attack types:
    all         - Run all attacks (default)
    syn         - SYN Flood
    portscan    - Port Scan
    ssh         - SSH Brute Force
    http        - HTTP Flood
    ftp         - FTP Brute Force
    udp         - UDP Flood

Examples:
    python generate_attacks.py                    # All attacks to localhost
    python generate_attacks.py 192.168.1.1       # All attacks to specific IP
    python generate_attacks.py 127.0.0.1 syn     # SYN flood to localhost
    python generate_attacks.py 127.0.0.1 portscan # Port scan localhost
""")
            sys.exit(0)
        target = sys.argv[1]
    
    attack_type = sys.argv[2] if len(sys.argv) > 2 else "all"
    
    print(f"\nTarget: {target}")
    print(f"Attack: {attack_type}")
    print("Make sure the Network Traffic Analyzer is capturing\n")
    
    if attack_type == "all":
        run_all_attacks(target)
    elif attack_type == "syn":
        syn_flood(target, 80, 100)
    elif attack_type == "portscan":
        port_scan(target, 1, 100)
    elif attack_type == "ssh":
        ssh_brute_force(target, 20)
    elif attack_type == "http":
        http_flood(target, 8080, 50)
    elif attack_type == "ftp":
        ftp_brute_force(target, 10)
    elif attack_type == "udp":
        udp_flood(target, 53, 100)
    else:
        print(f"Unknown attack type: {attack_type}")
        print("Use --help for usage information")
