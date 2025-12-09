#!/usr/bin/env python3
"""
Attack Simulation Script for Network Traffic Analyzer
Generates realistic attack patterns that trigger ML detection
"""

import requests
import json
import time

BASE_URL = "http://localhost:8080"

# These attack patterns are based on CICIDS2017 dataset characteristics
# The key is having the RIGHT COMBINATION of features, not just extreme values

ATTACK_PATTERNS = {
    "DDoS Attack": {
        "destination_port": 80,
        "flow_duration": 28,  # Very short duration
        "total_fwd_packets": 2,
        "total_bwd_packets": 0,
        "total_length_fwd_packets": 0,
        "total_length_bwd_packets": 0,
        "fwd_packet_length_max": 0,
        "fwd_packet_length_min": 0,
        "fwd_packet_length_mean": 0,
        "bwd_packet_length_max": 0,
        "bwd_packet_length_mean": 0,
        "flow_bytes_per_s": 0,
        "flow_packets_per_s": 71428.57,  # High packet rate
        "flow_iat_mean": 14,
        "fwd_iat_total": 14,
        "fwd_iat_mean": 14,
        "syn_flag_count": 1,
        "ack_flag_count": 0,
        "fin_flag_count": 0,
        "rst_flag_count": 0,
        "psh_flag_count": 0,
        "init_win_bytes_forward": 8192,
        "init_win_bytes_backward": 0,
        "active_mean": 0,
        "idle_mean": 0,
        "down_up_ratio": 0,
        "average_packet_size": 0
    },
    
    "DoS Hulk Attack": {
        "destination_port": 80,
        "flow_duration": 15463,
        "total_fwd_packets": 11,
        "total_bwd_packets": 9,
        "total_length_fwd_packets": 3545,
        "total_length_bwd_packets": 12106,
        "fwd_packet_length_max": 758,
        "fwd_packet_length_min": 0,
        "fwd_packet_length_mean": 322.27,
        "bwd_packet_length_max": 1420,
        "bwd_packet_length_mean": 1345.11,
        "flow_bytes_per_s": 1011845.79,
        "flow_packets_per_s": 1293.49,
        "flow_iat_mean": 773.15,
        "fwd_iat_total": 15360,
        "fwd_iat_mean": 1536,
        "syn_flag_count": 0,
        "ack_flag_count": 0,
        "fin_flag_count": 1,
        "rst_flag_count": 0,
        "psh_flag_count": 10,
        "init_win_bytes_forward": 8192,
        "init_win_bytes_backward": 236,
        "active_mean": 0,
        "idle_mean": 0,
        "down_up_ratio": 0,
        "average_packet_size": 782.55
    },
    
    "DoS Slowloris": {
        "destination_port": 80,
        "flow_duration": 189952897,  # Very long duration
        "total_fwd_packets": 6,
        "total_bwd_packets": 4,
        "total_length_fwd_packets": 276,
        "total_length_bwd_packets": 164,
        "fwd_packet_length_max": 197,
        "fwd_packet_length_min": 0,
        "fwd_packet_length_mean": 46,
        "bwd_packet_length_max": 164,
        "bwd_packet_length_mean": 41,
        "flow_bytes_per_s": 2.32,  # Very low bytes per second
        "flow_packets_per_s": 0.05,  # Very low packets per second
        "flow_iat_mean": 21105877.44,
        "fwd_iat_total": 189919316,
        "fwd_iat_mean": 37983863.2,
        "syn_flag_count": 0,
        "ack_flag_count": 0,
        "fin_flag_count": 0,
        "rst_flag_count": 0,
        "psh_flag_count": 4,
        "init_win_bytes_forward": 229,
        "init_win_bytes_backward": 237,
        "active_mean": 57960.8,
        "idle_mean": 31606386.25,  # High idle time
        "down_up_ratio": 0,
        "average_packet_size": 44
    },
    
    "Port Scan": {
        "destination_port": 29595,
        "flow_duration": 0,  # Zero duration - quick scan
        "total_fwd_packets": 1,
        "total_bwd_packets": 1,
        "total_length_fwd_packets": 0,
        "total_length_bwd_packets": 0,
        "fwd_packet_length_max": 0,
        "fwd_packet_length_min": 0,
        "fwd_packet_length_mean": 0,
        "bwd_packet_length_max": 0,
        "bwd_packet_length_mean": 0,
        "flow_bytes_per_s": 0,
        "flow_packets_per_s": 0,
        "flow_iat_mean": 0,
        "fwd_iat_total": 0,
        "fwd_iat_mean": 0,
        "syn_flag_count": 1,
        "ack_flag_count": 1,
        "fin_flag_count": 0,
        "rst_flag_count": 1,
        "psh_flag_count": 0,
        "init_win_bytes_forward": 1024,
        "init_win_bytes_backward": 0,
        "active_mean": 0,
        "idle_mean": 0,
        "down_up_ratio": 1,
        "average_packet_size": 0
    },
    
    "SSH Brute Force (Patator)": {
        "destination_port": 22,
        "flow_duration": 8934606,
        "total_fwd_packets": 13,
        "total_bwd_packets": 16,
        "total_length_fwd_packets": 2068,
        "total_length_bwd_packets": 4596,
        "fwd_packet_length_max": 900,
        "fwd_packet_length_min": 0,
        "fwd_packet_length_mean": 159.08,
        "bwd_packet_length_max": 824,
        "bwd_packet_length_mean": 287.25,
        "flow_bytes_per_s": 745.95,
        "flow_packets_per_s": 3.25,
        "flow_iat_mean": 318378.79,
        "fwd_iat_total": 8916166,
        "fwd_iat_mean": 743013.83,
        "syn_flag_count": 0,
        "ack_flag_count": 0,
        "fin_flag_count": 1,
        "rst_flag_count": 0,
        "psh_flag_count": 18,
        "init_win_bytes_forward": 29200,
        "init_win_bytes_backward": 26883,
        "active_mean": 131979.17,
        "idle_mean": 4277099.33,
        "down_up_ratio": 1,
        "average_packet_size": 229.79
    },
    
    "FTP Brute Force (Patator)": {
        "destination_port": 21,
        "flow_duration": 5003098,
        "total_fwd_packets": 11,
        "total_bwd_packets": 10,
        "total_length_fwd_packets": 166,
        "total_length_bwd_packets": 530,
        "fwd_packet_length_max": 31,
        "fwd_packet_length_min": 0,
        "fwd_packet_length_mean": 15.09,
        "bwd_packet_length_max": 118,
        "bwd_packet_length_mean": 53,
        "flow_bytes_per_s": 139.11,
        "flow_packets_per_s": 4.2,
        "flow_iat_mean": 250154.9,
        "fwd_iat_total": 5000026,
        "fwd_iat_mean": 500002.6,
        "syn_flag_count": 0,
        "ack_flag_count": 0,
        "fin_flag_count": 1,
        "rst_flag_count": 0,
        "psh_flag_count": 10,
        "init_win_bytes_forward": 29200,
        "init_win_bytes_backward": 26883,
        "active_mean": 1582.83,
        "idle_mean": 834032.5,
        "down_up_ratio": 0,
        "average_packet_size": 33.14
    },
    
    "Web Attack - SQL Injection": {
        "destination_port": 80,
        "flow_duration": 22165,
        "total_fwd_packets": 8,
        "total_bwd_packets": 6,
        "total_length_fwd_packets": 2012,
        "total_length_bwd_packets": 6372,
        "fwd_packet_length_max": 740,
        "fwd_packet_length_min": 0,
        "fwd_packet_length_mean": 251.5,
        "bwd_packet_length_max": 1420,
        "bwd_packet_length_mean": 1062,
        "flow_bytes_per_s": 378185.8,
        "flow_packets_per_s": 631.35,
        "flow_iat_mean": 1583.21,
        "fwd_iat_total": 18996,
        "fwd_iat_mean": 2713.71,
        "syn_flag_count": 0,
        "ack_flag_count": 0,
        "fin_flag_count": 1,
        "rst_flag_count": 0,
        "psh_flag_count": 7,
        "init_win_bytes_forward": 8192,
        "init_win_bytes_backward": 229,
        "active_mean": 0,
        "idle_mean": 0,
        "down_up_ratio": 0,
        "average_packet_size": 598.86
    },
    
    "Web Attack - XSS": {
        "destination_port": 80,
        "flow_duration": 31482,
        "total_fwd_packets": 8,
        "total_bwd_packets": 6,
        "total_length_fwd_packets": 1916,
        "total_length_bwd_packets": 6372,
        "fwd_packet_length_max": 708,
        "fwd_packet_length_min": 0,
        "fwd_packet_length_mean": 239.5,
        "bwd_packet_length_max": 1420,
        "bwd_packet_length_mean": 1062,
        "flow_bytes_per_s": 263295.66,
        "flow_packets_per_s": 444.71,
        "flow_iat_mean": 2248.71,
        "fwd_iat_total": 31182,
        "fwd_iat_mean": 4454.57,
        "syn_flag_count": 0,
        "ack_flag_count": 0,
        "fin_flag_count": 1,
        "rst_flag_count": 0,
        "psh_flag_count": 7,
        "init_win_bytes_forward": 8192,
        "init_win_bytes_backward": 229,
        "active_mean": 0,
        "idle_mean": 0,
        "down_up_ratio": 0,
        "average_packet_size": 591.29
    },
    
    "Botnet Traffic": {
        "destination_port": 6667,  # IRC port common for botnets
        "flow_duration": 119989424,
        "total_fwd_packets": 6,
        "total_bwd_packets": 5,
        "total_length_fwd_packets": 270,
        "total_length_bwd_packets": 2214,
        "fwd_packet_length_max": 135,
        "fwd_packet_length_min": 0,
        "fwd_packet_length_mean": 45,
        "bwd_packet_length_max": 1410,
        "bwd_packet_length_mean": 442.8,
        "flow_bytes_per_s": 20.7,
        "flow_packets_per_s": 0.09,
        "flow_iat_mean": 11998942.4,
        "fwd_iat_total": 119968028,
        "fwd_iat_mean": 23993605.6,
        "syn_flag_count": 0,
        "ack_flag_count": 0,
        "fin_flag_count": 0,
        "rst_flag_count": 0,
        "psh_flag_count": 5,
        "init_win_bytes_forward": 8192,
        "init_win_bytes_backward": 63712,
        "active_mean": 1022.75,
        "idle_mean": 29996356,
        "down_up_ratio": 0,
        "average_packet_size": 225.82
    },
    
    "Normal Traffic (Control)": {
        "destination_port": 443,
        "flow_duration": 24576307,
        "total_fwd_packets": 15,
        "total_bwd_packets": 12,
        "total_length_fwd_packets": 1478,
        "total_length_bwd_packets": 4896,
        "fwd_packet_length_max": 517,
        "fwd_packet_length_min": 0,
        "fwd_packet_length_mean": 98.53,
        "bwd_packet_length_max": 1420,
        "bwd_packet_length_mean": 408,
        "flow_bytes_per_s": 259.42,
        "flow_packets_per_s": 1.1,
        "flow_iat_mean": 943704.12,
        "fwd_iat_total": 24568687,
        "fwd_iat_mean": 1754906.21,
        "syn_flag_count": 0,
        "ack_flag_count": 0,
        "fin_flag_count": 1,
        "rst_flag_count": 0,
        "psh_flag_count": 12,
        "init_win_bytes_forward": 65535,
        "init_win_bytes_backward": 65535,
        "active_mean": 47832.29,
        "idle_mean": 2977091.29,
        "down_up_ratio": 0,
        "average_packet_size": 236.07
    }
}


def test_attack(name, pattern):
    """Send attack pattern to ML API and display result"""
    print(f"\n{'='*60}")
    print(f"Testing: {name}")
    print('='*60)
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/ml/analyze",
            json=pattern,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            
            prediction = result.get('prediction', 'Unknown')
            confidence = result.get('confidence', 0)
            is_threat = result.get('is_threat', False)
            severity = result.get('severity', 0)
            
            # Color coding for terminal
            if is_threat:
                status = "[!] THREAT DETECTED"
            else:
                status = "[OK] Normal Traffic"
            
            print(f"\n  Status:     {status}")
            print(f"  Prediction: {prediction}")
            print(f"  Confidence: {confidence*100:.2f}%")
            print(f"  Severity:   {severity}/5")
            
            # Show probability distribution
            probs = result.get('probabilities', {})
            if probs:
                print(f"\n  Probability Distribution:")
                sorted_probs = sorted(probs.items(), key=lambda x: x[1], reverse=True)
                for label, prob in sorted_probs[:5]:  # Top 5
                    bar = '█' * int(prob * 20)
                    print(f"    {label:12}: {bar} {prob*100:.1f}%")
            
            return result
        else:
            print(f"  Error: HTTP {response.status_code}")
            print(f"     {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        print(f"  Connection Error: Is the server running at {BASE_URL}?")
        return None
    except Exception as e:
        print(f"  Error: {e}")
        return None


def run_all_tests():
    """Run all attack simulations"""
    print("\n" + "="*70)
    print("  🔬 ATTACK SIMULATION TEST SUITE")
    print("  Testing ML Threat Detection on CICIDS2017-based patterns")
    print("="*70)
    
    # Check if server is running
    try:
        response = requests.get(f"{BASE_URL}/api/ml/status", timeout=5)
        if response.status_code == 200:
            status = response.json()
            print(f"\nServer connected")
            print(f"   Model loaded: {status.get('model_loaded', False)}")
            if not status.get('model_loaded'):
                print("\nWarning: ML model not loaded!")
                print("   Run: python -m ml.training_pipeline --quick")
                return
    except:
        print(f"\nCannot connect to server at {BASE_URL}")
        print("   Start the server with: sudo python3 app.py")
        return
    
    results = []
    threat_count = 0
    normal_count = 0
    
    for name, pattern in ATTACK_PATTERNS.items():
        result = test_attack(name, pattern)
        if result:
            results.append((name, result))
            if result.get('is_threat'):
                threat_count += 1
            else:
                normal_count += 1
        time.sleep(0.5)  # Small delay between tests
    
    # Summary
    print("\n" + "="*70)
    print("  TEST SUMMARY")
    print("="*70)
    print(f"\n  Total tests:     {len(results)}")
    print(f"  Threats found:   {threat_count}")
    print(f"  Normal traffic:  {normal_count}")
    
    if results:
        print(f"\n  Detection Results:")
        print(f"  {'-'*50}")
        for name, result in results:
            pred = result.get('prediction', 'Unknown')
            conf = result.get('confidence', 0) * 100
            threat = "[!]" if result.get('is_threat') else "[OK]"
            print(f"  {threat} {name[:30]:30} → {pred} ({conf:.1f}%)")


def interactive_mode():
    """Interactive testing mode"""
    print("\n🎮 Interactive Mode")
    print("Commands: ddos, dos, portscan, ssh, ftp, sql, xss, bot, normal, all, quit")
    
    shortcuts = {
        'ddos': 'DDoS Attack',
        'dos': 'DoS Hulk Attack',
        'slowloris': 'DoS Slowloris',
        'portscan': 'Port Scan',
        'ssh': 'SSH Brute Force (Patator)',
        'ftp': 'FTP Brute Force (Patator)',
        'sql': 'Web Attack - SQL Injection',
        'xss': 'Web Attack - XSS',
        'bot': 'Botnet Traffic',
        'normal': 'Normal Traffic (Control)'
    }
    
    while True:
        try:
            cmd = input("\n> ").strip().lower()
            
            if cmd == 'quit' or cmd == 'q':
                print("Goodbye!")
                break
            elif cmd == 'all':
                run_all_tests()
            elif cmd in shortcuts:
                name = shortcuts[cmd]
                test_attack(name, ATTACK_PATTERNS[name])
            elif cmd == 'help':
                print("Commands:", ', '.join(shortcuts.keys()), ", all, quit")
            else:
                print(f"Unknown command: {cmd}")
                print("Try: ddos, dos, portscan, ssh, ftp, sql, xss, bot, normal, all, quit")
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--interactive' or sys.argv[1] == '-i':
            interactive_mode()
        elif sys.argv[1] in ['ddos', 'dos', 'portscan', 'ssh', 'ftp', 'sql', 'xss', 'bot', 'normal']:
            shortcuts = {
                'ddos': 'DDoS Attack',
                'dos': 'DoS Hulk Attack',
                'portscan': 'Port Scan',
                'ssh': 'SSH Brute Force (Patator)',
                'ftp': 'FTP Brute Force (Patator)',
                'sql': 'Web Attack - SQL Injection',
                'xss': 'Web Attack - XSS',
                'bot': 'Botnet Traffic',
                'normal': 'Normal Traffic (Control)'
            }
            name = shortcuts[sys.argv[1]]
            test_attack(name, ATTACK_PATTERNS[name])
        else:
            print("Usage: python simulate_attacks.py [--interactive | attack_type]")
            print("Attack types: ddos, dos, portscan, ssh, ftp, sql, xss, bot, normal")
    else:
        run_all_tests()
