#!/bin/bash
# Complete Attack Test Patterns for CICIDS2017-trained model

echo "=== Testing Attack Detection ==="
echo ""

# DoS Hulk Attack - Complete pattern from CICIDS2017
echo "Testing DoS Hulk Attack..."
curl -s -X POST http://localhost:8080/api/ml/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "destination_port": 80,
    "flow_duration": 119,
    "total_fwd_packets": 12,
    "total_bwd_packets": 0,
    "total_length_fwd_packets": 6048,
    "total_length_bwd_packets": 0,
    "fwd_packet_length_max": 504,
    "fwd_packet_length_mean": 504,
    "bwd_packet_length_max": 0,
    "bwd_packet_length_mean": 0,
    "flow_bytes_per_s": 50823529.41,
    "flow_packets_per_s": 100840.34,
    "flow_iat_mean": 9.92,
    "flow_iat_std": 4.98,
    "fwd_iat_total": 109,
    "fwd_iat_mean": 9.91,
    "bwd_iat_total": 0,
    "bwd_iat_mean": 0,
    "fwd_psh_flags": 0,
    "bwd_psh_flags": 0,
    "fwd_header_length": 240,
    "bwd_header_length": 0,
    "fwd_packets_per_s": 100840.34,
    "bwd_packets_per_s": 0,
    "min_packet_length": 504,
    "max_packet_length": 504,
    "packet_length_mean": 504,
    "packet_length_std": 0,
    "fin_flag_count": 0,
    "syn_flag_count": 0,
    "rst_flag_count": 0,
    "psh_flag_count": 0,
    "ack_flag_count": 0,
    "urg_flag_count": 0,
    "down_up_ratio": 0,
    "average_packet_size": 504,
    "init_win_bytes_forward": 8192,
    "init_win_bytes_backward": 0,
    "act_data_pkt_fwd": 12,
    "active_mean": 0,
    "idle_mean": 0
  }' | python3 -m json.tool

echo ""
echo "---"

# DoS GoldenEye Attack
echo "Testing DoS GoldenEye Attack..."
curl -s -X POST http://localhost:8080/api/ml/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "destination_port": 80,
    "flow_duration": 17209,
    "total_fwd_packets": 5,
    "total_bwd_packets": 4,
    "total_length_fwd_packets": 637,
    "total_length_bwd_packets": 5692,
    "fwd_packet_length_max": 343,
    "fwd_packet_length_mean": 127.4,
    "bwd_packet_length_max": 1420,
    "bwd_packet_length_mean": 1423,
    "flow_bytes_per_s": 367775.58,
    "flow_packets_per_s": 523.01,
    "flow_iat_mean": 2151.13,
    "flow_iat_std": 3269.2,
    "fwd_iat_total": 16783,
    "fwd_iat_mean": 4195.75,
    "bwd_iat_total": 3439,
    "bwd_iat_mean": 1146.33,
    "fwd_psh_flags": 0,
    "bwd_psh_flags": 0,
    "fwd_header_length": 100,
    "bwd_header_length": 80,
    "fwd_packets_per_s": 290.56,
    "bwd_packets_per_s": 232.44,
    "min_packet_length": 0,
    "max_packet_length": 1420,
    "packet_length_mean": 703.22,
    "packet_length_std": 631.39,
    "fin_flag_count": 1,
    "syn_flag_count": 0,
    "rst_flag_count": 0,
    "psh_flag_count": 4,
    "ack_flag_count": 0,
    "urg_flag_count": 0,
    "down_up_ratio": 0,
    "average_packet_size": 703.22,
    "init_win_bytes_forward": 8192,
    "init_win_bytes_backward": 229,
    "act_data_pkt_fwd": 3,
    "active_mean": 0,
    "idle_mean": 0
  }' | python3 -m json.tool

echo ""
echo "---"

# SSH Brute Force (Patator)
echo "Testing SSH Brute Force..."
curl -s -X POST http://localhost:8080/api/ml/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "destination_port": 22,
    "flow_duration": 35378853,
    "total_fwd_packets": 17,
    "total_bwd_packets": 19,
    "total_length_fwd_packets": 3140,
    "total_length_bwd_packets": 5304,
    "fwd_packet_length_max": 900,
    "fwd_packet_length_mean": 184.71,
    "bwd_packet_length_max": 560,
    "bwd_packet_length_mean": 279.16,
    "flow_bytes_per_s": 238.61,
    "flow_packets_per_s": 1.02,
    "flow_iat_mean": 1013681.51,
    "flow_iat_std": 4216437.58,
    "fwd_iat_total": 35371997,
    "fwd_iat_mean": 2210749.81,
    "bwd_iat_total": 35247697,
    "bwd_iat_mean": 1958205.39,
    "fwd_psh_flags": 0,
    "bwd_psh_flags": 0,
    "fwd_header_length": 692,
    "bwd_header_length": 772,
    "fwd_packets_per_s": 0.48,
    "bwd_packets_per_s": 0.54,
    "min_packet_length": 0,
    "max_packet_length": 900,
    "packet_length_mean": 234.56,
    "packet_length_std": 213.96,
    "fin_flag_count": 1,
    "syn_flag_count": 0,
    "rst_flag_count": 0,
    "psh_flag_count": 20,
    "ack_flag_count": 0,
    "urg_flag_count": 0,
    "down_up_ratio": 1,
    "average_packet_size": 234.56,
    "init_win_bytes_forward": 29200,
    "init_win_bytes_backward": 26883,
    "act_data_pkt_fwd": 8,
    "active_mean": 29596.13,
    "idle_mean": 5816594.78
  }' | python3 -m json.tool

echo ""
echo "---"

# FTP Brute Force (Patator)
echo "Testing FTP Brute Force..."
curl -s -X POST http://localhost:8080/api/ml/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "destination_port": 21,
    "flow_duration": 5004087,
    "total_fwd_packets": 11,
    "total_bwd_packets": 10,
    "total_length_fwd_packets": 166,
    "total_length_bwd_packets": 530,
    "fwd_packet_length_max": 31,
    "fwd_packet_length_mean": 15.09,
    "bwd_packet_length_max": 118,
    "bwd_packet_length_mean": 53,
    "flow_bytes_per_s": 139.08,
    "flow_packets_per_s": 4.2,
    "flow_iat_mean": 250204.35,
    "flow_iat_std": 451696.29,
    "fwd_iat_total": 5001298,
    "fwd_iat_mean": 500129.8,
    "bwd_iat_total": 4978553,
    "bwd_iat_mean": 553172.56,
    "fwd_psh_flags": 0,
    "bwd_psh_flags": 0,
    "fwd_header_length": 452,
    "bwd_header_length": 412,
    "fwd_packets_per_s": 2.2,
    "bwd_packets_per_s": 2,
    "min_packet_length": 0,
    "max_packet_length": 118,
    "packet_length_mean": 33.14,
    "packet_length_std": 33.85,
    "fin_flag_count": 1,
    "syn_flag_count": 0,
    "rst_flag_count": 0,
    "psh_flag_count": 10,
    "ack_flag_count": 0,
    "urg_flag_count": 0,
    "down_up_ratio": 0,
    "average_packet_size": 33.14,
    "init_win_bytes_forward": 29200,
    "init_win_bytes_backward": 26883,
    "act_data_pkt_fwd": 5,
    "active_mean": 1582.83,
    "idle_mean": 834066.5
  }' | python3 -m json.tool

echo ""
echo "---"

# DDoS Attack
echo "Testing DDoS Attack..."
curl -s -X POST http://localhost:8080/api/ml/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "destination_port": 80,
    "flow_duration": 9,
    "total_fwd_packets": 6,
    "total_bwd_packets": 0,
    "total_length_fwd_packets": 0,
    "total_length_bwd_packets": 0,
    "fwd_packet_length_max": 0,
    "fwd_packet_length_mean": 0,
    "bwd_packet_length_max": 0,
    "bwd_packet_length_mean": 0,
    "flow_bytes_per_s": 0,
    "flow_packets_per_s": 666666.67,
    "flow_iat_mean": 1.8,
    "flow_iat_std": 0.84,
    "fwd_iat_total": 9,
    "fwd_iat_mean": 1.8,
    "bwd_iat_total": 0,
    "bwd_iat_mean": 0,
    "fwd_psh_flags": 0,
    "bwd_psh_flags": 0,
    "fwd_header_length": 120,
    "bwd_header_length": 0,
    "fwd_packets_per_s": 666666.67,
    "bwd_packets_per_s": 0,
    "min_packet_length": 0,
    "max_packet_length": 0,
    "packet_length_mean": 0,
    "packet_length_std": 0,
    "fin_flag_count": 0,
    "syn_flag_count": 6,
    "rst_flag_count": 0,
    "psh_flag_count": 0,
    "ack_flag_count": 0,
    "urg_flag_count": 0,
    "down_up_ratio": 0,
    "average_packet_size": 0,
    "init_win_bytes_forward": 8192,
    "init_win_bytes_backward": 0,
    "act_data_pkt_fwd": 0,
    "active_mean": 0,
    "idle_mean": 0
  }' | python3 -m json.tool

echo ""
echo "---"

# Port Scan
echo "Testing Port Scan..."
curl -s -X POST http://localhost:8080/api/ml/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "destination_port": 9999,
    "flow_duration": 0,
    "total_fwd_packets": 2,
    "total_bwd_packets": 2,
    "total_length_fwd_packets": 0,
    "total_length_bwd_packets": 0,
    "fwd_packet_length_max": 0,
    "fwd_packet_length_mean": 0,
    "bwd_packet_length_max": 0,
    "bwd_packet_length_mean": 0,
    "flow_bytes_per_s": 0,
    "flow_packets_per_s": 0,
    "flow_iat_mean": 0,
    "flow_iat_std": 0,
    "fwd_iat_total": 0,
    "fwd_iat_mean": 0,
    "bwd_iat_total": 0,
    "bwd_iat_mean": 0,
    "fwd_psh_flags": 0,
    "bwd_psh_flags": 0,
    "fwd_header_length": 40,
    "bwd_header_length": 40,
    "fwd_packets_per_s": 0,
    "bwd_packets_per_s": 0,
    "min_packet_length": 0,
    "max_packet_length": 0,
    "packet_length_mean": 0,
    "packet_length_std": 0,
    "fin_flag_count": 0,
    "syn_flag_count": 1,
    "rst_flag_count": 1,
    "psh_flag_count": 0,
    "ack_flag_count": 1,
    "urg_flag_count": 0,
    "down_up_ratio": 1,
    "average_packet_size": 0,
    "init_win_bytes_forward": 1024,
    "init_win_bytes_backward": 0,
    "act_data_pkt_fwd": 0,
    "active_mean": 0,
    "idle_mean": 0
  }' | python3 -m json.tool

echo ""
echo "---"

# Normal Traffic (Control)
echo "Testing Normal Traffic..."
curl -s -X POST http://localhost:8080/api/ml/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "destination_port": 443,
    "flow_duration": 10000000,
    "total_fwd_packets": 20,
    "total_bwd_packets": 25,
    "total_length_fwd_packets": 2000,
    "total_length_bwd_packets": 15000,
    "fwd_packet_length_max": 500,
    "fwd_packet_length_mean": 100,
    "bwd_packet_length_max": 1400,
    "bwd_packet_length_mean": 600,
    "flow_bytes_per_s": 1700,
    "flow_packets_per_s": 4.5,
    "flow_iat_mean": 222222,
    "flow_iat_std": 100000,
    "fwd_iat_total": 9500000,
    "fwd_iat_mean": 500000,
    "bwd_iat_total": 9000000,
    "bwd_iat_mean": 375000,
    "fwd_psh_flags": 0,
    "bwd_psh_flags": 0,
    "fwd_header_length": 400,
    "bwd_header_length": 500,
    "fwd_packets_per_s": 2,
    "bwd_packets_per_s": 2.5,
    "min_packet_length": 0,
    "max_packet_length": 1400,
    "packet_length_mean": 377.78,
    "packet_length_std": 400,
    "fin_flag_count": 1,
    "syn_flag_count": 0,
    "rst_flag_count": 0,
    "psh_flag_count": 15,
    "ack_flag_count": 0,
    "urg_flag_count": 0,
    "down_up_ratio": 1,
    "average_packet_size": 377.78,
    "init_win_bytes_forward": 65535,
    "init_win_bytes_backward": 65535,
    "act_data_pkt_fwd": 10,
    "active_mean": 50000,
    "idle_mean": 1000000
  }' | python3 -m json.tool

echo ""
echo "=== Test Complete ==="
