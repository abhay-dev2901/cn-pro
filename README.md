# Network Traffic Analyzer with ML-Based Threat Detection

A real-time network traffic analysis tool that captures packets, visualizes network activity, and detects security threats using machine learning.

## Overview

This project combines traditional packet capture with machine learning to provide:
- Live network traffic monitoring
- Protocol analysis and visualization
- Automated threat detection (DDoS, Brute Force, Port Scans, etc.)
- Interactive web dashboard

## Features

### Traffic Analysis
- Real-time packet capture using Scapy
- Protocol parsing: TCP, UDP, HTTP, DNS
- Bandwidth monitoring and throughput calculation
- Packet size distribution analysis

### Threat Detection
- **Machine Learning Model**: Random Forest classifier trained on CICIDS2017 dataset
- **Rule-Based Detection**: Real-time pattern matching for common attacks
- **Supported Threats**:
  - DDoS (Distributed Denial of Service)
  - DoS (Denial of Service)
  - Port Scanning
  - Brute Force (SSH, FTP, Telnet, RDP)
  - Web Attacks
  - Botnet Activity

### Dashboard
- Real-time visualization with Chart.js
- Protocol distribution charts
- Bandwidth graphs
- Threat alerts and anomaly logs
- Export functionality (CSV, JSON, PCAP)

## Requirements

- Python 3.9+
- Root/Administrator privileges (required for packet capture)
- ~500MB disk space for ML model and dataset

## Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd "CN Traffic Analyzer"
```

### 2. Create Virtual Environment (Recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Train the ML Model
```bash
# Quick training (5-10 minutes)
python -m ml.training_pipeline --quick

# Full training (30+ minutes, better accuracy)
python -m ml.training_pipeline
```

## Usage

### Starting the Application
```bash
# Linux/Mac (requires sudo for packet capture)
sudo venv/bin/python app.py

# Windows (run as Administrator)
python app.py
```

### Accessing the Dashboard
Open your browser and navigate to:
```
http://localhost:8080
```

### Capturing Traffic
1. Select a network interface (or leave blank for auto-detect)
2. Optionally enter a BPF filter (e.g., `tcp port 80`)
3. Click "Start Capture"
4. Monitor real-time traffic and threat detections

### Testing Threat Detection
Run the attack simulator to test detection capabilities:
```bash
# Target your server IP
python generate_attacks.py <server-ip>

# Examples:
python generate_attacks.py 192.168.1.100
python generate_attacks.py 127.0.0.1 http    # HTTP flood only
python generate_attacks.py 127.0.0.1 ssh     # SSH brute force only
```

## Project Structure

```
CN Traffic Analyzer/
├── app.py                  # Flask web server
├── packet_capture.py       # Scapy-based packet capture
├── packet_analyzer.py      # Protocol parsing
├── anomaly_detector.py     # Rule-based detection
├── generate_attacks.py     # Attack traffic generator for testing
│
├── ml/                     # Machine Learning Module
│   ├── training_pipeline.py    # Model training script
│   ├── predict.py              # Prediction and rule-based detection
│   ├── preprocessing.py        # Data preprocessing
│   ├── flask_integration.py    # Flask API integration
│   ├── model.pkl               # Trained model (generated)
│   └── preprocessor.pkl        # Data preprocessor (generated)
│
├── MachineLearningCVE/     # CICIDS2017 Dataset (CSV files)
│
├── static/
│   ├── css/style.css       # Dashboard styles
│   └── js/dashboard.js     # Frontend JavaScript
│
├── templates/
│   └── index.html          # Dashboard template
│
└── requirements.txt        # Python dependencies
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard |
| `/api/capture/start` | POST | Start packet capture |
| `/api/capture/stop` | POST | Stop packet capture |
| `/api/stats` | GET | Get traffic statistics |
| `/api/packets/recent` | GET | Get recent packets |
| `/api/anomalies` | GET | Get detected threats |
| `/api/ml/status` | GET | ML model status |
| `/api/stream` | GET | SSE stream for real-time updates |
| `/api/export/csv` | GET | Export as CSV |
| `/api/export/json` | GET | Export as JSON |
| `/api/export/pcap` | GET | Export as PCAP |

## How It Works

### Packet Capture
1. Scapy sniffs packets on the selected network interface
2. Each packet is parsed to extract protocol, IPs, ports, flags
3. Flow statistics are computed (packet rate, byte rate, duration)

### Threat Detection
1. **Rule-Based Layer**: Immediate detection based on port and traffic patterns
2. **ML Layer**: Random Forest model classifies traffic based on 37 features
3. Detected threats are logged and displayed on the dashboard

### ML Model
- **Algorithm**: Random Forest Classifier
- **Training Data**: CICIDS2017 dataset (~2.8 million samples)
- **Features**: 37 network flow features
- **Classes**: Normal, DDoS, DoS, PortScan, BruteForce, WebAttack, Botnet
- **Accuracy**: ~99.7% on test set

## Troubleshooting

### "Permission denied" Error
Packet capture requires root privileges:
```bash
sudo venv/bin/python app.py
```

### "Module not found" with sudo
Use the virtual environment's Python:
```bash
sudo venv/bin/python app.py
# or
sudo -E python app.py
```

### No Packets Captured
- Ensure correct network interface is selected
- Check if traffic exists: `tcpdump -i <interface>`
- Verify no firewall is blocking

### ML Model Not Loaded
Train the model first:
```bash
python -m ml.training_pipeline --quick
```

## Technologies Used

- **Backend**: Python, Flask, Scapy
- **ML**: scikit-learn, pandas, numpy
- **Frontend**: HTML, CSS, JavaScript, Chart.js, Bootstrap
- **Data**: CICIDS2017 Intrusion Detection Dataset

## Authors

- Abhay Pratap Rana
- Saloni Sharma
- Vaishnav Verma

BTech Computer Science and AI, Rishihood University

## License

This project is for educational purposes.

## References

- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Flask Documentation](https://flask.palletsprojects.com/)
