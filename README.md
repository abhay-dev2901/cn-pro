# Real-Time Network Traffic Analyzer

A lightweight, web-based Network Traffic Analyzer that captures and parses packets in real-time, displays interactive visualizations, and detects basic anomalies.

## Features

- **Real-time Packet Capture**: TCP, UDP, HTTP, DNS protocols
- **Interactive Dashboard**: Visual charts for protocol distribution, bandwidth, and metrics
- **Metrics**: Throughput, latency, packet loss
- **Anomaly Detection**: Port scan detection
- **ML-Based Threat Detection**: DDoS, Brute Force, Port Scans, Web Attacks, Botnet, and more
- **Export**: CSV, JSON, and PCAP formats
- **User-Friendly**: Simple start/stop controls and filters

## Requirements

- Python 3.10+
- Root/Administrator privileges (for packet capture)

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
sudo python app.py
```

**Note**: Administrative privileges are required for packet capture on most systems.

## Usage

1. Start the Flask server (requires sudo on Linux/Mac):
   ```bash
   sudo python app.py
   ```
2. Open your browser to `http://localhost:8080`
3. Select a network interface (optional - auto-detects if not specified)
4. Enter a BPF filter (optional - e.g., `tcp port 80` or `udp port 53`)
5. Click "Start Capture" to begin monitoring network traffic
6. View real-time visualizations and metrics
7. Monitor detected anomalies (port scans)
8. Export data as CSV, JSON, or PCAP formats

## Machine Learning Module

The project includes an ML module for advanced threat detection using the CICIDS2017 dataset.

### Training the Model

```bash
# Quick training (~5 minutes)
python -m ml.training_pipeline --quick

# Full training (~30+ minutes)
python -m ml.training_pipeline
```

### Supported Threat Types

- **DDoS** - Distributed Denial of Service attacks
- **DoS** - Denial of Service attacks
- **Port Scan** - Port scanning reconnaissance
- **Brute Force** - SSH/FTP/Web login attacks
- **Web Attacks** - SQL Injection, XSS
- **Botnet** - Bot network activity
- **Infiltration** - Network infiltration attempts

See `ml/README.md` for detailed documentation.

## Troubleshooting

- **Permission Denied**: Packet capture requires root/administrator privileges. Use `sudo` on Linux/Mac.
- **No Packets Captured**: Ensure you're selecting the correct network interface (use `ifconfig` or `ipconfig` to list interfaces).
- **PCAP Export Empty**: Start capture and wait for packets to be captured before exporting.
- **Interface Not Found**: Check available interfaces using `ifconfig` (Linux/Mac) or `ipconfig` (Windows).

## Project Structure

```
CN Traffic Analyzer/
├── app.py                 # Flask backend
├── packet_capture.py      # Scapy packet capture logic
├── packet_analyzer.py     # Packet parsing and analysis
├── anomaly_detector.py    # Rule-based anomaly detection
├── ml_anomaly_detector.py # ML-enhanced anomaly detection
├── ml/                    # Machine Learning module
│   ├── __init__.py
│   ├── dataset_loader.py  # CICIDS2017 data loading
│   ├── preprocessing.py   # Data preprocessing
│   ├── training_pipeline.py # Model training
│   ├── predict.py         # Prediction module
│   ├── flask_integration.py # Flask integration
│   ├── model.pkl          # Trained model (after training)
│   └── preprocessor.pkl   # Fitted preprocessor
├── MachineLearningCVE/    # CICIDS2017 dataset (CSV files)
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── dashboard.js
├── templates/
│   └── index.html
├── exports/               # Exported files directory
└── requirements.txt
```

## Authors

- Abhay Pratap Rana
- Saloni Sharma
- Vaishnav Verma

BTech CS and AI, Rishihood University

