# Machine Learning Module for Network Traffic Analyzer

This module provides ML-based threat detection for the Real-Time Network Traffic Analyzer.

## Features

- **Multi-class Threat Detection**: DDoS, DoS, Port Scan, Brute Force, Web Attacks, Botnet, Infiltration
- **Multiple ML Models**: Random Forest, XGBoost, Logistic Regression (automatically selects best)
- **Easy Integration**: Simple API for Flask integration
- **Real-time Prediction**: Fast inference for live traffic analysis

## Folder Structure

```
ml/
├── __init__.py              # Module initialization
├── dataset_loader.py        # CICIDS2017 dataset loading
├── preprocessing.py         # Data cleaning and feature engineering
├── training_pipeline.py     # Model training and evaluation
├── predict.py               # Prediction module
├── flask_integration.py     # Flask app integration
├── model.pkl               # Trained model (after training)
├── preprocessor.pkl        # Fitted preprocessor (after training)
└── README.md               # This file
```

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Train the Model

**Quick training (sampled data, ~5 minutes):**
```bash
cd "/Users/abhayprataprana/Desktop/CN Traffic Analyzer"
python -m ml.training_pipeline --quick
```

**Medium training (~15 minutes):**
```bash
python -m ml.training_pipeline --medium
```

**Full training (all data, ~30+ minutes):**
```bash
python -m ml.training_pipeline
```

### 3. Test Prediction

```bash
python -m ml.predict
```

## Flask Integration

### Option 1: Add ML Routes to app.py

Add these imports and routes to your `app.py`:

```python
# Add at the top with other imports
from ml.flask_integration import get_detector, analyze_packet_with_ml

# Initialize detector (add after other initializations)
ml_detector = get_detector()

# Add these routes

@app.route('/api/ml/status', methods=['GET'])
def ml_status():
    """Get ML model status"""
    detector = get_detector()
    return jsonify({
        'model_loaded': detector.is_ready,
        'statistics': detector.get_statistics()
    })

@app.route('/api/ml/analyze', methods=['POST'])
def ml_analyze():
    """Analyze packet/flow with ML"""
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    result = analyze_packet_with_ml(data)
    return jsonify(result)

@app.route('/api/ml/threats', methods=['GET'])
def ml_threats():
    """Get recent ML-detected threats"""
    limit = request.args.get('limit', 20, type=int)
    detector = get_detector()
    return jsonify({
        'threats': detector.get_recent_threats(limit),
        'statistics': detector.get_statistics()
    })
```

### Option 2: Use Enhanced Anomaly Detector

Replace the anomaly detector in `packet_capture.py`:

```python
# Replace:
# from anomaly_detector import AnomalyDetector
# With:
from ml_anomaly_detector import MLAnomalyDetector

# Replace:
# self.anomaly_detector = AnomalyDetector()
# With:
self.anomaly_detector = MLAnomalyDetector(use_ml=True)
```

### Option 3: Direct Prediction in Code

```python
from ml.predict import ThreatPredictor

# Initialize (loads model automatically)
predictor = ThreatPredictor()

# Predict
result = predictor.predict({
    'destination_port': 22,
    'flow_duration': 1000,
    'total_fwd_packets': 100,
    'syn_flag_count': 50,
    # ... more features
})

print(f"Prediction: {result['prediction']}")
print(f"Is Threat: {result['is_threat']}")
print(f"Confidence: {result['confidence']}")
```

## Dataset

This module uses the **CICIDS2017** dataset from the Canadian Institute for Cybersecurity.

**Expected location:** `MachineLearningCVE/` folder in the project root

**Files:**
- Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
- Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
- Friday-WorkingHours-Morning.pcap_ISCX.csv
- Monday-WorkingHours.pcap_ISCX.csv
- Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
- Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
- Tuesday-WorkingHours.pcap_ISCX.csv
- Wednesday-workingHours.pcap_ISCX.csv

## Attack Categories

| Category | Description | Source Labels |
|----------|-------------|---------------|
| Normal | Benign traffic | BENIGN |
| DDoS | Distributed DoS | DDoS |
| DoS | Denial of Service | DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest |
| PortScan | Port scanning | PortScan |
| BruteForce | Login attacks | FTP-Patator, SSH-Patator, Web Attack – Brute Force |
| WebAttack | Web-based attacks | Web Attack – XSS, Web Attack – Sql Injection |
| Botnet | Bot activity | Bot |
| Infiltration | Network infiltration | Infiltration |
| Heartbleed | Heartbleed exploit | Heartbleed |

## Model Metrics

After training, you'll see metrics like:

```
MODEL COMPARISON
============================================================
Model                Accuracy     Precision    Recall       F1          
------------------------------------------------------------
RandomForest         0.9945       0.9943       0.9945       0.9943
XGBoost              0.9952       0.9951       0.9952       0.9951
LogisticRegression   0.9234       0.9312       0.9234       0.9198

🏆 Best Model: XGBoost (F1 Score: 0.9951)
```

## API Reference

### ThreatPredictor

```python
class ThreatPredictor:
    def predict(self, packet_data: Dict) -> Dict:
        """
        Returns:
            {
                'prediction': str,      # 'Normal', 'DDoS', 'PortScan', etc.
                'confidence': float,    # 0.0 to 1.0
                'is_threat': bool,      # True if not Normal
                'severity': int,        # 0-5 (0=normal, 5=critical)
                'description': str,     # Human-readable description
                'probabilities': dict   # Per-class probabilities
            }
        """
```

### Feature Names

Key features expected by the model:

| Feature | Description |
|---------|-------------|
| destination_port | Target port number |
| flow_duration | Flow duration in microseconds |
| total_fwd_packets | Forward packet count |
| total_bwd_packets | Backward packet count |
| flow_bytes_per_s | Bytes per second |
| flow_packets_per_s | Packets per second |
| syn_flag_count | SYN flag count |
| ack_flag_count | ACK flag count |
| ... | See preprocessing.py for full list |

## Troubleshooting

### Model not found
```
Warning: Model not found at ml/model.pkl
```
**Solution:** Run training pipeline first:
```bash
python -m ml.training_pipeline --quick
```

### XGBoost not installed
```
Warning: XGBoost not installed
```
**Solution:** Install XGBoost:
```bash
pip install xgboost
```

### Memory issues during training
**Solution:** Use sampled training:
```bash
python -m ml.training_pipeline --quick  # Uses 10k samples per file
```

## License

Part of the CN Traffic Analyzer project.
