"""
Prediction Module for Network Threat Detection
Provides easy-to-use interface for making predictions
"""

import os
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Union, Tuple
import joblib
import warnings
warnings.filterwarnings('ignore')

# Handle both direct run and module run
try:
    from .preprocessing import DataPreprocessor, create_features_from_packet
except ImportError:
    from preprocessing import DataPreprocessor, create_features_from_packet


# Threat severity levels
THREAT_SEVERITY = {
    'Normal': 0,
    'PortScan': 1,
    'BruteForce': 2,
    'WebAttack': 2,
    'DoS': 3,
    'DDoS': 4,
    'Botnet': 4,
    'Infiltration': 4,
    'Heartbleed': 5,
    'Other': 2
}

# Threat descriptions
THREAT_DESCRIPTIONS = {
    'Normal': 'Normal network traffic',
    'DDoS': 'Distributed Denial of Service attack - flooding attack from multiple sources',
    'DoS': 'Denial of Service attack - flooding attack from single source',
    'PortScan': 'Port scanning activity - reconnaissance attempt',
    'BruteForce': 'Brute force attack - login/credential guessing attempt',
    'WebAttack': 'Web-based attack - SQL injection, XSS, or similar',
    'Botnet': 'Botnet activity - compromised host communication',
    'Infiltration': 'Network infiltration attempt',
    'Heartbleed': 'Heartbleed vulnerability exploit attempt',
    'Other': 'Unknown or other type of malicious activity'
}


class ThreatPredictor:
    """
    Threat Predictor for real-time network traffic analysis
    
    Usage:
        predictor = ThreatPredictor('/path/to/ml/models')
        result = predictor.predict(packet_features)
    """
    
    def __init__(self, model_dir: Optional[str] = None):
        """
        Initialize the predictor
        
        Args:
            model_dir: Directory containing model.pkl and preprocessor.pkl
                      If None, uses the default ml/ directory
        """
        if model_dir is None:
            model_dir = os.path.dirname(os.path.abspath(__file__))
        
        self.model_dir = model_dir
        self.model = None
        self.preprocessor = None
        self.model_name = ""
        self.is_loaded = False
        
        # Try to load model automatically
        self._load_model()
    
    def _load_model(self):
        """
        Load the trained model and preprocessor
        """
        model_path = os.path.join(self.model_dir, 'model.pkl')
        preprocessor_path = os.path.join(self.model_dir, 'preprocessor.pkl')
        
        if not os.path.exists(model_path):
            print(f"⚠️ Model not found at {model_path}")
            print("Please run training_pipeline.py first to train the model.")
            return
        
        if not os.path.exists(preprocessor_path):
            print(f"⚠️ Preprocessor not found at {preprocessor_path}")
            print("Please run training_pipeline.py first.")
            return
        
        try:
            # Load model
            model_data = joblib.load(model_path)
            self.model = model_data['model']
            self.model_name = model_data.get('model_name', 'Unknown')
            
            # Load preprocessor
            self.preprocessor = DataPreprocessor.load(preprocessor_path)
            
            self.is_loaded = True
            print(f"✅ Model loaded: {self.model_name}")
            print(f"   Classes: {self.preprocessor.get_class_labels()}")
            
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            self.is_loaded = False
    
    def predict(self, packet_data: Union[Dict, pd.DataFrame]) -> Dict:
        """
        Predict threat type for packet/flow data
        
        Args:
            packet_data: Either a dictionary of features or a DataFrame
            
        Returns:
            Dictionary with prediction results:
            {
                'prediction': str,          # Threat category
                'confidence': float,        # Prediction confidence (0-1)
                'probabilities': dict,      # Probabilities for each class
                'severity': int,            # Severity level (0-5)
                'description': str,         # Human-readable description
                'is_threat': bool           # Whether it's a threat
            }
        """
        if not self.is_loaded:
            return {
                'error': 'Model not loaded. Please train the model first.',
                'prediction': 'Unknown',
                'is_threat': False,
                'severity': 0
            }
        
        try:
            # Convert to DataFrame if dict
            if isinstance(packet_data, dict):
                df = create_features_from_packet(packet_data)
            else:
                df = packet_data.copy()
            
            # Preprocess
            X = self.preprocessor.transform(df)
            
            # Predict
            prediction_encoded = self.model.predict(X)[0]
            prediction = self.preprocessor.inverse_transform_labels([prediction_encoded])[0]
            
            # Get probabilities if available
            probabilities = {}
            confidence = 1.0
            
            if hasattr(self.model, 'predict_proba'):
                probs = self.model.predict_proba(X)[0]
                class_labels = self.preprocessor.get_class_labels()
                probabilities = {label: float(prob) for label, prob in zip(class_labels, probs)}
                confidence = float(max(probs))
            
            # Get severity and description
            severity = THREAT_SEVERITY.get(prediction, 2)
            description = THREAT_DESCRIPTIONS.get(prediction, 'Unknown threat type')
            is_threat = prediction != 'Normal'
            
            return {
                'prediction': prediction,
                'confidence': round(confidence, 4),
                'probabilities': probabilities,
                'severity': severity,
                'description': description,
                'is_threat': is_threat
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'prediction': 'Error',
                'is_threat': False,
                'severity': 0
            }
    
    def predict_batch(self, packets: List[Dict]) -> List[Dict]:
        """
        Predict threats for multiple packets
        
        Args:
            packets: List of packet feature dictionaries
            
        Returns:
            List of prediction results
        """
        return [self.predict(packet) for packet in packets]
    
    def predict_from_scapy_packet(self, packet) -> Dict:
        """
        Predict threat from a raw Scapy packet
        This extracts basic features from a Scapy packet object
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Prediction result
        """
        features = self._extract_features_from_scapy(packet)
        return self.predict(features)
    
    def _extract_features_from_scapy(self, packet) -> Dict:
        """
        Extract features from a Scapy packet
        Note: For full flow-level features, you need multiple packets in a flow
        """
        from scapy.layers.inet import IP, TCP, UDP
        
        features = {}
        
        # Basic IP features
        if IP in packet:
            features['total_length_fwd_packets'] = len(packet)
            features['fwd_packet_length_max'] = len(packet)
            features['fwd_packet_length_min'] = len(packet)
            features['fwd_packet_length_mean'] = len(packet)
            features['max_packet_length'] = len(packet)
            features['min_packet_length'] = len(packet)
            features['packet_length_mean'] = len(packet)
            features['average_packet_size'] = len(packet)
        
        # TCP features
        if TCP in packet:
            tcp = packet[TCP]
            features['destination_port'] = tcp.dport
            features['fwd_header_length'] = tcp.dataofs * 4 if tcp.dataofs else 20
            
            # Flags
            flags = tcp.flags
            features['fin_flag_count'] = 1 if 'F' in str(flags) else 0
            features['syn_flag_count'] = 1 if 'S' in str(flags) else 0
            features['rst_flag_count'] = 1 if 'R' in str(flags) else 0
            features['psh_flag_count'] = 1 if 'P' in str(flags) else 0
            features['ack_flag_count'] = 1 if 'A' in str(flags) else 0
            features['urg_flag_count'] = 1 if 'U' in str(flags) else 0
            
            # Window size
            features['init_win_bytes_forward'] = tcp.window
        
        # UDP features
        elif UDP in packet:
            udp = packet[UDP]
            features['destination_port'] = udp.dport
        
        return features
    
    def get_threat_summary(self, predictions: List[Dict]) -> Dict:
        """
        Get a summary of threats from multiple predictions
        
        Args:
            predictions: List of prediction results
            
        Returns:
            Summary dictionary
        """
        if not predictions:
            return {'total': 0, 'threats': 0, 'normal': 0, 'categories': {}}
        
        total = len(predictions)
        threats = sum(1 for p in predictions if p.get('is_threat', False))
        normal = total - threats
        
        # Count by category
        categories = {}
        for p in predictions:
            cat = p.get('prediction', 'Unknown')
            categories[cat] = categories.get(cat, 0) + 1
        
        # Get highest severity
        max_severity = max((p.get('severity', 0) for p in predictions), default=0)
        
        return {
            'total': total,
            'threats': threats,
            'normal': normal,
            'threat_percentage': round(threats / total * 100, 2) if total > 0 else 0,
            'categories': categories,
            'max_severity': max_severity
        }


# Convenience function for quick predictions
def predict_threat(packet_data: Dict, model_dir: Optional[str] = None) -> Dict:
    """
    Quick prediction function
    
    Args:
        packet_data: Packet/flow features dictionary
        model_dir: Optional model directory
        
    Returns:
        Prediction result
    """
    predictor = ThreatPredictor(model_dir)
    return predictor.predict(packet_data)


if __name__ == "__main__":
    # Test the predictor
    print("Testing ThreatPredictor...")
    
    # Initialize predictor
    predictor = ThreatPredictor()
    
    if predictor.is_loaded:
        # Test with sample data
        test_packet = {
            'destination_port': 80,
            'flow_duration': 100,
            'total_fwd_packets': 10,
            'total_bwd_packets': 5,
            'flow_bytes_per_s': 10000,
            'syn_flag_count': 1,
            'ack_flag_count': 1
        }
        
        result = predictor.predict(test_packet)
        print("\nTest Prediction:")
        print(f"  Prediction: {result['prediction']}")
        print(f"  Confidence: {result['confidence']}")
        print(f"  Is Threat:  {result['is_threat']}")
        print(f"  Severity:   {result['severity']}")
        print(f"  Description: {result['description']}")
    else:
        print("\nModel not trained yet. Run training_pipeline.py first:")
        print("  python -m ml.training_pipeline --quick")
