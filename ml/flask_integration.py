"""
Flask Integration Module
Provides easy integration of ML predictions into the Flask app
"""

import os
import sys
from typing import Dict, List, Optional
from collections import deque
from datetime import datetime
import threading

# Handle both direct run and module run
try:
    from .predict import ThreatPredictor, THREAT_SEVERITY, THREAT_DESCRIPTIONS
except ImportError:
    from predict import ThreatPredictor, THREAT_SEVERITY, THREAT_DESCRIPTIONS


class MLThreatDetector:
    """
    ML-based threat detector for Flask integration
    Thread-safe and caches recent predictions
    """
    
    def __init__(self, model_dir: Optional[str] = None, cache_size: int = 1000):
        """
        Initialize the threat detector
        
        Args:
            model_dir: Directory containing the trained model
            cache_size: Number of recent predictions to cache
        """
        if model_dir is None:
            model_dir = os.path.dirname(os.path.abspath(__file__))
        
        self.predictor = ThreatPredictor(model_dir)
        self.predictions_cache = deque(maxlen=cache_size)
        self.threat_counts = {}
        self.lock = threading.Lock()
        
        # Statistics
        self.total_predictions = 0
        self.total_threats = 0
    
    @property
    def is_ready(self) -> bool:
        """Check if the model is loaded and ready"""
        return self.predictor.is_loaded
    
    def analyze_packet(self, packet_features: Dict) -> Dict:
        """
        Analyze a packet and return threat prediction
        
        Args:
            packet_features: Dictionary of packet/flow features
            
        Returns:
            Prediction result with timestamp
        """
        result = self.predictor.predict(packet_features)
        result['timestamp'] = datetime.now().isoformat()
        
        with self.lock:
            # Update statistics
            self.total_predictions += 1
            if result.get('is_threat', False):
                self.total_threats += 1
                
                # Update threat counts
                category = result.get('prediction', 'Unknown')
                self.threat_counts[category] = self.threat_counts.get(category, 0) + 1
            
            # Cache prediction
            self.predictions_cache.append(result)
        
        return result
    
    def analyze_flow(self, flow_data: Dict) -> Dict:
        """
        Analyze network flow data
        This is the main method for integration with packet_analyzer.py
        
        Args:
            flow_data: Flow-level features extracted from packets
            
        Returns:
            Prediction result
        """
        # Map flow data keys to expected feature names
        mapped_features = self._map_flow_features(flow_data)
        return self.analyze_packet(mapped_features)
    
    def _map_flow_features(self, flow_data: Dict) -> Dict:
        """
        Map flow data from packet analyzer to ML features
        """
        # Create a mapping from common names to expected feature names
        feature_mapping = {
            'dst_port': 'destination_port',
            'src_port': 'destination_port',
            'duration': 'flow_duration',
            'packet_count': 'total_fwd_packets',
            'bytes': 'total_length_fwd_packets',
            'size': 'total_length_fwd_packets',
            'protocol': None,  # Will be handled separately
        }
        
        mapped = {}
        for key, value in flow_data.items():
            # Normalize key
            key_lower = key.lower().replace(' ', '_')
            
            # Check if there's a mapping
            if key_lower in feature_mapping:
                mapped_key = feature_mapping[key_lower]
                if mapped_key:
                    mapped[mapped_key] = value
            else:
                # Use as-is if it looks like a valid feature
                mapped[key_lower] = value
        
        return mapped
    
    def get_recent_threats(self, limit: int = 20) -> List[Dict]:
        """
        Get recent threat detections
        
        Args:
            limit: Maximum number of threats to return
            
        Returns:
            List of recent threat predictions
        """
        with self.lock:
            threats = [p for p in self.predictions_cache if p.get('is_threat', False)]
            return list(threats)[-limit:]
    
    def get_statistics(self) -> Dict:
        """
        Get threat detection statistics
        
        Returns:
            Statistics dictionary
        """
        with self.lock:
            total = self.total_predictions
            threats = self.total_threats
            
            return {
                'total_analyzed': total,
                'total_threats': threats,
                'normal_traffic': total - threats,
                'threat_percentage': round(threats / total * 100, 2) if total > 0 else 0,
                'threat_breakdown': dict(self.threat_counts),
                'model_loaded': self.predictor.is_loaded,
                'model_name': self.predictor.model_name if self.predictor.is_loaded else None
            }
    
    def reset_statistics(self):
        """Reset all statistics"""
        with self.lock:
            self.total_predictions = 0
            self.total_threats = 0
            self.threat_counts = {}
            self.predictions_cache.clear()


# Global instance for Flask app
_detector_instance: Optional[MLThreatDetector] = None


def get_detector() -> MLThreatDetector:
    """
    Get the global threat detector instance
    Creates one if it doesn't exist
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = MLThreatDetector()
    return _detector_instance


def analyze_packet_with_ml(packet_features: Dict) -> Dict:
    """
    Convenience function for analyzing packets
    
    Args:
        packet_features: Packet/flow features
        
    Returns:
        Prediction result
    """
    detector = get_detector()
    return detector.analyze_packet(packet_features)


# Example Flask routes (can be added to app.py)
FLASK_ROUTES_EXAMPLE = '''
# Add these routes to your app.py for ML integration:

from ml.flask_integration import get_detector, analyze_packet_with_ml

# Initialize detector
ml_detector = get_detector()

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
'''


if __name__ == "__main__":
    # Test the integration
    print("Testing ML Flask Integration...")
    
    detector = get_detector()
    
    if detector.is_ready:
        # Test packet analysis
        test_flow = {
            'dst_port': 22,
            'duration': 1000,
            'packet_count': 100,
            'bytes': 50000,
            'syn_flag_count': 50,
            'ack_flag_count': 50
        }
        
        result = detector.analyze_flow(test_flow)
        print(f"\nTest Result:")
        print(f"  Prediction: {result['prediction']}")
        print(f"  Is Threat:  {result['is_threat']}")
        print(f"  Severity:   {result['severity']}")
        
        print(f"\nStatistics: {detector.get_statistics()}")
        
        print("\n" + "="*50)
        print("Flask Integration Example Routes:")
        print("="*50)
        print(FLASK_ROUTES_EXAMPLE)
    else:
        print("\nModel not loaded. Train the model first:")
        print("  cd ml && python training_pipeline.py --quick")
