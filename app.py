"""
Flask Application - Main backend server
Provides API endpoints and serves the web dashboard
"""

from flask import Flask, render_template, jsonify, request, Response, send_file
from flask_cors import CORS
from packet_capture import PacketCapture
import json
import csv
import io
from datetime import datetime
import threading
import time

# ML Integration
try:
    from ml.flask_integration import get_detector, analyze_packet_with_ml
    ML_AVAILABLE = True
    print("ML module loaded successfully")
except ImportError as e:
    ML_AVAILABLE = False
    print(f"ML module not available: {e}")

app = Flask(__name__)
CORS(app)

# Initialize packet capture
capture = PacketCapture()

# Initialize ML detector
ml_detector = None
if ML_AVAILABLE:
    ml_detector = get_detector()
    if ml_detector.is_ready:
        print("ML model loaded and ready for predictions")
    else:
        print("ML model not trained. Run: python -m ml.training_pipeline --quick")

# Global state
capture_lock = threading.Lock()


@app.route('/')
def index():
    """Serve the main dashboard"""
    return render_template('index.html')


@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """Get available network interfaces"""
    interfaces = capture.get_interfaces()
    return jsonify({'interfaces': interfaces})


@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """Start packet capture"""
    with capture_lock:
        data = request.json or {}
        interface = data.get('interface', '')
        filter_string = data.get('filter', '')
        
        # Set interface (even if empty, it will be converted to None)
        capture.set_interface(interface)
        # Set filter (even if empty, it will be converted to None)
        capture.set_filter(filter_string)
        
        # Get available interfaces for debugging
        available_interfaces = capture.get_interfaces()
        print(f"Available interfaces: {available_interfaces}")
        print(f"Selected interface: {interface or 'auto-detect'}")
        print(f"Filter: {filter_string or 'none'}")
            
        if capture.start_capture():
            return jsonify({
                'status': 'started', 
                'message': 'Capture started successfully',
                'available_interfaces': available_interfaces,
                'selected_interface': interface or 'auto-detect'
            })
        else:
            return jsonify({'status': 'error', 'message': 'Capture already running'}), 400


@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    with capture_lock:
        capture.stop_capture()
        return jsonify({'status': 'stopped', 'message': 'Capture stopped successfully'})


@app.route('/api/capture/status', methods=['GET'])
def capture_status():
    """Get capture status"""
    stats = capture.get_stats() if capture.is_capturing else {}
    stats['is_capturing'] = capture.is_capturing
    stats['total_packets'] = stats.get('total_packets', 0)
    
    # Include error if any
    error = capture.get_last_error()
    if error:
        stats['error'] = error
    
    return jsonify(stats)


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get current statistics"""
    stats = capture.get_stats()
    stats['is_capturing'] = capture.is_capturing
    return jsonify(stats)


@app.route('/api/packets/recent', methods=['GET'])
def get_recent_packets():
    """Get recent packets"""
    limit = request.args.get('limit', 50, type=int)
    packets = capture.get_recent_packets(limit)
    return jsonify({'packets': packets})


@app.route('/api/anomalies', methods=['GET'])
def get_anomalies():
    """Get detected anomalies"""
    limit = request.args.get('limit', 20, type=int)
    anomalies = capture.get_anomalies(limit)
    return jsonify({'anomalies': anomalies})


# ============== ML API Routes ==============

@app.route('/api/ml/status', methods=['GET'])
def ml_status():
    """Get ML model status and statistics"""
    if not ML_AVAILABLE:
        return jsonify({
            'available': False,
            'error': 'ML module not installed'
        })
    
    detector = get_detector()
    return jsonify({
        'available': True,
        'model_loaded': detector.is_ready,
        'model_name': detector.predictor.model_name if detector.is_ready else None,
        'statistics': detector.get_statistics()
    })


@app.route('/api/ml/analyze', methods=['POST'])
def ml_analyze():
    """Analyze packet/flow data with ML model"""
    if not ML_AVAILABLE:
        return jsonify({'error': 'ML module not available'}), 503
    
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    result = analyze_packet_with_ml(data)
    return jsonify(result)


@app.route('/api/ml/threats', methods=['GET'])
def ml_threats():
    """Get recent ML-detected threats"""
    if not ML_AVAILABLE:
        return jsonify({'error': 'ML module not available'}), 503
    
    limit = request.args.get('limit', 20, type=int)
    detector = get_detector()
    
    return jsonify({
        'threats': detector.get_recent_threats(limit),
        'statistics': detector.get_statistics()
    })


@app.route('/api/ml/predict', methods=['POST'])
def ml_predict():
    """
    Predict threat type for given features
    Expects JSON with packet/flow features
    """
    if not ML_AVAILABLE:
        return jsonify({'error': 'ML module not available'}), 503
    
    detector = get_detector()
    if not detector.is_ready:
        return jsonify({
            'error': 'ML model not trained. Run: python -m ml.training_pipeline --quick'
        }), 503
    
    data = request.json
    if not data:
        return jsonify({'error': 'No features provided'}), 400
    
    result = detector.analyze_packet(data)
    return jsonify(result)


@app.route('/api/ml/simulate', methods=['POST'])
def ml_simulate():
    """
    Simulate an attack and inject it into the frontend display
    """
    if not ML_AVAILABLE:
        return jsonify({'error': 'ML module not available'}), 503
    
    detector = get_detector()
    if not detector.is_ready:
        return jsonify({'error': 'ML model not trained'}), 503
    
    data = request.json
    if not data:
        return jsonify({'error': 'No attack data provided'}), 400
    
    # Analyze with ML
    result = detector.analyze_packet(data)
    
    # If threat detected, add to capture anomalies for frontend
    if result.get('is_threat'):
        anomaly = {
            'type': f"ML: {result['prediction']}",
            'source_ip': data.get('source_ip', f"192.168.1.{hash(str(data)) % 255}"),
            'destination_ip': data.get('destination_ip', '10.0.0.1'),
            'destination_port': data.get('destination_port', 80),
            'confidence': round(result.get('confidence', 0), 2),
            'severity': result.get('severity', 2),
            'description': result.get('description', ''),
            'timestamp': datetime.now().isoformat(),
            'detection_method': 'ml'
        }
        capture.anomalies.append(anomaly)
        if len(capture.anomalies) > 1000:
            capture.anomalies = capture.anomalies[-1000:]
        result['injected'] = True
    
    return jsonify(result)


@app.route('/api/ml/simulate/batch', methods=['POST'])
def ml_simulate_batch():
    """Simulate multiple attacks for demo"""
    if not ML_AVAILABLE:
        return jsonify({'error': 'ML module not available'}), 503
    
    attacks = [
        {'name': 'DDoS', 'source_ip': '192.168.1.100', 'destination_port': 80, 'flow_packets_per_s': 50000, 'syn_flag_count': 100, 'ack_flag_count': 5},
        {'name': 'Port Scan', 'source_ip': '10.0.0.50', 'destination_port': 22, 'total_fwd_packets': 2, 'syn_flag_count': 1, 'ack_flag_count': 0},
        {'name': 'SSH Brute Force', 'source_ip': '172.16.0.25', 'destination_port': 22, 'total_fwd_packets': 10, 'psh_flag_count': 8},
        {'name': 'DoS', 'source_ip': '192.168.2.50', 'destination_port': 80, 'flow_bytes_per_s': 500000, 'flow_packets_per_s': 500},
        {'name': 'FTP Brute Force', 'source_ip': '10.10.10.10', 'destination_port': 21, 'total_fwd_packets': 5}
    ]
    
    detector = get_detector()
    results = []
    
    for attack in attacks:
        result = detector.analyze_packet(attack)
        if result.get('is_threat'):
            anomaly = {
                'type': f"ML: {result['prediction']}",
                'source_ip': attack['source_ip'],
                'destination_ip': '10.0.0.1',
                'destination_port': attack.get('destination_port', 80),
                'confidence': round(result.get('confidence', 0), 2),
                'severity': result.get('severity', 2),
                'description': result.get('description', ''),
                'timestamp': datetime.now().isoformat(),
                'detection_method': 'ml'
            }
            capture.anomalies.append(anomaly)
        
        results.append({
            'attack': attack['name'],
            'detected': result.get('is_threat', False),
            'prediction': result.get('prediction'),
            'confidence': result.get('confidence')
        })
    
    return jsonify({'message': f'Simulated {len(attacks)} attacks', 'results': results, 'threats_injected': sum(1 for r in results if r['detected'])})


@app.route('/api/stream')
def stream_data():
    """Server-Sent Events stream for real-time updates"""
    def generate():
        while True:
            # Count ML threats from anomalies
            ml_anomalies = [a for a in capture.anomalies if a.get('detection_method') == 'ml' or 'ML:' in str(a.get('type', ''))]
            
            if capture.is_capturing:
                stats = capture.get_stats()
                error = capture.get_last_error()
                if error:
                    stats['error'] = error
                
                data = {
                    'stats': stats,
                    'recent_packets': capture.get_recent_packets(10),
                    'anomalies': capture.get_anomalies(10),
                    'is_capturing': True
                }
            else:
                error = capture.get_last_error()
                data = {
                    'is_capturing': False,
                    'stats': {'error': error} if error else {},
                    'recent_packets': [],
                    'anomalies': capture.get_anomalies(10),  # Show anomalies even when not capturing
                    'ml_available': ML_AVAILABLE
                }
            
            # ALWAYS add ML statistics
            if ML_AVAILABLE and ml_detector and ml_detector.is_ready:
                # Use total_ml_threats for accurate count (not capped by anomaly list limit)
                total_threats = getattr(capture, 'total_ml_threats', 0)
                threat_breakdown = getattr(capture, 'ml_threat_breakdown', {}).copy()
                
                ml_stats = {
                    'total_threats': total_threats,
                    'threat_breakdown': threat_breakdown,
                    'model_loaded': True
                }
                
                data['ml_stats'] = ml_stats
                data['ml_threats'] = ml_anomalies[-5:]
                data['ml_available'] = True
            else:
                data['ml_available'] = False
                data['ml_stats'] = {'total_threats': 0, 'threat_breakdown': {}}
            
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(1)
            
    return Response(generate(), mimetype='text/event-stream')


@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    """Export recent packets as CSV"""
    packets = capture.get_recent_packets(1000)
    
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'timestamp', 'protocol', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
        'size', 'flags', 'dns_query', 'http_method', 'http_host'
    ])
    writer.writeheader()
    writer.writerows(packets)
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=traffic_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
    )


@app.route('/api/export/json', methods=['GET'])
def export_json():
    """Export recent packets as JSON"""
    packets = capture.get_recent_packets(1000)
    data = {
        'export_time': datetime.now().isoformat(),
        'total_packets': len(packets),
        'packets': packets,
        'stats': capture.get_stats(),
        'anomalies': capture.get_anomalies()
    }
    
    output = io.StringIO()
    json.dump(data, output, indent=2)
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=traffic_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'}
    )


@app.route('/api/export/pcap', methods=['GET'])
def export_pcap():
    """
    Export captured packets as PCAP file
    Note: This requires storing raw packets during capture.
    """
    try:
        from scapy.all import wrpcap
        import tempfile
        import os
        import atexit
        
        # Get stored packets from capture
        packets = capture.get_stored_packets()
        
        if not packets:
            return jsonify({'error': 'No packets available for export. Start capture and wait for packets.'}), 400
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
        temp_file.close()
        
        # Write packets to PCAP file
        wrpcap(temp_file.name, packets)
        
        # Schedule cleanup after response
        def cleanup():
            try:
                if os.path.exists(temp_file.name):
                    os.unlink(temp_file.name)
            except:
                pass
        
        # Register cleanup
        atexit.register(cleanup)
        
        # Clean up after a delay (allows download to complete)
        import threading
        def delayed_cleanup():
            import time
            time.sleep(60)  # Wait 60 seconds before cleanup
            cleanup()
        
        threading.Thread(target=delayed_cleanup, daemon=True).start()
        
        return send_file(
            temp_file.name,
            mimetype='application/vnd.tcpdump.pcap',
            as_attachment=True,
            download_name=f'traffic_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pcap'
        )
    except Exception as e:
        return jsonify({'error': f'PCAP export failed: {str(e)}'}), 500


if __name__ == '__main__':
    print("Starting Network Traffic Analyzer...")
    print("Note: This application requires root/administrator privileges for packet capture.")
    print("Open http://localhost:5000 in your browser")
    app.run(debug=True, host='0.0.0.0', port=8080, threaded=True)

