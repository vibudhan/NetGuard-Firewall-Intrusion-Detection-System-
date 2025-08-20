import os
import logging
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import threading
import time

from network_simulator import NetworkSimulator
from threat_detector import ThreatDetector
from firewall_rules import FirewallRules
from alert_manager import AlertManager

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize components
network_sim = NetworkSimulator()
threat_detector = ThreatDetector()
firewall_rules = FirewallRules()
alert_manager = AlertManager()

# Global statistics
stats = {
    'total_packets': 0,
    'blocked_packets': 0,
    'alerts_count': 0,
    'top_ips': {},
    'top_ports': {},
    'protocol_stats': {'TCP': 0, 'UDP': 0, 'ICMP': 0},
    'last_update': datetime.now()
}

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    """Get current system statistics"""
    return jsonify({
        'stats': stats,
        'alerts': alert_manager.get_recent_alerts(50),
        'rules': firewall_rules.get_all_rules()
    })

@app.route('/api/rules', methods=['GET', 'POST', 'DELETE'])
def manage_rules():
    """Manage firewall rules"""
    if request.method == 'POST':
        rule_data = request.get_json()
        rule_id = firewall_rules.add_rule(
            rule_type=rule_data.get('type'),
            value=rule_data.get('value'),
            action=rule_data.get('action'),
            description=rule_data.get('description', '')
        )
        socketio.emit('rule_added', {'rule_id': rule_id, 'rule': rule_data})
        return jsonify({'success': True, 'rule_id': rule_id})
    
    elif request.method == 'DELETE':
        rule_id = request.args.get('id')
        if firewall_rules.remove_rule(rule_id):
            socketio.emit('rule_removed', {'rule_id': rule_id})
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Rule not found'})
    
    return jsonify({'rules': firewall_rules.get_all_rules()})

@app.route('/api/alerts')
def get_alerts():
    """Get alerts with pagination"""
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    severity = request.args.get('severity')
    
    alerts = alert_manager.get_alerts(limit=limit, offset=offset, severity=severity)
    return jsonify({'alerts': alerts})

@app.route('/api/alerts/export')
def export_alerts():
    """Export alerts as JSON"""
    alerts = alert_manager.get_all_alerts()
    return jsonify({'alerts': alerts, 'exported_at': datetime.now().isoformat()})

def process_packet(packet):
    """Process a single packet through the security pipeline"""
    global stats
    
    # Update basic stats
    stats['total_packets'] += 1
    stats['protocol_stats'][packet['protocol']] += 1
    stats['last_update'] = datetime.now()
    
    # Update top IPs and ports
    src_ip = packet['src_ip']
    dst_port = packet['dst_port']
    
    stats['top_ips'][src_ip] = stats['top_ips'].get(src_ip, 0) + 1
    stats['top_ports'][str(dst_port)] = stats['top_ports'].get(str(dst_port), 0) + 1
    
    # Check firewall rules
    blocked = firewall_rules.check_packet(packet)
    if blocked:
        stats['blocked_packets'] += 1
        alert_manager.add_alert(
            'high',
            'Firewall Block',
            f"Packet from {src_ip}:{packet['src_port']} to {packet['dst_ip']}:{dst_port} blocked by rule: {blocked['reason']}",
            {'packet': packet, 'rule': blocked}
        )
    
    # Run threat detection
    threats = threat_detector.analyze_packet(packet)
    for threat in threats:
        stats['alerts_count'] += 1
        alert_manager.add_alert(
            threat['severity'],
            threat['type'],
            threat['description'],
            {'packet': packet, 'threat_data': threat.get('data', {})}
        )
    
    # Emit real-time updates
    socketio.emit('packet_processed', {
        'packet': packet,
        'blocked': blocked,
        'threats': threats,
        'stats': {
            'total': stats['total_packets'],
            'blocked': stats['blocked_packets'],
            'alerts': stats['alerts_count']
        }
    })
    
    return packet, blocked, threats

def network_monitor_loop():
    """Main network monitoring loop"""
    logging.info("Starting network monitor loop")
    
    while True:
        try:
            # Generate simulated packets
            packets = network_sim.generate_packet_batch(5)
            
            for packet in packets:
                process_packet(packet)
            
            # Emit periodic stats update
            if stats['total_packets'] % 20 == 0:
                socketio.emit('stats_update', {
                    'stats': stats,
                    'recent_alerts': alert_manager.get_recent_alerts(10)
                })
            
            # Sleep briefly to control packet rate
            time.sleep(0.5)
            
        except Exception as e:
            logging.error(f"Error in network monitor loop: {e}")
            time.sleep(1)

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logging.info("Client connected")
    emit('connected', {
        'message': 'Connected to Network Security Monitor',
        'stats': stats,
        'recent_alerts': alert_manager.get_recent_alerts(20)
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logging.info("Client disconnected")

@socketio.on('request_stats')
def handle_stats_request():
    """Handle stats request from client"""
    emit('stats_update', {
        'stats': stats,
        'recent_alerts': alert_manager.get_recent_alerts(10)
    })

if __name__ == '__main__':
    # Start network monitoring in background thread
    monitor_thread = threading.Thread(target=network_monitor_loop, daemon=True)
    monitor_thread.start()
    
    # Initialize some default firewall rules
    firewall_rules.add_rule('ip', '192.168.1.100', 'block', 'Known malicious IP')
    firewall_rules.add_rule('port', '22', 'allow', 'SSH access')
    firewall_rules.add_rule('port', '80', 'allow', 'HTTP traffic')
    firewall_rules.add_rule('port', '443', 'allow', 'HTTPS traffic')
    firewall_rules.add_rule('ip', '10.0.0.0/8', 'allow', 'Internal network')
    
    # Start the Flask-SocketIO server
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
