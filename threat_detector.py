import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging

class ThreatDetector:
    """Advanced threat detection system for network security monitoring"""
    
    def __init__(self):
        # Tracking data structures
        self.ip_activity = defaultdict(lambda: {
            'packet_count': 0,
            'last_seen': None,
            'ports_accessed': set(),
            'protocols_used': set(),
            'first_seen': None,
            'packet_rate': deque(maxlen=60)  # Track rate over last 60 seconds
        })
        
        self.port_activity = defaultdict(lambda: {
            'access_count': 0,
            'unique_ips': set(),
            'last_access': None
        })
        
        # Detection thresholds
        self.thresholds = {
            'port_scan': {
                'ports_per_ip': 10,      # More than 10 ports from same IP
                'timeframe': 60,         # Within 60 seconds
                'min_packets': 5         # Minimum packets to consider
            },
            'dos_attack': {
                'packets_per_second': 50, # More than 50 packets per second
                'sustained_duration': 10,  # For at least 10 seconds
                'packet_threshold': 500    # Total packets in short timeframe
            },
            'brute_force': {
                'failed_attempts': 10,    # Simulated failed connection attempts
                'timeframe': 300         # Within 5 minutes
            },
            'suspicious_activity': {
                'rare_port_threshold': 5, # Accessing less common ports
                'multiple_protocols': 3   # Using multiple protocols rapidly
            }
        }
        
        # Known suspicious patterns
        self.suspicious_patterns = {
            'common_attack_ports': {21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 3389},
            'high_risk_ports': {23, 135, 139, 445, 1433, 3389},  # Telnet, SMB, SQL Server, RDP
            'scanning_patterns': ['SYN'],  # TCP SYN scans
        }
    
    def analyze_packet(self, packet):
        """Analyze a single packet for threats"""
        threats = []
        src_ip = packet['src_ip']
        dst_port = packet['dst_port']
        timestamp = datetime.fromisoformat(packet['timestamp'])
        
        # Update tracking data
        self._update_tracking(packet, timestamp)
        
        # Run detection algorithms
        threats.extend(self._detect_port_scan(src_ip, timestamp))
        threats.extend(self._detect_dos_attack(src_ip, timestamp))
        threats.extend(self._detect_suspicious_activity(packet, timestamp))
        threats.extend(self._detect_brute_force(src_ip, dst_port, timestamp))
        
        return threats
    
    def _update_tracking(self, packet, timestamp):
        """Update internal tracking data structures"""
        src_ip = packet['src_ip']
        dst_port = packet['dst_port']
        protocol = packet['protocol']
        
        # Update IP activity
        ip_data = self.ip_activity[src_ip]
        ip_data['packet_count'] += 1
        ip_data['last_seen'] = timestamp
        ip_data['ports_accessed'].add(dst_port)
        ip_data['protocols_used'].add(protocol)
        ip_data['packet_rate'].append(timestamp)
        
        if ip_data['first_seen'] is None:
            ip_data['first_seen'] = timestamp
        
        # Update port activity
        port_data = self.port_activity[dst_port]
        port_data['access_count'] += 1
        port_data['unique_ips'].add(src_ip)
        port_data['last_access'] = timestamp
    
    def _detect_port_scan(self, src_ip, timestamp):
        """Detect port scanning activity"""
        threats = []
        ip_data = self.ip_activity[src_ip]
        
        # Check if IP has accessed many ports recently
        ports_count = len(ip_data['ports_accessed'])
        timeframe = self.thresholds['port_scan']['timeframe']
        
        if (ports_count >= self.thresholds['port_scan']['ports_per_ip'] and
            ip_data['packet_count'] >= self.thresholds['port_scan']['min_packets']):
            
            # Additional check: ensure activity is within timeframe
            if ip_data['first_seen'] and (timestamp - ip_data['first_seen']).seconds <= timeframe:
                
                severity = 'high' if ports_count > 20 else 'medium'
                
                threats.append({
                    'type': 'Port Scan Detected',
                    'severity': severity,
                    'description': f'IP {src_ip} accessed {ports_count} different ports in {timeframe}s',
                    'data': {
                        'attacker_ip': src_ip,
                        'ports_accessed': list(ip_data['ports_accessed']),
                        'packet_count': ip_data['packet_count'],
                        'duration': (timestamp - ip_data['first_seen']).seconds
                    }
                })
        
        return threats
    
    def _detect_dos_attack(self, src_ip, timestamp):
        """Detect Denial of Service attacks"""
        threats = []
        ip_data = self.ip_activity[src_ip]
        
        # Calculate packet rate over recent time window
        recent_packets = [t for t in ip_data['packet_rate'] 
                         if (timestamp - t).seconds <= 10]
        
        packets_per_second = len(recent_packets) / 10 if recent_packets else 0
        
        if packets_per_second >= self.thresholds['dos_attack']['packets_per_second']:
            severity = 'critical' if packets_per_second > 100 else 'high'
            
            threats.append({
                'type': 'DoS Attack Detected',
                'severity': severity,
                'description': f'High packet rate from {src_ip}: {packets_per_second:.1f} packets/sec',
                'data': {
                    'attacker_ip': src_ip,
                    'packet_rate': packets_per_second,
                    'total_packets': ip_data['packet_count'],
                    'attack_duration': (timestamp - ip_data['first_seen']).seconds if ip_data['first_seen'] else 0
                }
            })
        
        return threats
    
    def _detect_suspicious_activity(self, packet, timestamp):
        """Detect various suspicious activities"""
        threats = []
        src_ip = packet['src_ip']
        dst_port = packet['dst_port']
        protocol = packet['protocol']
        flags = packet.get('flags', [])
        
        # Check for access to high-risk ports
        if dst_port in self.suspicious_patterns['high_risk_ports']:
            threats.append({
                'type': 'High-Risk Port Access',
                'severity': 'medium',
                'description': f'Access to high-risk port {dst_port} from {src_ip}',
                'data': {
                    'src_ip': src_ip,
                    'dst_port': dst_port,
                    'port_description': self._get_port_description(dst_port)
                }
            })
        
        # Check for TCP SYN scanning patterns
        if protocol == 'TCP' and flags == ['SYN']:
            ip_data = self.ip_activity[src_ip]
            if len(ip_data['ports_accessed']) > 5:  # Multiple SYN packets to different ports
                threats.append({
                    'type': 'TCP SYN Scan',
                    'severity': 'medium',
                    'description': f'Potential SYN scan from {src_ip} targeting port {dst_port}',
                    'data': {
                        'src_ip': src_ip,
                        'scan_type': 'SYN',
                        'target_ports': list(ip_data['ports_accessed'])
                    }
                })
        
        # Check for protocol anomalies
        ip_data = self.ip_activity[src_ip]
        if len(ip_data['protocols_used']) >= self.thresholds['suspicious_activity']['multiple_protocols']:
            threats.append({
                'type': 'Protocol Anomaly',
                'severity': 'low',
                'description': f'IP {src_ip} using multiple protocols: {", ".join(ip_data["protocols_used"])}',
                'data': {
                    'src_ip': src_ip,
                    'protocols': list(ip_data['protocols_used'])
                }
            })
        
        return threats
    
    def _detect_brute_force(self, src_ip, dst_port, timestamp):
        """Detect brute force attacks (simulated based on connection patterns)"""
        threats = []
        
        # Simulate brute force detection for common services
        brute_force_ports = {22: 'SSH', 21: 'FTP', 23: 'Telnet', 3389: 'RDP'}
        
        if dst_port in brute_force_ports:
            ip_data = self.ip_activity[src_ip]
            
            # If same IP is making many connections to authentication services
            if (ip_data['packet_count'] > 20 and 
                len(ip_data['ports_accessed']) <= 3):  # Focused on few ports
                
                threats.append({
                    'type': 'Potential Brute Force',
                    'severity': 'high',
                    'description': f'Possible brute force attack on {brute_force_ports[dst_port]} from {src_ip}',
                    'data': {
                        'attacker_ip': src_ip,
                        'target_service': brute_force_ports[dst_port],
                        'target_port': dst_port,
                        'attempt_count': ip_data['packet_count']
                    }
                })
        
        return threats
    
    def _get_port_description(self, port):
        """Get human-readable description of port"""
        port_descriptions = {
            21: 'FTP - File Transfer Protocol',
            22: 'SSH - Secure Shell',
            23: 'Telnet - Unencrypted text communications',
            25: 'SMTP - Simple Mail Transfer Protocol',
            53: 'DNS - Domain Name System',
            80: 'HTTP - Hypertext Transfer Protocol',
            135: 'RPC - Remote Procedure Call',
            139: 'NetBIOS - Network Basic Input/Output System',
            443: 'HTTPS - HTTP Secure',
            445: 'SMB - Server Message Block',
            993: 'IMAPS - Internet Message Access Protocol Secure',
            995: 'POP3S - Post Office Protocol 3 Secure',
            1433: 'MSSQL - Microsoft SQL Server',
            3389: 'RDP - Remote Desktop Protocol'
        }
        
        return port_descriptions.get(port, f'Port {port}')
    
    def get_threat_statistics(self):
        """Get overall threat statistics"""
        total_ips = len(self.ip_activity)
        suspicious_ips = sum(1 for ip_data in self.ip_activity.values() 
                           if len(ip_data['ports_accessed']) > 5)
        
        most_active_ip = max(self.ip_activity.items(), 
                           key=lambda x: x[1]['packet_count'], 
                           default=(None, {'packet_count': 0}))
        
        return {
            'total_monitored_ips': total_ips,
            'suspicious_ips': suspicious_ips,
            'most_active_ip': most_active_ip[0],
            'most_active_packet_count': most_active_ip[1]['packet_count'],
            'total_unique_ports': len(self.port_activity)
        }
    
    def cleanup_old_data(self, max_age_hours=24):
        """Clean up old tracking data to prevent memory bloat"""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        # Clean up old IP activity data
        old_ips = [ip for ip, data in self.ip_activity.items() 
                   if data['last_seen'] and data['last_seen'] < cutoff_time]
        
        for ip in old_ips:
            del self.ip_activity[ip]
        
        logging.info(f"Cleaned up {len(old_ips)} old IP records")
