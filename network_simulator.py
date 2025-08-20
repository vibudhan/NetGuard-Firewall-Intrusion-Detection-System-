import random
import time
from datetime import datetime
from ipaddress import IPv4Network, IPv4Address
import logging

class NetworkSimulator:
    """Simulates realistic network traffic for educational purposes"""
    
    def __init__(self):
        # Common IP ranges for simulation
        self.internal_networks = [
            IPv4Network('192.168.1.0/24'),
            IPv4Network('10.0.0.0/24'),
            IPv4Network('172.16.0.0/24')
        ]
        
        self.external_networks = [
            IPv4Network('203.0.113.0/24'),  # TEST-NET-3
            IPv4Network('198.51.100.0/24'),  # TEST-NET-2
            IPv4Network('8.8.8.0/24'),      # Public DNS range simulation
        ]
        
        # Common ports and their typical usage
        self.common_ports = {
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
        # Suspicious/malicious IPs for simulation
        self.suspicious_ips = [
            '192.168.1.100',  # Simulated compromised internal host
            '203.0.113.50',   # Simulated external attacker
            '198.51.100.75',  # Simulated botnet member
        ]
        
        # Protocol weights for realistic distribution
        self.protocol_weights = {'TCP': 0.7, 'UDP': 0.25, 'ICMP': 0.05}
        
    def generate_ip(self, ip_type='mixed'):
        """Generate IP addresses based on type"""
        if ip_type == 'internal':
            network = random.choice(self.internal_networks)
            return str(network.network_address + random.randint(1, 254))
        elif ip_type == 'external':
            network = random.choice(self.external_networks)
            return str(network.network_address + random.randint(1, 254))
        elif ip_type == 'suspicious':
            return random.choice(self.suspicious_ips)
        else:  # mixed
            choice = random.random()
            if choice < 0.6:  # 60% internal
                return self.generate_ip('internal')
            elif choice < 0.9:  # 30% external
                return self.generate_ip('external')
            else:  # 10% suspicious
                return self.generate_ip('suspicious')
    
    def generate_port(self, port_type='mixed'):
        """Generate ports based on type"""
        if port_type == 'common':
            return random.choice(list(self.common_ports.keys()))
        elif port_type == 'high':
            return random.randint(1024, 65535)
        elif port_type == 'system':
            return random.randint(1, 1023)
        else:  # mixed
            choice = random.random()
            if choice < 0.5:  # 50% common ports
                return self.generate_port('common')
            elif choice < 0.8:  # 30% high ports
                return self.generate_port('high')
            else:  # 20% system ports
                return self.generate_port('system')
    
    def generate_protocol(self):
        """Generate protocol based on realistic weights"""
        rand = random.random()
        cumulative = 0
        for protocol, weight in self.protocol_weights.items():
            cumulative += weight
            if rand <= cumulative:
                return protocol
        return 'TCP'  # fallback
    
    def generate_packet(self, scenario=None):
        """Generate a single network packet"""
        timestamp = datetime.now()
        
        # Generate different types of traffic based on scenario
        if scenario == 'port_scan':
            # Simulate port scanning activity
            src_ip = self.generate_ip('suspicious')
            dst_ip = self.generate_ip('internal')
            dst_port = self.generate_port('mixed')
            src_port = random.randint(1024, 65535)
            protocol = 'TCP'
            packet_size = random.randint(40, 100)  # Small probe packets
            
        elif scenario == 'dos_attack':
            # Simulate DoS attack patterns
            src_ip = self.generate_ip('suspicious')
            dst_ip = self.generate_ip('internal')
            dst_port = self.generate_port('common')
            src_port = random.randint(1024, 65535)
            protocol = random.choice(['TCP', 'UDP'])
            packet_size = random.randint(1000, 1500)  # Larger attack packets
            
        elif scenario == 'normal_traffic':
            # Simulate normal network activity
            if random.random() < 0.7:  # 70% outbound traffic
                src_ip = self.generate_ip('internal')
                dst_ip = self.generate_ip('external')
            else:  # 30% inbound traffic
                src_ip = self.generate_ip('external')
                dst_ip = self.generate_ip('internal')
                
            dst_port = self.generate_port('common')
            src_port = self.generate_port('high')
            protocol = self.generate_protocol()
            packet_size = random.randint(64, 1500)
            
        else:
            # Default mixed traffic
            src_ip = self.generate_ip('mixed')
            dst_ip = self.generate_ip('mixed')
            dst_port = self.generate_port('mixed')
            src_port = self.generate_port('high')
            protocol = self.generate_protocol()
            packet_size = random.randint(64, 1500)
        
        packet = {
            'timestamp': timestamp.isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'size': packet_size,
            'flags': self.generate_tcp_flags(protocol),
            'scenario': scenario or 'normal'
        }
        
        return packet
    
    def generate_tcp_flags(self, protocol):
        """Generate realistic TCP flags"""
        if protocol != 'TCP':
            return None
            
        flag_combinations = [
            ['SYN'],           # Connection initiation
            ['SYN', 'ACK'],    # Connection response
            ['ACK'],           # Data transfer
            ['FIN', 'ACK'],    # Connection termination
            ['RST'],           # Connection reset
            ['PSH', 'ACK'],    # Push data
        ]
        
        return random.choice(flag_combinations)
    
    def generate_packet_batch(self, count=10):
        """Generate a batch of packets with realistic distribution"""
        packets = []
        
        # Determine scenario distribution
        scenarios = []
        for _ in range(count):
            rand = random.random()
            if rand < 0.8:  # 80% normal traffic
                scenarios.append('normal_traffic')
            elif rand < 0.95:  # 15% port scans
                scenarios.append('port_scan')
            else:  # 5% DoS attacks
                scenarios.append('dos_attack')
        
        for scenario in scenarios:
            packets.append(self.generate_packet(scenario))
        
        return packets
    
    def simulate_attack_sequence(self, attack_type, duration=30):
        """Simulate a specific attack sequence"""
        logging.info(f"Simulating {attack_type} attack for {duration} seconds")
        
        packets = []
        start_time = time.time()
        
        while time.time() - start_time < duration:
            if attack_type == 'port_scan':
                # Generate multiple packets from same IP to different ports
                attacker_ip = self.generate_ip('suspicious')
                target_ip = self.generate_ip('internal')
                
                for port in random.sample(list(self.common_ports.keys()), 5):
                    packet = self.generate_packet('port_scan')
                    packet['src_ip'] = attacker_ip
                    packet['dst_ip'] = target_ip
                    packet['dst_port'] = port
                    packets.append(packet)
                    
            elif attack_type == 'dos':
                # Generate high volume of packets to same target
                for _ in range(20):
                    packets.append(self.generate_packet('dos_attack'))
            
            time.sleep(0.1)
        
        return packets
