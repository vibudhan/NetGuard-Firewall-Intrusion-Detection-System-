import uuid
from datetime import datetime
from ipaddress import ip_network, ip_address, AddressValueError
import logging
import re

class FirewallRules:
    """Advanced firewall rule engine for network security"""
    
    def __init__(self):
        self.rules = {}  # rule_id -> rule_data
        self.rule_stats = {}  # rule_id -> usage statistics
        
        # Rule priorities (higher number = higher priority)
        self.rule_priorities = {
            'ip_block': 100,
            'ip_allow': 90,
            'port_block': 80,
            'port_allow': 70,
            'protocol_block': 60,
            'protocol_allow': 50,
            'default': 0
        }
    
    def add_rule(self, rule_type, value, action, description='', priority=None):
        """Add a new firewall rule"""
        rule_id = str(uuid.uuid4())
        
        # Validate rule parameters
        if not self._validate_rule(rule_type, value, action):
            raise ValueError(f"Invalid rule parameters: type={rule_type}, value={value}, action={action}")
        
        # Determine priority
        if priority is None:
            priority = self.rule_priorities.get(f"{rule_type}_{action}", self.rule_priorities['default'])
        
        rule = {
            'id': rule_id,
            'type': rule_type,
            'value': value,
            'action': action,  # 'allow' or 'block'
            'description': description,
            'priority': priority,
            'created_at': datetime.now().isoformat(),
            'enabled': True,
            'hit_count': 0
        }
        
        self.rules[rule_id] = rule
        self.rule_stats[rule_id] = {
            'matches': 0,
            'last_match': None,
            'matched_ips': set(),
            'matched_ports': set()
        }
        
        logging.info(f"Added firewall rule: {rule}")
        return rule_id
    
    def remove_rule(self, rule_id):
        """Remove a firewall rule"""
        if rule_id in self.rules:
            rule = self.rules.pop(rule_id)
            self.rule_stats.pop(rule_id, None)
            logging.info(f"Removed firewall rule: {rule}")
            return True
        return False
    
    def update_rule(self, rule_id, **kwargs):
        """Update an existing firewall rule"""
        if rule_id not in self.rules:
            return False
        
        rule = self.rules[rule_id]
        for key, value in kwargs.items():
            if key in ['type', 'value', 'action', 'description', 'priority', 'enabled']:
                rule[key] = value
        
        rule['modified_at'] = datetime.now().isoformat()
        logging.info(f"Updated firewall rule {rule_id}: {kwargs}")
        return True
    
    def check_packet(self, packet):
        """Check if a packet should be blocked by firewall rules"""
        src_ip = packet['src_ip']
        dst_ip = packet['dst_ip']
        src_port = packet['src_port']
        dst_port = packet['dst_port']
        protocol = packet['protocol']
        
        # Get all applicable rules sorted by priority
        applicable_rules = self._get_applicable_rules(packet)
        
        for rule in applicable_rules:
            if not rule['enabled']:
                continue
            
            match_result = self._check_rule_match(rule, packet)
            
            if match_result:
                # Update rule statistics
                self._update_rule_stats(rule['id'], packet)
                
                if rule['action'] == 'block':
                    return {
                        'blocked': True,
                        'rule_id': rule['id'],
                        'rule': rule,
                        'reason': self._get_block_reason(rule, packet)
                    }
                elif rule['action'] == 'allow':
                    # Explicit allow - don't check lower priority rules
                    return None
        
        # Default action - allow if no blocking rules matched
        return None
    
    def _validate_rule(self, rule_type, value, action):
        """Validate rule parameters"""
        valid_types = ['ip', 'port', 'protocol', 'subnet']
        valid_actions = ['allow', 'block']
        
        if rule_type not in valid_types:
            return False
        
        if action not in valid_actions:
            return False
        
        # Type-specific validation
        if rule_type == 'ip':
            try:
                ip_address(value)
            except AddressValueError:
                # Check if it's a subnet
                try:
                    ip_network(value, strict=False)
                except AddressValueError:
                    return False
        
        elif rule_type == 'subnet':
            try:
                ip_network(value, strict=False)
            except AddressValueError:
                return False
        
        elif rule_type == 'port':
            try:
                port = int(value)
                if not (1 <= port <= 65535):
                    return False
            except ValueError:
                # Check for port ranges (e.g., "80-90")
                if '-' in str(value):
                    try:
                        start, end = map(int, str(value).split('-'))
                        if not (1 <= start <= end <= 65535):
                            return False
                    except ValueError:
                        return False
                else:
                    return False
        
        elif rule_type == 'protocol':
            if value.upper() not in ['TCP', 'UDP', 'ICMP']:
                return False
        
        return True
    
    def _get_applicable_rules(self, packet):
        """Get rules applicable to a packet, sorted by priority"""
        applicable_rules = []
        
        for rule in self.rules.values():
            if self._is_rule_applicable(rule, packet):
                applicable_rules.append(rule)
        
        # Sort by priority (highest first)
        return sorted(applicable_rules, key=lambda r: r['priority'], reverse=True)
    
    def _is_rule_applicable(self, rule, packet):
        """Check if a rule is applicable to a packet"""
        rule_type = rule['type']
        rule_value = rule['value']
        
        if rule_type == 'ip':
            return (packet['src_ip'] == rule_value or 
                    packet['dst_ip'] == rule_value or
                    self._ip_in_network(packet['src_ip'], rule_value) or
                    self._ip_in_network(packet['dst_ip'], rule_value))
        
        elif rule_type == 'subnet':
            return (self._ip_in_network(packet['src_ip'], rule_value) or
                    self._ip_in_network(packet['dst_ip'], rule_value))
        
        elif rule_type == 'port':
            return (self._port_matches(packet['src_port'], rule_value) or
                    self._port_matches(packet['dst_port'], rule_value))
        
        elif rule_type == 'protocol':
            return packet['protocol'].upper() == rule_value.upper()
        
        return False
    
    def _check_rule_match(self, rule, packet):
        """Check if a rule matches a packet (more detailed than applicability)"""
        return self._is_rule_applicable(rule, packet)
    
    def _ip_in_network(self, ip_str, network_str):
        """Check if an IP is in a network/subnet"""
        try:
            ip = ip_address(ip_str)
            network = ip_network(network_str, strict=False)
            return ip in network
        except (AddressValueError, ValueError):
            return ip_str == network_str
    
    def _port_matches(self, port, rule_port):
        """Check if a port matches a rule port (handles ranges)"""
        if isinstance(rule_port, int) or rule_port.isdigit():
            return port == int(rule_port)
        
        # Handle port ranges
        if '-' in str(rule_port):
            try:
                start, end = map(int, str(rule_port).split('-'))
                return start <= port <= end
            except ValueError:
                return False
        
        return False
    
    def _update_rule_stats(self, rule_id, packet):
        """Update statistics for a matched rule"""
        if rule_id in self.rule_stats:
            stats = self.rule_stats[rule_id]
            stats['matches'] += 1
            stats['last_match'] = datetime.now().isoformat()
            stats['matched_ips'].add(packet['src_ip'])
            stats['matched_ports'].add(packet['dst_port'])
            
            # Update rule hit count
            self.rules[rule_id]['hit_count'] += 1
    
    def _get_block_reason(self, rule, packet):
        """Generate human-readable block reason"""
        rule_type = rule['type']
        rule_value = rule['value']
        
        if rule_type == 'ip':
            if packet['src_ip'] == rule_value:
                return f"Source IP {packet['src_ip']} is blocked"
            elif packet['dst_ip'] == rule_value:
                return f"Destination IP {packet['dst_ip']} is blocked"
            else:
                return f"IP in blocked network {rule_value}"
        
        elif rule_type == 'subnet':
            return f"IP in blocked subnet {rule_value}"
        
        elif rule_type == 'port':
            if self._port_matches(packet['src_port'], rule_value):
                return f"Source port {packet['src_port']} is blocked"
            else:
                return f"Destination port {packet['dst_port']} is blocked"
        
        elif rule_type == 'protocol':
            return f"Protocol {packet['protocol']} is blocked"
        
        return f"Blocked by rule: {rule['description']}"
    
    def get_all_rules(self):
        """Get all rules with their statistics"""
        rules_with_stats = []
        
        for rule_id, rule in self.rules.items():
            rule_data = rule.copy()
            rule_data['stats'] = self.rule_stats.get(rule_id, {})
            
            # Convert sets to lists for JSON serialization
            stats = rule_data['stats']
            if 'matched_ips' in stats:
                stats['matched_ips'] = list(stats['matched_ips'])
            if 'matched_ports' in stats:
                stats['matched_ports'] = list(stats['matched_ports'])
            
            rules_with_stats.append(rule_data)
        
        # Sort by priority
        return sorted(rules_with_stats, key=lambda r: r['priority'], reverse=True)
    
    def get_rule(self, rule_id):
        """Get a specific rule"""
        if rule_id in self.rules:
            rule_data = self.rules[rule_id].copy()
            rule_data['stats'] = self.rule_stats.get(rule_id, {})
            return rule_data
        return None
    
    def enable_rule(self, rule_id):
        """Enable a rule"""
        if rule_id in self.rules:
            self.rules[rule_id]['enabled'] = True
            return True
        return False
    
    def disable_rule(self, rule_id):
        """Disable a rule"""
        if rule_id in self.rules:
            self.rules[rule_id]['enabled'] = False
            return True
        return False
    
    def get_statistics(self):
        """Get overall firewall statistics"""
        total_rules = len(self.rules)
        active_rules = sum(1 for rule in self.rules.values() if rule['enabled'])
        total_matches = sum(stats['matches'] for stats in self.rule_stats.values())
        
        most_matched_rule = None
        max_matches = 0
        for rule_id, stats in self.rule_stats.items():
            if stats['matches'] > max_matches:
                max_matches = stats['matches']
                most_matched_rule = self.rules[rule_id]
        
        return {
            'total_rules': total_rules,
            'active_rules': active_rules,
            'disabled_rules': total_rules - active_rules,
            'total_matches': total_matches,
            'most_matched_rule': most_matched_rule,
            'most_matches': max_matches
        }
    
    def export_rules(self):
        """Export all rules for backup/import"""
        export_data = {
            'rules': list(self.rules.values()),
            'exported_at': datetime.now().isoformat(),
            'version': '1.0'
        }
        return export_data
    
    def import_rules(self, export_data):
        """Import rules from exported data"""
        if 'rules' not in export_data:
            return False
        
        imported_count = 0
        for rule_data in export_data['rules']:
            try:
                rule_id = self.add_rule(
                    rule_data['type'],
                    rule_data['value'],
                    rule_data['action'],
                    rule_data.get('description', ''),
                    rule_data.get('priority')
                )
                imported_count += 1
            except Exception as e:
                logging.error(f"Failed to import rule {rule_data}: {e}")
        
        logging.info(f"Imported {imported_count} firewall rules")
        return imported_count > 0
