import uuid
from datetime import datetime, timedelta
from collections import deque
import logging
import json

class AlertManager:
    """Comprehensive alert management system for network security monitoring"""
    
    def __init__(self, max_alerts=10000):
        self.alerts = deque(maxlen=max_alerts)
        self.alert_index = {}  # For quick lookups
        self.alert_stats = {
            'total': 0,
            'by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'by_type': {},
            'last_24h': 0
        }
        
        # Alert severity levels with colors and priorities
        self.severity_levels = {
            'low': {'priority': 1, 'color': 'success', 'icon': 'info'},
            'medium': {'priority': 2, 'color': 'warning', 'icon': 'exclamation-triangle'},
            'high': {'priority': 3, 'color': 'danger', 'icon': 'shield-exclamation'},
            'critical': {'priority': 4, 'color': 'dark', 'icon': 'exclamation-circle'}
        }
        
        # Alert type configurations
        self.alert_types = {
            'Port Scan Detected': {
                'description': 'Multiple port access from single IP',
                'default_severity': 'medium',
                'auto_block': False
            },
            'DoS Attack Detected': {
                'description': 'High volume traffic from single source',
                'default_severity': 'high',
                'auto_block': True
            },
            'Firewall Block': {
                'description': 'Traffic blocked by firewall rules',
                'default_severity': 'medium',
                'auto_block': False
            },
            'High-Risk Port Access': {
                'description': 'Access to commonly exploited ports',
                'default_severity': 'medium',
                'auto_block': False
            },
            'TCP SYN Scan': {
                'description': 'TCP SYN scanning activity detected',
                'default_severity': 'medium',
                'auto_block': False
            },
            'Potential Brute Force': {
                'description': 'Repeated authentication attempts',
                'default_severity': 'high',
                'auto_block': True
            },
            'Protocol Anomaly': {
                'description': 'Unusual protocol usage patterns',
                'default_severity': 'low',
                'auto_block': False
            }
        }
    
    def add_alert(self, severity, alert_type, description, metadata=None):
        """Add a new security alert"""
        alert_id = str(uuid.uuid4())
        timestamp = datetime.now()
        
        # Validate severity
        if severity not in self.severity_levels:
            severity = 'medium'  # Default fallback
        
        alert = {
            'id': alert_id,
            'timestamp': timestamp.isoformat(),
            'severity': severity,
            'type': alert_type,
            'description': description,
            'metadata': metadata or {},
            'acknowledged': False,
            'resolved': False,
            'created_at': timestamp.isoformat()
        }
        
        # Add to collections
        self.alerts.appendleft(alert)  # Most recent first
        self.alert_index[alert_id] = alert
        
        # Update statistics
        self._update_stats(alert)
        
        logging.info(f"Added {severity} alert: {alert_type} - {description}")
        return alert_id
    
    def _update_stats(self, alert):
        """Update alert statistics"""
        self.alert_stats['total'] += 1
        self.alert_stats['by_severity'][alert['severity']] += 1
        
        alert_type = alert['type']
        if alert_type not in self.alert_stats['by_type']:
            self.alert_stats['by_type'][alert_type] = 0
        self.alert_stats['by_type'][alert_type] += 1
        
        # Count alerts in last 24 hours
        self._update_24h_count()
    
    def _update_24h_count(self):
        """Update count of alerts in last 24 hours"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        count = 0
        
        for alert in self.alerts:
            alert_time = datetime.fromisoformat(alert['timestamp'])
            if alert_time >= cutoff_time:
                count += 1
            else:
                break  # Alerts are ordered by time, so we can break early
        
        self.alert_stats['last_24h'] = count
    
    def get_alert(self, alert_id):
        """Get a specific alert by ID"""
        return self.alert_index.get(alert_id)
    
    def get_alerts(self, limit=100, offset=0, severity=None, alert_type=None, 
                   acknowledged=None, resolved=None):
        """Get alerts with filtering and pagination"""
        filtered_alerts = []
        
        for alert in self.alerts:
            # Apply filters
            if severity and alert['severity'] != severity:
                continue
            
            if alert_type and alert['type'] != alert_type:
                continue
            
            if acknowledged is not None and alert['acknowledged'] != acknowledged:
                continue
            
            if resolved is not None and alert['resolved'] != resolved:
                continue
            
            filtered_alerts.append(alert)
        
        # Apply pagination
        start = offset
        end = offset + limit
        return filtered_alerts[start:end]
    
    def get_recent_alerts(self, count=20):
        """Get most recent alerts"""
        return list(self.alerts)[:count]
    
    def get_all_alerts(self):
        """Get all alerts (for export)"""
        return list(self.alerts)
    
    def acknowledge_alert(self, alert_id, acknowledged_by=None):
        """Acknowledge an alert"""
        if alert_id in self.alert_index:
            alert = self.alert_index[alert_id]
            alert['acknowledged'] = True
            alert['acknowledged_at'] = datetime.now().isoformat()
            alert['acknowledged_by'] = acknowledged_by
            return True
        return False
    
    def resolve_alert(self, alert_id, resolved_by=None, resolution_notes=None):
        """Mark an alert as resolved"""
        if alert_id in self.alert_index:
            alert = self.alert_index[alert_id]
            alert['resolved'] = True
            alert['resolved_at'] = datetime.now().isoformat()
            alert['resolved_by'] = resolved_by
            alert['resolution_notes'] = resolution_notes
            return True
        return False
    
    def bulk_acknowledge(self, alert_ids, acknowledged_by=None):
        """Acknowledge multiple alerts"""
        success_count = 0
        for alert_id in alert_ids:
            if self.acknowledge_alert(alert_id, acknowledged_by):
                success_count += 1
        return success_count
    
    def bulk_resolve(self, alert_ids, resolved_by=None, resolution_notes=None):
        """Resolve multiple alerts"""
        success_count = 0
        for alert_id in alert_ids:
            if self.resolve_alert(alert_id, resolved_by, resolution_notes):
                success_count += 1
        return success_count
    
    def get_alerts_by_severity(self, severity):
        """Get all alerts of a specific severity"""
        return [alert for alert in self.alerts if alert['severity'] == severity]
    
    def get_alerts_by_type(self, alert_type):
        """Get all alerts of a specific type"""
        return [alert for alert in self.alerts if alert['type'] == alert_type]
    
    def get_alert_statistics(self):
        """Get comprehensive alert statistics"""
        # Update 24h count before returning
        self._update_24h_count()
        
        # Calculate additional stats
        unresolved_count = sum(1 for alert in self.alerts if not alert['resolved'])
        unacknowledged_count = sum(1 for alert in self.alerts if not alert['acknowledged'])
        
        # Get top alert types
        top_types = sorted(
            self.alert_stats['by_type'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        # Get severity distribution for charts
        severity_data = []
        for severity, config in self.severity_levels.items():
            count = self.alert_stats['by_severity'][severity]
            severity_data.append({
                'severity': severity,
                'count': count,
                'color': config['color'],
                'priority': config['priority']
            })
        
        return {
            'total_alerts': self.alert_stats['total'],
            'alerts_last_24h': self.alert_stats['last_24h'],
            'unresolved_alerts': unresolved_count,
            'unacknowledged_alerts': unacknowledged_count,
            'severity_distribution': severity_data,
            'top_alert_types': top_types,
            'alert_rate': self._calculate_alert_rate()
        }
    
    def _calculate_alert_rate(self):
        """Calculate alerts per hour over the last 24 hours"""
        if self.alert_stats['last_24h'] == 0:
            return 0
        
        return round(self.alert_stats['last_24h'] / 24, 2)
    
    def get_timeline_data(self, hours=24):
        """Get alert timeline data for charts"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        timeline_data = {}
        
        for alert in self.alerts:
            alert_time = datetime.fromisoformat(alert['timestamp'])
            if alert_time < cutoff_time:
                break
            
            # Group by hour
            hour_key = alert_time.strftime('%Y-%m-%d %H:00')
            if hour_key not in timeline_data:
                timeline_data[hour_key] = {
                    'total': 0,
                    'by_severity': {s: 0 for s in self.severity_levels.keys()}
                }
            
            timeline_data[hour_key]['total'] += 1
            timeline_data[hour_key]['by_severity'][alert['severity']] += 1
        
        # Convert to list format for charts
        timeline_list = []
        for hour_key in sorted(timeline_data.keys()):
            data = timeline_data[hour_key]
            data['hour'] = hour_key
            timeline_list.append(data)
        
        return timeline_list
    
    def cleanup_old_alerts(self, max_age_days=30):
        """Clean up alerts older than specified days"""
        cutoff_time = datetime.now() - timedelta(days=max_age_days)
        
        # Since we're using a deque, we need to rebuild it
        new_alerts = deque(maxlen=self.alerts.maxlen)
        cleaned_count = 0
        
        for alert in self.alerts:
            alert_time = datetime.fromisoformat(alert['timestamp'])
            if alert_time >= cutoff_time:
                new_alerts.append(alert)
            else:
                # Remove from index
                self.alert_index.pop(alert['id'], None)
                cleaned_count += 1
        
        self.alerts = new_alerts
        
        # Recalculate statistics
        self._recalculate_stats()
        
        logging.info(f"Cleaned up {cleaned_count} old alerts")
        return cleaned_count
    
    def _recalculate_stats(self):
        """Recalculate all statistics from current alerts"""
        self.alert_stats = {
            'total': len(self.alerts),
            'by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'by_type': {},
            'last_24h': 0
        }
        
        for alert in self.alerts:
            self.alert_stats['by_severity'][alert['severity']] += 1
            
            alert_type = alert['type']
            if alert_type not in self.alert_stats['by_type']:
                self.alert_stats['by_type'][alert_type] = 0
            self.alert_stats['by_type'][alert_type] += 1
        
        self._update_24h_count()
    
    def export_alerts(self, format='json'):
        """Export alerts for analysis or backup"""
        export_data = {
            'alerts': [dict(alert) for alert in self.alerts],  # Convert deque items to dicts
            'statistics': self.get_alert_statistics(),
            'export_timestamp': datetime.now().isoformat(),
            'total_exported': len(self.alerts)
        }
        
        if format == 'json':
            return json.dumps(export_data, indent=2)
        else:
            return export_data
    
    def search_alerts(self, query, fields=['description', 'type']):
        """Search alerts by text query"""
        query = query.lower()
        matching_alerts = []
        
        for alert in self.alerts:
            for field in fields:
                if field in alert and query in str(alert[field]).lower():
                    matching_alerts.append(alert)
                    break
        
        return matching_alerts
