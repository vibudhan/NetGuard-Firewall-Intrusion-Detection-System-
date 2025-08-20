# Network Security Monitor

## Overview

This is a comprehensive network security monitoring system that provides real-time threat detection, firewall management, and security analytics through a web-based dashboard. The application simulates network traffic for educational purposes and demonstrates various cybersecurity concepts including intrusion detection, firewall rule management, and security alert processing.

The system features a Flask-based web application with real-time updates via WebSocket connections, providing an interactive dashboard for monitoring network security events, managing firewall rules, and responding to security threats.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Web Framework**: Flask with Jinja2 templating engine serving HTML pages
- **Real-time Communication**: Socket.IO for bidirectional WebSocket communication between client and server
- **UI Framework**: Bootstrap with dark theme for responsive design
- **JavaScript Architecture**: Class-based ES6 modules for dashboard functionality
- **Visualization**: Chart.js for real-time data visualization and analytics
- **Styling**: Custom CSS with Font Awesome icons for security-themed interface

### Backend Architecture
- **Core Framework**: Flask application with modular component design
- **Component Architecture**: Separate specialized modules for different security functions:
  - `NetworkSimulator`: Generates realistic network traffic patterns for demonstration
  - `ThreatDetector`: Analyzes traffic patterns to identify security threats
  - `FirewallRules`: Manages firewall rule engine with priority-based rule processing
  - `AlertManager`: Handles security alert generation, categorization, and management
- **Threading Model**: Background threads for continuous network simulation and real-time processing
- **Event-Driven Design**: Socket.IO events for real-time dashboard updates

### Data Storage Solutions
- **In-Memory Storage**: Uses Python data structures (dictionaries, deques, sets) for real-time data
- **Session Management**: Flask sessions with configurable secret keys
- **Statistics Tracking**: Time-based statistics with rolling windows for performance metrics
- **Alert Management**: Circular buffer (deque) for efficient alert storage with configurable limits

### Security Features
- **Threat Detection Engine**: Multi-layered detection system with configurable thresholds for:
  - Port scanning detection
  - DoS attack identification
  - Brute force attempt monitoring
  - Suspicious activity pattern recognition
- **Firewall Rule Engine**: Priority-based rule processing with support for IP, port, and protocol filtering
- **Alert Severity System**: Four-tier severity classification (low, medium, high, critical) with automatic response capabilities
- **Network Simulation**: Realistic traffic generation including normal and malicious patterns

## External Dependencies

### Frontend Libraries
- **Bootstrap**: CSS framework with dark theme variant for responsive UI design
- **Font Awesome**: Icon library for security and networking symbols
- **Chart.js**: JavaScript charting library for real-time data visualization
- **Socket.IO Client**: WebSocket client library for real-time communication

### Backend Dependencies
- **Flask**: Python web framework for HTTP request handling and templating
- **Flask-SocketIO**: WebSocket integration for real-time bidirectional communication
- **Python Standard Library**: Extensive use of built-in modules including:
  - `ipaddress`: IP address validation and network calculations
  - `datetime`: Time-based operations and scheduling
  - `collections`: Efficient data structures (deque, defaultdict)
  - `uuid`: Unique identifier generation for alerts and rules
  - `logging`: Application logging and debugging
  - `threading`: Background task execution
  - `json`: Data serialization for API responses

### Network Simulation Components
- **IPv4Network/IPv4Address**: Python's ipaddress module for realistic IP address generation
- **Random Traffic Generation**: Simulated network patterns including both legitimate and malicious traffic
- **Protocol Simulation**: Support for TCP, UDP, and ICMP traffic patterns

### Development Environment
- **Environment Variables**: Configuration through environment variables for security settings
- **Debug Mode**: Development-friendly error handling and hot reloading
- **CORS Support**: Cross-origin resource sharing for Socket.IO connections