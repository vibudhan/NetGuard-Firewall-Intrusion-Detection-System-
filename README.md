🛡️ Network Security Monitor
A real-time network security monitoring dashboard with: - Intrusion Detection 🚨 - Firewall Management 🔥 - Live Threat Visualization 📊
Built using Flask + Socket.IO, this project demonstrates the core concepts of network security, intrusion detection, and real-time visualization. (Educational & demonstration purposes only.)
________________________________________

🚀 Features
🔐 Core Security
•	🔍 Packet Simulation – Generates realistic traffic patterns

•	🛡 Threat Detection Engine – Multi-layered detection with configurable thresholds

•	🔥 Dynamic Firewall Rules – Rule-based IP, port, and protocol filtering

•	🚨 Smart Alert System – Four-tier severity classification + auto responses

•	📊 Live Dashboard – Real-time visualization of traffic & alerts
⚔ Detection Capabilities
•	Port Scanning 🔎

•	DoS Attack Monitoring 🌊

•	Brute Force Detection 🔑

•	Protocol Anomaly Identification 📡

•	High-Risk Port Monitoring ⚠
📊 Dashboard
•	Live stats (packets, block rate, alerts)

•	Interactive charts (traffic & protocols)

•	Real-time activity feed

•	Web-based firewall & alert management
________________________________________

🖼 Screenshots

![WhatsApp Image 2025-08-20 at 20 08 14_fcaeaeb6](https://github.com/user-attachments/assets/5cfdb74a-c4ee-40a9-a267-0bd95168e196)
![WhatsApp Image 2025-08-20 at 20 10 14_edaec3a9](https://github.com/user-attachments/assets/998bc5ae-e955-485f-8f51-dc7fe891e66e)
![WhatsApp Image 2025-08-20 at 20 12 10_0501b5bf](https://github.com/user-attachments/assets/96207cc5-2e77-4135-888a-8947f627e502)
________________________________________

🛠 Tech Stack
Backend - Flask (Python web framework)
- Flask-SocketIO (real-time updates)
- Python Standard Library (network simulation)
Frontend - Bootstrap 5.3 (dark theme UI)
- Chart.js (visualization)
- Socket.IO Client (WebSocket updates)
- Font Awesome (icons)
Architecture - Modular Design 🧩
- Event-Driven (Socket.IO) ⚡
- In-Memory Storage for speed 🚀
- Background Threads for monitoring 🧵
________________________________________

📦 Installation:

✅ Prerequisites:

•	Python 3.11+
•	pip package manager

⚡ Quick Start:

# Clone repository
git clone <repository-url>
cd network-security-monitor

# Install dependencies
pip install flask flask-socketio eventlet gunicorn

# Set secret key
export SESSION_SECRET="your-secret-key-here"

# Run app
gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
Open your browser at: http://localhost:5000
________________________________________
🏗 Project Structure
network-security-monitor/
├── app.py                 # Flask application & routes
├── main.py                # Entry point
├── network_simulator.py   # Traffic simulation engine
├── threat_detector.py     # Threat detection logic
├── firewall_rules.py      # Firewall management
├── alert_manager.py       # Alert system
├── templates/             # HTML templates
├── static/                # CSS, JS, assets
├── screenshots/           # Dashboard screenshots
└── README.md
________________________________________

🔧 Configuration
🔑 Environment Variables
•	SESSION_SECRET → Flask session secret key
🛡 Default Firewall Rules
•	Block malicious IP: 192.168.1.100

•	Allow SSH (22), HTTP (80), HTTPS (443)

•	Allow internal subnet: 10.0.0.0/8
⚙ Detection Thresholds (threat_detector.py)
thresholds = {
    'port_scan': {'ports_per_ip': 10, 'timeframe': 60, 'min_packets': 5},
    'dos_attack': {'packets_per_second': 50, 'sustained_duration': 10, 'packet_threshold': 500}
}
________________________________________

📈 Dashboard Preview
•	Statistics Cards → packets, alerts, block rate

•	Charts → traffic analysis, protocol distribution

•	Live Feed → real-time network events (color-coded by severity)

•	Firewall Management → add/remove rules via UI

•	Alert Management → filter/export alerts
________________________________________

🔒 Security Highlights
•	Threat Detection → port scans, DoS, brute force, anomalies, risky ports

•	Severity Levels → Critical, High, Medium, Low

•	Firewall Rules → IP, subnet, port, protocol filtering
________________________________________

🚀 Deployment
Development
python app.py
Production (Gunicorn)
gunicorn --bind 0.0.0.0:5000 --workers 4 --worker-class eventlet main:app
Docker
FROM python:3.11-slim
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--worker-class", "eventlet", "main:app"]
________________________________________

📈 Usage Examples
➕ Add Firewall Rule via API
curl -X POST http://localhost:5000/api/rules \
  -H "Content-Type: application/json" \
  -d '{"type":"ip","value":"192.168.1.50","action":"block"}'
🔎 Get Alerts
curl http://localhost:5000/api/alerts?severity=high
________________________________________

🔮 Future Enhancements
•	Persistent DB storage

•	User authentication & role-based access control

•	Email/SMS notifications

•	Machine learning-based threat detection

•	Integration with external threat intelligence feeds

•	Network topology visualization
________________________________________

📜 License
Educational use only. Not for production security systems.
⚠ Disclaimer: This project simulates network monitoring for learning purposes only. Always use professional-grade tools in production environm

---

This project was personally developed by Vibudhan Dubey and Prajwal Dikshit as part of my MCA learning journey.


