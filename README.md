# 🔐 WiFi Security Educator v2.0.0

**Professional WiFi Security Analysis Tool for Educational Purposes**

## 📋 Overview

WiFi Security Educator is a comprehensive web application designed to teach users about WiFi network security through hands-on analysis, scanning, and educational content. The tool provides a safe environment to learn about network vulnerabilities, encryption protocols, and security best practices.

## ✨ Features

### 🔍 **Core Features**
- **Network Scanner**: Discover and analyze nearby WiFi networks
- **Security Analysis**: Deep inspection of network vulnerabilities
- **Password Generator**: Create strong, secure passwords
- **Security Reports**: Generate detailed security assessment reports
- **Education Center**: Learn about WiFi security through interactive lessons
- **Dashboard**: Monitor security metrics and statistics

### 🎯 **Key Capabilities**
- Real-time network scanning simulation
- WPA2/WPA3 encryption analysis
- Password strength testing
- Security threat identification
- Educational quizzes and lessons
- Data export and backup

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Termux (Android) or Linux/Mac terminal
- Web browser

### Installation

#### Method 1: Complete Setup (Recommended)
```bash
# 1. Clone 
git clone https://github.com/kit-huhuy/WiFi-Security-Educator
cd WiFi-Security-Educator
cd webui

# 2. Install dependencies
pip install -r requirements.txt

# 2. Run the web application
python app.py
```
## **🖥️ Usage
**Web Interface**
1 Start the Flask server:
```bash
python app.py
```
2 Open your browser and navigate to:
```bash
http://localhost:5000
```
2 Access the application through:
```bash
Local: http://127.0.0.1:5000

Network: http://[YOUR_IP]:5000
```
## **📱 Platform Support**
✅ Termux (Android)
```bash
# Install required packages
pkg install python python-pip
pip install flask colorama

# Run the application
python app.py
```
**✅ Linux/Mac**
```bash
# Install Python if not present
sudo apt install python3 python3-pip  # Ubuntu/Debian

# Install dependencies
pip3 install flask colorama

# Run the application
python3 app.py
```
**✅ Windows**
```bash

# Install Python from python.org
# Open Command Prompt or PowerShell

pip install flask colorama
python app.py
```

## **📊 Features in Detail**

**1. Network Scanner**

- Simulates WiFi network discovery

- Shows SSID, BSSID, signal strength

- Identifies encryption types (WEP, WPA, WPA2, WPA3)

- Calculates security scores

**2. Security Analysis**

- Deep vulnerability assessment

- Encryption strength analysis

- Signal security evaluation

- Threat level classification

- Custom recommendations

**3. Password Generator**

- Configurable length (8-32 characters)

- Multiple character sets

- Strength meter

- Hash generation (MD5, SHA256)

- Password history

**4. Education Center**

- Interactive lessons

- Security glossary

- Knowledge quizzes

- Achievement system

- Progress tracking

**5. Reporting System**

- Detailed security reports

- Export to JSON/PDF

- Historical data

- Comparative analysis

**🛡️ Security & Privacy**

- Data Handling

- All data stored locally

- No internet connectivity required

- Encrypted data storage

- Automatic backup system

**Legal Compliance**

Educational Use Only

Test only on networks you own

Follow local laws and regulations

Respect privacy and security laws

**Privacy Features**

No data collection

No analytics tracking

No third-party services

Complete user control

**🔄 API Reference
Web API Endpoints**
```txt
GET  /api/v1/status          # Server status
POST /api/v1/scan            # Start network scan
POST /api/v1/analyze/{id}    # Analyze specific network
POST /api/v1/generate-password # Generate password
POST /api/v1/generate-report  # Generate security report
GET  /api/v1/download-report/{id} # Download report
POST /api/v1/clear-data      # Clear all datadata
```
**Example API Usage**
```javascript
// Start a scan
fetch('/api/v1/scan', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'}
})
.then(response => response.json())
.then(data => console.log(data));
```

**🧩 Modules**

Frontend (HTML/CSS/JS)

Bootstrap 5: Responsive design

Font Awesome: Icons

Chart.js: Data visualization

Custom CSS: Professional styling

Vanilla JavaScript: No framework dependencies

**Backend (Python/Flask)**

Flask: Web framework

JSON: Data storage

Colorama: Terminal colors

Standard Library: No external dependencies

