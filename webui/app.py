#!/usr/bin/env python3
"""
WiFi Security Educator - FIXED CONNECTION VERSION
"""

from flask import Flask, render_template, jsonify, request, send_file
import os
import sys
import json
import random
import socket
import datetime
from threading import Thread
import time

# ========== CONFIG ==========
PORT = 5000  # Default port
HOST = '0.0.0.0'  # Bind to all interfaces

# ========== CREATE APP ==========
app = Flask(__name__,
            template_folder='templates',
            static_folder='static',
            static_url_path='/static')

# Enable debug
app.debug = True

# ========== DATA STORAGE ==========
data_store = {
    'scans': [],
    'reports': [],
    'passwords': [],
    'education_progress': {},
    'settings': {
        'dark_mode': False,
        'notifications': True,
        'auto_save': True
    }
}

# ========== HELPER FUNCTIONS ==========
def get_local_ip():
    """Get local IP address"""
    try:
        # Create a socket to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def check_port_available(port):
    """Check if port is available"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result != 0  # True if port is available

def find_available_port(start_port=5000, max_attempts=10):
    """Find an available port"""
    for port in range(start_port, start_port + max_attempts):
        if check_port_available(port):
            return port
    return start_port  # Return original even if busy

# ========== ROUTES ==========
@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/health')
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        'status': 'online',
        'timestamp': datetime.datetime.now().isoformat(),
        'service': 'WiFi Security Educator'
    })

@app.route('/api/v1/status')
def api_status():
    """API status endpoint"""
    return jsonify({
        'status': 'online',
        'version': '2.0.0',
        'server_time': datetime.datetime.now().isoformat(),
        'timestamp': int(time.time()),
        'data': {
            'scans_count': len(data_store['scans']),
            'reports_count': len(data_store['reports']),
            'passwords_count': len(data_store['passwords'])
        }
    })

@app.route('/api/v1/test')
def api_test():
    """Simple test endpoint"""
    return jsonify({
        'message': 'API is working!',
        'success': True,
        'data': {'test': 'passed'}
    })

@app.route('/api/v1/scan', methods=['POST'])
def api_scan():
    """Mock WiFi scan"""
    try:
        # Generate mock networks
        networks = []
        network_count = random.randint(3, 8)
        
        for i in range(network_count):
            signal = random.randint(-90, -40)
            encryption = random.choice(['WPA2', 'WPA3', 'WEP', 'OPEN'])
            
            network = {
                'id': i + 1,
                'ssid': f'{random.choice(["Home", "Office", "Public", "Guest"])}_{random.randint(1, 99)}',
                'bssid': ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6)),
                'channel': random.choice([1, 6, 11, 36]),
                'signal': signal,
                'encryption': encryption,
                'security_score': random.randint(20, 95) if encryption != 'OPEN' else random.randint(5, 30),
                'vendor': random.choice(['TP-Link', 'ASUS', 'Netgear', 'Linksys']),
                'frequency': random.choice(['2.4 GHz', '5 GHz'])
            }
            networks.append(network)
        
        scan_result = {
            'scan_id': len(data_store['scans']) + 1,
            'timestamp': datetime.datetime.now().isoformat(),
            'networks_found': network_count,
            'networks': networks,
            'duration_ms': random.randint(2000, 5000)
        }
        
        data_store['scans'].append(scan_result)
        
        return jsonify({
            'success': True,
            'message': f'Found {network_count} WiFi networks',
            'data': scan_result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

# ========== ALL OTHER ROUTES ==========
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/scan')
def scan_page():
    return render_template('scan.html')

@app.route('/analyze')
def analyze_page():
    return render_template('analyze.html')

@app.route('/generate')
def generate_page():
    return render_template('generate.html')

@app.route('/report')
def report_page():
    return render_template('report.html')

@app.route('/education')
def education_page():
    return render_template('education.html')

@app.route('/settings')
def settings_page():
    return render_template('settings.html')

# ========== STATIC FILE SERVING ==========
@app.route('/favicon.ico')
def favicon():
    return send_file('static/favicon.ico') if os.path.exists('static/favicon.ico') else ('', 204)

# ========== ERROR HANDLERS ==========
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'message': 'The requested resource was not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error', 'message': 'Something went wrong'}), 500

# ========== STARTUP ==========
def create_directories():
    """Create necessary directories"""
    directories = [
        'templates',
        'static/css',
        'static/js',
        'static/images',
        'reports',
        'backups'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✓ Created directory: {directory}")

def print_server_info(port):
    """Print server connection information"""
    local_ip = get_local_ip()
    
    print("\n" + "="*60)
    print("🚀 WIFI SECURITY EDUCATOR - SERVER STARTED")
    print("="*60)
    print("\n📡 CONNECTION OPTIONS:")
    print(f"   Local:    http://127.0.0.1:{port}")
    print(f"   Network:  http://{local_ip}:{port}")
    print("\n🔧 TEST ENDPOINTS:")
    print(f"   Health:   http://127.0.0.1:{port}/health")
    print(f"   API Test: http://127.0.0.1:{port}/api/v1/test")
    print(f"   Status:   http://127.0.0.1:{port}/api/v1/status")
    print("\n🌐 MAIN PAGES:")
    print(f"   Home:     http://127.0.0.1:{port}/")
    print(f"   Dashboard:http://127.0.0.1:{port}/dashboard")
    print(f"   Scanner:  http://127.0.0.1:{port}/scan")
    print("="*60)
    print("\n⚠️  TROUBLESHOOTING:")
    print("   If connection fails, try:")
    print("   1. Check if port {port} is available")
    print("   2. Allow firewall access")
    print("   3. Try different browser")
    print("="*60)

def check_dependencies():
    """Check and install dependencies"""
    try:
        import flask
        print("✓ Flask is installed")
    except ImportError:
        print("⚠️  Flask not found. Installing...")
        os.system(f"{sys.executable} -m pip install flask")
        print("✓ Flask installed successfully")

# ========== MAIN ==========
if __name__ == '__main__':
    print("🔧 Checking dependencies...")
    check_dependencies()
    
    print("\n📁 Setting up directories...")
    create_directories()
    
    # Find available port - tidak perlu global keyword
    PORT = find_available_port(PORT)  # Ini akan mengubah variabel global PORT
    
    print(f"\n🔌 Starting server on port {PORT}...")
    
    
    try:
        # Print connection info
        print_server_info(PORT)
        
        # Run the app
        app.run(
            host=HOST,
            port=PORT,
            debug=True,
            threaded=True,
            use_reloader=False
        )
        
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"\n❌ ERROR: Port {PORT} is already in use!")
            print("\n🔧 SOLUTIONS:")
            print("   1. Kill the existing process:")
            print(f"      lsof -ti:{PORT} | xargs kill -9")
            print("\n   2. Or use a different port:")
            print(f"      Change PORT = {PORT} to PORT = 8080 in main.py")
            print("\n   3. Wait a few minutes and try again")
        else:
            print(f"\n❌ ERROR: {e}")
        
        # Try alternative port
        alt_port = 8080
        print(f"\n🔄 Trying alternative port {alt_port}...")
        try:
            app.run(host=HOST, port=alt_port, debug=True)
        except Exception as alt_e:
            print(f"\n❌ Failed on all ports: {alt_e}")
            print("\n💡 MANUAL START:")
            print("   python main.py --port 9999")
    
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        print("\n🔧 Try running with:")
        print("   python3 main.py")
        print("\nOr install missing packages:")
        print("   pip install flask")