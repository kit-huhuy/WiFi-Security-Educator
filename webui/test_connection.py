#!/usr/bin/env python3
"""
Test connection to WiFi Security Educator
"""

import requests
import time
import socket
import sys

def test_localhost(port=5000):
    """Test connection to localhost"""
    print(f"\n🔍 Testing connection to port {port}...")
    
    urls = [
        f"http://127.0.0.1:{port}/",
        f"http://127.0.0.1:{port}/health",
        f"http://127.0.0.1:{port}/api/v1/status"
    ]
    
    for url in urls:
        try:
            print(f"\nTesting: {url}")
            response = requests.get(url, timeout=5)
            print(f"✅ Status: {response.status_code}")
            if response.headers.get('Content-Type'):
                print(f"   Type: {response.headers['Content-Type']}")
            if len(response.text) < 100:
                print(f"   Response: {response.text[:50]}...")
        except requests.ConnectionError:
            print(f"❌ Connection failed - Server not running")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    return True

def check_port_open(port=5000):
    """Check if port is open"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    
    if result == 0:
        print(f"\n✅ Port {port} is OPEN")
        return True
    else:
        print(f"\n❌ Port {port} is CLOSED")
        return False

def main():
    print("="*60)
    print("🔧 CONNECTION TESTER - WiFi Security Educator")
    print("="*60)
    
    port = 5000
    
    # Check if port is open
    if not check_port_open(port):
        print("\n🔧 TROUBLESHOOTING:")
        print("1. Make sure server is running:")
        print("   python main.py")
        print("\n2. Try different port:")
        print("   python main.py --port 8080")
        print("\n3. Check firewall/antivirus")
        return
    
    # Test connections
    test_localhost(port)
    
    print("\n" + "="*60)
    print("📝 NEXT STEPS:")
    print("1. Open browser to: http://127.0.0.1:5000")
    print("2. If not working, check browser console (F12)")
    print("3. Try different browser")
    print("="*60)

if __name__ == '__main__':
    main()