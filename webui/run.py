#!/usr/bin/env python3
"""
WiFi Security Educator - Runner Script
Use this if main.py doesn't work
"""

import os
import sys
import subprocess
import time
import socket

def check_port(port=5000):
    """Check if port is available"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result == 0

def kill_process_on_port(port):
    """Kill process using specified port"""
    try:
        if sys.platform == 'win32':
            # Windows
            subprocess.run(f'netstat -ano | findstr :{port}', shell=True)
            subprocess.run(f'taskkill /F /PID {port}', shell=True)
        else:
            # Linux/Mac/Termux
            result = subprocess.run(
                f"lsof -ti:{port}",
                shell=True,
                capture_output=True,
                text=True
            )
            if result.stdout:
                pids = result.stdout.strip().split('\n')
                for pid in pids:
                    subprocess.run(f'kill -9 {pid}', shell=True)
                print(f"✓ Killed process(es) on port {port}")
    except:
        pass

def start_server(port=5000):
    """Start Flask server"""
    print(f"\n🚀 Starting WiFi Security Educator on port {port}...")
    
    # Set environment variable
    os.environ['FLASK_APP'] = 'main.py'
    os.environ['FLASK_ENV'] = 'development'
    
    # Command to run
    cmd = [sys.executable, 'main.py']
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        print(f"\n⏳ Server starting... (PID: {process.pid})")
        
        # Wait a bit and check if running
        time.sleep(3)
        
        if check_port(port):
            print(f"\n✅ SUCCESS! Server is running!")
            print(f"\n📡 Access at: http://localhost:{port}")
            print(f"   or: http://127.0.0.1:{port}")
            
            # Keep script running
            try:
                process.wait()
            except KeyboardInterrupt:
                print("\n\n👋 Shutting down server...")
                process.terminate()
        else:
            print(f"\n❌ Server failed to start on port {port}")
            print(f"\nSTDOUT:\n{process.stdout.read() if process.stdout else 'No output'}")
            print(f"\nSTDERR:\n{process.stderr.read() if process.stderr else 'No error output'}")
            
    except Exception as e:
        print(f"\n❌ Error starting server: {e}")

def main():
    print("="*60)
    print("🔐 WIFI SECURITY EDUCATOR - SERVER LAUNCHER")
    print("="*60)
    
    # Check Python version
    print(f"\n🐍 Python: {sys.version}")
    
    # Check if main.py exists
    if not os.path.exists('main.py'):
        print("\n❌ ERROR: main.py not found!")
        print("   Make sure you're in the correct directory.")
        return
    
    # Ask for port
    port = input(f"\nEnter port number [5000]: ").strip()
    port = int(port) if port.isdigit() else 5000
    
    # Check if port is in use
    if check_port(port):
        print(f"\n⚠️  Port {port} is already in use.")
        choice = input("Kill existing process? (y/N): ").lower()
        if choice == 'y':
            kill_process_on_port(port)
            time.sleep(2)
    
    # Start server
    start_server(port)

if __name__ == '__main__':
    main()