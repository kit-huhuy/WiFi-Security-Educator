from flask import Flask, render_template
import os

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/scan')
def scan():
    return render_template('scan.html')

@app.route('/analyze')
def analyze():
    return render_template('analyze.html')

@app.route('/generate')
def generate():
    return render_template('generate.html')

@app.route('/report')
def report():
    return render_template('report.html')

@app.route('/education')
def education():
    return render_template('education.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

if __name__ == '__main__':
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    print("=" * 50)
    print("WiFi Security Educator")
    print("=" * 50)
    print("Local: http://localhost:5000")
    print("Network: http://127.0.0.1:5000")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=5000, debug=True)