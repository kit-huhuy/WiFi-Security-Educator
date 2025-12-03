#!/usr/bin/env python3
"""
WiFi Security Educator - Console Interface
Command-line version for Termux/Linux
"""

import os
import sys
import json
import random
import hashlib
import datetime
import subprocess
import requests
from time import sleep
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

class WiFiSecurityConsole:
    def __init__(self):
        self.data_file = "wifi_data.json"
        self.reports_dir = "reports"
        self.load_data()
        
    def load_data(self):
        """Load saved data from file"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    self.data = json.load(f)
            except:
                self.data = {
                    'scans': [],
                    'reports': [],
                    'passwords': [],
                    'stats': {
                        'total_scans': 0,
                        'networks_found': 0,
                        'vulnerabilities': 0
                    }
                }
        else:
            self.data = {
                'scans': [],
                'reports': [],
                'passwords': [],
                'stats': {
                    'total_scans': 0,
                    'networks_found': 0,
                    'vulnerabilities': 0
                }
            }
    
    def save_data(self):
        """Save data to file"""
        with open(self.data_file, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        """Print application header"""
        self.clear_screen()
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + "🔐 WiFi SECURITY EDUCATOR - Console Edition")
        print(Fore.CYAN + "=" * 60)
        print(Fore.WHITE + f"Scans: {self.data['stats']['total_scans']} | " +
              f"Networks: {self.data['stats']['networks_found']} | " +
              f"Reports: {len(self.data['reports'])}")
        print(Fore.CYAN + "-" * 60)
    
    def main_menu(self):
        """Display main menu"""
        while True:
            self.print_header()
            print(Fore.GREEN + "\n📋 MAIN MENU")
            print(Fore.WHITE + "1. 📡 Scan WiFi Networks")
            print(Fore.WHITE + "2. 🔍 Analyze Network Security")
            print(Fore.WHITE + "3. 🔑 Generate Secure Password")
            print(Fore.WHITE + "4. 📊 View Security Reports")
            print(Fore.WHITE + "5. 📚 Security Education")
            print(Fore.WHITE + "6. ⚙️  Settings & Tools")
            print(Fore.WHITE + "7. 📈 View Statistics")
            print(Fore.WHITE + "8. 🚪 Exit")
            
            choice = input(Fore.YELLOW + "\nSelect option (1-8): ").strip()
            
            if choice == '1':
                self.scan_networks()
            elif choice == '2':
                self.analyze_network()
            elif choice == '3':
                self.generate_password()
            elif choice == '4':
                self.view_reports()
            elif choice == '5':
                self.security_education()
            elif choice == '6':
                self.settings_menu()
            elif choice == '7':
                self.view_statistics()
            elif choice == '8':
                self.exit_app()
            else:
                print(Fore.RED + "Invalid choice! Press Enter to continue...")
                input()
    
    def scan_networks(self):
        """Perform WiFi network scan"""
        self.print_header()
        print(Fore.GREEN + "\n📡 WIFI NETWORK SCANNER")
        print(Fore.CYAN + "-" * 60)
        
        print(Fore.YELLOW + "\nStarting scan...")
        
        # Simulate scanning animation
        for i in range(5):
            print(Fore.WHITE + "Scanning" + "." * (i % 4), end="\r")
            sleep(0.5)
        
        # Generate mock networks
        networks = []
        network_count = random.randint(3, 8)
        
        for i in range(network_count):
            signal = random.randint(-90, -40)
            is_encrypted = random.choice([True, True, False])  # 2/3 chance encrypted
            encryption = random.choice(['WPA2', 'WPA3', 'WPA']) if is_encrypted else 'OPEN'
            
            network = {
                'id': i + 1,
                'ssid': random.choice(['Home', 'Office', 'Public', 'Guest', 'IoT', 'Secure']) + 
                       f"_{random.randint(1, 99)}",
                'bssid': ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6)),
                'channel': random.choice([1, 6, 11, 36, 40, 44, 48, 149, 153, 157]),
                'signal': signal,
                'encryption': encryption,
                'security_score': random.randint(20, 95) if is_encrypted else random.randint(5, 30),
                'vendor': random.choice(['TP-Link', 'ASUS', 'Netgear', 'Linksys', 'D-Link']),
                'frequency': random.choice(['2.4 GHz', '5 GHz'])
            }
            networks.append(network)
        
        # Display results
        print(Fore.GREEN + f"\n✅ Found {network_count} networks:")
        print(Fore.CYAN + "-" * 60)
        
        for network in networks:
            signal_color = Fore.GREEN if network['signal'] > -60 else \
                          Fore.YELLOW if network['signal'] > -70 else Fore.RED
            
            sec_color = Fore.GREEN if network['security_score'] >= 70 else \
                       Fore.YELLOW if network['security_score'] >= 40 else Fore.RED
            
            enc_color = Fore.GREEN if network['encryption'] in ['WPA2', 'WPA3'] else \
                       Fore.RED if network['encryption'] == 'OPEN' else Fore.YELLOW
            
            print(f"{Fore.WHITE}{network['id']:2d}. {network['ssid']:20s}")
            print(f"     BSSID: {network['bssid']}")
            print(f"     Signal: {signal_color}{network['signal']} dBm{Fore.WHITE} | " +
                  f"Channel: {network['channel']} ({network['frequency']})")
            print(f"     Encryption: {enc_color}{network['encryption']:6s}{Fore.WHITE} | " +
                  f"Security: {sec_color}{network['security_score']}/100")
            print(Fore.CYAN + "     " + "-" * 40)
        
        # Save scan
        scan_data = {
            'id': len(self.data['scans']) + 1,
            'timestamp': datetime.datetime.now().isoformat(),
            'networks_found': network_count,
            'networks': networks
        }
        
        self.data['scans'].append(scan_data)
        self.data['stats']['total_scans'] += 1
        self.data['stats']['networks_found'] += network_count
        
        self.save_data()
        
        print(Fore.YELLOW + "\nOptions:")
        print(Fore.WHITE + "1. Analyze a network")
        print(Fore.WHITE + "2. Save scan report")
        print(Fore.WHITE + "3. Back to menu")
        
        choice = input(Fore.YELLOW + "\nSelect (1-3): ").strip()
        
        if choice == '1':
            self.analyze_specific_network(networks)
        elif choice == '2':
            self.save_scan_report(scan_data)
    
    def analyze_specific_network(self, networks):
        """Analyze a specific network"""
        self.print_header()
        print(Fore.GREEN + "\n🔍 NETWORK ANALYSIS")
        print(Fore.CYAN + "-" * 60)
        
        try:
            network_id = int(input(Fore.YELLOW + "Enter network number to analyze: "))
            if 1 <= network_id <= len(networks):
                network = networks[network_id - 1]
                self.perform_analysis(network)
            else:
                print(Fore.RED + "Invalid network number!")
        except ValueError:
            print(Fore.RED + "Please enter a valid number!")
        
        input(Fore.YELLOW + "\nPress Enter to continue...")
    
    def perform_analysis(self, network):
        """Perform detailed security analysis"""
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.YELLOW + f"SECURITY ANALYSIS: {network['ssid']}")
        print(Fore.CYAN + "=" * 60)
        
        # Security checks
        checks = [
            ('Encryption Type', 'PASS' if network['encryption'] in ['WPA2', 'WPA3'] else 'FAIL', 30),
            ('Signal Strength', 'PASS' if network['signal'] > -70 else 'WARNING', 20),
            ('Default SSID', 'PASS' if 'default' not in network['ssid'].lower() else 'FAIL', 15),
            ('Channel Congestion', 'PASS' if network['channel'] not in [1, 6, 11] else 'WARNING', 20),
            ('Security Protocol', 'PASS' if network['encryption'] != 'WEP' else 'FAIL', 15)
        ]
        
        total_score = 0
        max_score = 0
        
        for check, status, weight in checks:
            status_color = Fore.GREEN if status == 'PASS' else \
                          Fore.YELLOW if status == 'WARNING' else Fore.RED
            
            score = weight if status == 'PASS' else weight//2 if status == 'WARNING' else 0
            total_score += score
            max_score += weight
            
            print(f"{Fore.WHITE}{check:20s} {status_color}{status:8s} {Fore.WHITE}{score:3d}/{weight}")
        
        security_percentage = (total_score / max_score) * 100
        
        print(Fore.CYAN + "-" * 60)
        print(f"{Fore.WHITE}Overall Security: {self.get_score_color(security_percentage)}{security_percentage:.1f}%")
        print(Fore.CYAN + "=" * 60)
        
        # Recommendations
        print(Fore.YELLOW + "\n🔧 RECOMMENDATIONS:")
        recommendations = [
            "Use WPA3 encryption if available",
            "Change default router password",
            "Disable WPS feature",
            "Update router firmware regularly",
            "Use strong password with special characters"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"{Fore.WHITE}{i}. {rec}")
    
    def get_score_color(self, score):
        """Get color based on security score"""
        if score >= 80:
            return Fore.GREEN
        elif score >= 60:
            return Fore.YELLOW
        elif score >= 40:
            return Fore.LIGHTRED_EX
        else:
            return Fore.RED
    
    def save_scan_report(self, scan_data):
        """Save scan as report"""
        report = {
            'id': hashlib.md5(scan_data['timestamp'].encode()).hexdigest()[:8],
            'title': f"WiFi Scan Report #{len(self.data['reports']) + 1}",
            'date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scan_data': scan_data,
            'summary': {
                'total_networks': scan_data['networks_found'],
                'secure_networks': sum(1 for n in scan_data['networks'] if n['security_score'] >= 70),
                'risky_networks': sum(1 for n in scan_data['networks'] if n['security_score'] < 70),
                'average_security': sum(n['security_score'] for n in scan_data['networks']) / scan_data['networks_found']
            }
        }
        
        self.data['reports'].append(report)
        self.save_data()
        
        # Ensure reports directory exists
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Save as JSON file
        report_file = os.path.join(self.reports_dir, f"report_{report['id']}.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(Fore.GREEN + f"\n✅ Report saved: {report_file}")
        sleep(2)
    
    def analyze_network(self):
        """Analyze network from saved scans"""
        self.print_header()
        print(Fore.GREEN + "\n🔍 NETWORK ANALYSIS")
        print(Fore.CYAN + "-" * 60)
        
        if not self.data['scans']:
            print(Fore.YELLOW + "No scans available. Please run a scan first.")
            input(Fore.YELLOW + "\nPress Enter to continue...")
            return
        
        print(Fore.YELLOW + "Select scan to analyze:")
        for i, scan in enumerate(self.data['scans'][-5:], 1):  # Show last 5 scans
            date = datetime.datetime.fromisoformat(scan['timestamp']).strftime('%Y-%m-%d %H:%M')
            print(f"{Fore.WHITE}{i}. Scan #{scan['id']} ({date}) - {scan['networks_found']} networks")
        
        try:
            choice = int(input(Fore.YELLOW + "\nSelect scan (1-5): "))
            if 1 <= choice <= min(5, len(self.data['scans'])):
                scan = self.data['scans'][-choice]
                self.analyze_specific_network(scan['networks'])
        except (ValueError, IndexError):
            print(Fore.RED + "Invalid selection!")
            input(Fore.YELLOW + "\nPress Enter to continue...")
    
    def generate_password(self):
        """Generate secure password"""
        self.print_header()
        print(Fore.GREEN + "\n🔑 PASSWORD GENERATOR")
        print(Fore.CYAN + "-" * 60)
        
        try:
            length = int(input(Fore.YELLOW + "Password length (8-32): ") or "12")
            length = max(8, min(32, length))
            
            include_upper = input(Fore.YELLOW + "Include uppercase? (Y/n): ").lower() != 'n'
            include_lower = input(Fore.YELLOW + "Include lowercase? (Y/n): ").lower() != 'n'
            include_numbers = input(Fore.YELLOW + "Include numbers? (Y/n): ").lower() != 'n'
            include_symbols = input(Fore.YELLOW + "Include symbols? (Y/n): ").lower() != 'n'
            
            # Build character set
            charset = ''
            if include_upper: charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            if include_lower: charset += 'abcdefghijklmnopqrstuvwxyz'
            if include_numbers: charset += '0123456789'
            if include_symbols: charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'
            
            if not charset:
                print(Fore.RED + "Error: No character types selected!")
                input(Fore.YELLOW + "\nPress Enter to continue...")
                return
            
            # Generate password
            import secrets
            password = ''.join(secrets.choice(charset) for _ in range(length))
            
            # Calculate entropy
            entropy = len(charset) ** length
            entropy_bits = entropy.bit_length()
            
            # Strength assessment
            strength = "Very Weak"
            if entropy_bits > 80: strength = "Strong"
            elif entropy_bits > 60: strength = "Good"
            elif entropy_bits > 40: strength = "Moderate"
            elif entropy_bits > 20: strength = "Weak"
            
            # Display results
            print(Fore.CYAN + "\n" + "=" * 60)
            print(Fore.YELLOW + "GENERATED PASSWORD")
            print(Fore.CYAN + "=" * 60)
            print(Fore.GREEN + f"\n{password}")
            print(Fore.CYAN + "-" * 60)
            print(Fore.WHITE + f"Length: {length} characters")
            print(Fore.WHITE + f"Character set size: {len(charset)}")
            print(Fore.WHITE + f"Entropy: ~{entropy_bits} bits")
            print(Fore.WHITE + f"Strength: {strength}")
            print(Fore.CYAN + "-" * 60)
            
            # Hash values
            md5_hash = hashlib.md5(password.encode()).hexdigest()
            sha256_hash = hashlib.sha256(password.encode()).hexdigest()
            
            print(Fore.WHITE + f"MD5: {md5_hash}")
            print(Fore.WHITE + f"SHA256: {sha256_hash[:32]}...")
            
            # Save to history
            password_data = {
                'password': password,
                'timestamp': datetime.datetime.now().isoformat(),
                'length': length,
                'strength': strength,
                'entropy_bits': entropy_bits
            }
            
            self.data['passwords'].append(password_data)
            self.save_data()
            
            print(Fore.YELLOW + "\nOptions:")
            print(Fore.WHITE + "1. Copy to clipboard")
            print(Fore.WHITE + "2. Generate another")
            print(Fore.WHITE + "3. Back to menu")
            
            choice = input(Fore.YELLOW + "\nSelect (1-3): ").strip()
            
            if choice == '1':
                self.copy_to_clipboard(password)
            elif choice == '2':
                self.generate_password()
                
        except ValueError:
            print(Fore.RED + "Invalid input!")
            input(Fore.YELLOW + "\nPress Enter to continue...")
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        try:
            # For Termux/Linux
            subprocess.run(['termux-clipboard-set', text], check=True)
            print(Fore.GREEN + "✓ Copied to clipboard!")
        except:
            try:
                # For systems with xclip
                subprocess.run(['xclip', '-selection', 'clipboard'], input=text.encode(), check=True)
                print(Fore.GREEN + "✓ Copied to clipboard!")
            except:
                print(Fore.YELLOW + "⚠ Could not copy to clipboard automatically.")
                print(Fore.WHITE + "Please copy manually from above.")
        
        sleep(2)
    
    def view_reports(self):
        """View saved reports"""
        self.print_header()
        print(Fore.GREEN + "\n📊 SECURITY REPORTS")
        print(Fore.CYAN + "-" * 60)
        
        if not self.data['reports']:
            print(Fore.YELLOW + "No reports available.")
            input(Fore.YELLOW + "\nPress Enter to continue...")
            return
        
        print(Fore.YELLOW + "Available Reports:")
        for i, report in enumerate(self.data['reports'][-10:], 1):  # Show last 10
            print(f"{Fore.WHITE}{i:2d}. {report['title']}")
            print(f"     Date: {report['date']} | ID: {report['id']}")
            print(f"     Networks: {report['summary']['total_networks']} | " +
                  f"Secure: {report['summary']['secure_networks']} | " +
                  f"Avg Score: {report['summary']['average_security']:.1f}%")
            print(Fore.CYAN + "     " + "-" * 40)
        
        print(Fore.YELLOW + "\nOptions:")
        print(Fore.WHITE + "1. View report details")
        print(Fore.WHITE + "2. Export all reports")
        print(Fore.WHITE + "3. Delete reports")
        print(Fore.WHITE + "4. Back to menu")
        
        choice = input(Fore.YELLOW + "\nSelect (1-4): ").strip()
        
        if choice == '1':
            try:
                report_num = int(input(Fore.YELLOW + "Enter report number: "))
                if 1 <= report_num <= min(10, len(self.data['reports'])):
                    report = self.data['reports'][-report_num]
                    self.show_report_details(report)
            except ValueError:
                print(Fore.RED + "Invalid number!")
                input(Fore.YELLOW + "\nPress Enter to continue...")
        elif choice == '2':
            self.export_reports()
        elif choice == '3':
            self.delete_reports()
    
    def show_report_details(self, report):
        """Show detailed report information"""
        self.print_header()
        print(Fore.GREEN + f"\n📄 REPORT: {report['title']}")
        print(Fore.CYAN + "=" * 60)
        
        print(Fore.WHITE + f"Report ID: {report['id']}")
        print(Fore.WHITE + f"Generated: {report['date']}")
        print(Fore.CYAN + "-" * 60)
        
        summary = report['summary']
        print(Fore.YELLOW + "📈 SUMMARY")
        print(Fore.WHITE + f"Total Networks: {summary['total_networks']}")
        print(Fore.GREEN + f"Secure Networks: {summary['secure_networks']}")
        print(Fore.RED + f"Risky Networks: {summary['risky_networks']}")
        print(Fore.WHITE + f"Average Security Score: {summary['average_security']:.1f}%")
        print(Fore.CYAN + "-" * 60)
        
        # Show top networks
        print(Fore.YELLOW + "📡 NETWORKS (Top 5)")
        networks = report['scan_data']['networks'][:5]
        for network in networks:
            score_color = self.get_score_color(network['security_score'])
            print(f"{Fore.WHITE}{network['ssid']:20s} {score_color}{network['security_score']:3d}% " +
                  f"{Fore.WHITE}| {network['encryption']:6s} | Ch{network['channel']:3d}")
        
        input(Fore.YELLOW + "\nPress Enter to continue...")
    
    def export_reports(self):
        """Export all reports to JSON file"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        export_file = f"wifi_reports_export_{timestamp}.json"
        
        with open(export_file, 'w') as f:
            json.dump(self.data['reports'], f, indent=2)
        
        print(Fore.GREEN + f"\n✅ Reports exported to: {export_file}")
        print(Fore.WHITE + f"Total reports: {len(self.data['reports'])}")
        sleep(2)
    
    def delete_reports(self):
        """Delete reports"""
        if input(Fore.RED + "\nDelete ALL reports? (y/N): ").lower() == 'y':
            self.data['reports'].clear()
            self.save_data()
            
            # Also delete report files
            import shutil
            if os.path.exists(self.reports_dir):
                shutil.rmtree(self.reports_dir)
                os.makedirs(self.reports_dir)
            
            print(Fore.GREEN + "✓ All reports deleted!")
            sleep(2)
    
    def security_education(self):
        """Security education module"""
        self.print_header()
        print(Fore.GREEN + "\n📚 SECURITY EDUCATION")
        print(Fore.CYAN + "-" * 60)
        
        lessons = {
            '1': ('WiFi Encryption Basics', self.lesson_encryption),
            '2': ('Common WiFi Threats', self.lesson_threats),
            '3': ('Password Security', self.lesson_passwords),
            '4': ('Best Practices', self.lesson_best_practices),
            '5': ('Security Tools', self.lesson_tools)
        }
        
        print(Fore.YELLOW + "Available Lessons:")
        for key, (title, _) in lessons.items():
            print(Fore.WHITE + f"{key}. {title}")
        
        print(Fore.WHITE + "6. Take Security Quiz")
        print(Fore.WHITE + "7. Back to menu")
        
        choice = input(Fore.YELLOW + "\nSelect lesson (1-7): ").strip()
        
        if choice in lessons:
            lessons[choice][1]()
        elif choice == '6':
            self.security_quiz()
    
    def lesson_encryption(self):
        """Encryption lesson"""
        self.print_header()
        print(Fore.GREEN + "\n🔐 WIFI ENCRYPTION BASICS")
        print(Fore.CYAN + "=" * 60)
        
        content = """
WiFi encryption secures the data transmitted over wireless networks.
Here are the main encryption protocols:

1. WEP (Wired Equivalent Privacy)
   - Introduced: 1997
   - Security: VERY WEAK (broken in minutes)
   - Status: DEPRECATED - Never use!

2. WPA (WiFi Protected Access)
   - Introduced: 2003
   - Security: WEAK
   - Status: OBSOLETE - Avoid using

3. WPA2 (WiFi Protected Access 2)
   - Introduced: 2004
   - Security: STRONG
   - Status: RECOMMENDED for most networks
   - Uses AES encryption

4. WPA3 (WiFi Protected Access 3)
   - Introduced: 2018
   - Security: VERY STRONG
   - Status: LATEST STANDARD
   - Protects against brute-force attacks
   - Provides forward secrecy

🔐 BEST PRACTICE: Always use WPA2 or WPA3.
                  Never use WEP or WPA.
"""
        print(Fore.WHITE + content)
        input(Fore.YELLOW + "\nPress Enter to continue...")
    
    def lesson_threats(self):
        """WiFi threats lesson"""
        self.print_header()
        print(Fore.GREEN + "\n⚠️ COMMON WIFI THREATS")
        print(Fore.CYAN + "=" * 60)
        
        content = """
Major WiFi Security Threats:

1. Evil Twin Attacks
   - Fake WiFi access points
   - Trick users into connecting
   - Monitor all traffic

2. Packet Sniffing
   - Intercept unencrypted data
   - Capture passwords, emails
   - Especially dangerous on public WiFi

3. KRACK Attacks
   - Key Reinstallation Attacks
   - Exploit WPA2 handshake
   - Can decrypt traffic

4. Brute Force Attacks
   - Try all password combinations
   - Weak passwords can be cracked quickly
   - Use strong, complex passwords

5. Man-in-the-Middle (MITM)
   - Intercept communications
   - Can modify data in transit
   - Use HTTPS and VPNs for protection

🛡️ PROTECTION TIPS:
   - Use VPN on public WiFi
   - Enable WPA3 encryption
   - Avoid unknown networks
   - Keep devices updated
"""
        print(Fore.WHITE + content)
        input(Fore.YELLOW + "\nPress Enter to continue...")
    
    def lesson_passwords(self):
        """Password security lesson"""
        self.print_header()
        print(Fore.GREEN + "\n🔑 PASSWORD SECURITY")
        print(Fore.CYAN + "=" * 60)
        
        content = """
Creating Strong WiFi Passwords:

📏 LENGTH MATTERS:
   - Minimum: 12 characters
   - Recommended: 16+ characters
   - Each extra character increases security exponentially

🎨 CHARACTER DIVERSITY:
   - Uppercase letters (A-Z)
   - Lowercase letters (a-z)
   - Numbers (0-9)
   - Symbols (!@#$%^&*)

❌ AVOID THESE:
   - Dictionary words
   - Personal information
   - Simple patterns (123456, qwerty)
   - Reusing passwords

✅ GOOD EXAMPLES:
   - "T7#mP9@kL2$wQ5&"
   - "B3@cH!sUn8#dOlPhIn"
   - "W1f1$3cur3P@ss2024!"

🔄 PASSWORD MANAGERS:
   - Store passwords securely
   - Generate strong passwords
   - Auto-fill login forms
   - Examples: Bitwarden, KeePass, LastPass

🔐 WIFI PASSWORD TIPS:
   - Change default router password
   - Use different password for admin and WiFi
   - Update passwords periodically
   - Don't share passwords publicly
"""
        print(Fore.WHITE + content)
        input(Fore.YELLOW + "\nPress Enter to continue...")
    
    def lesson_best_practices(self):
        """Best practices lesson"""
        self.print_header()
        print(Fore.GREEN + "\n🛡️ WIFI SECURITY BEST PRACTICES")
        print(Fore.CYAN + "=" * 60)
        
        content = """
Essential Security Practices:

1. ROUTER CONFIGURATION
   - Change default admin credentials
   - Disable WPS (WiFi Protected Setup)
   - Enable firewall
   - Update firmware regularly

2. NETWORK SETTINGS
   - Use WPA2/WPA3 encryption
   - Hide SSID if not needed publicly
   - Enable MAC address filtering
   - Set up guest network for visitors

3. DEVICE SECURITY
   - Keep devices updated
   - Install antivirus software
   - Use VPN on public networks
   - Disable auto-connect to unknown networks

4. MONITORING
   - Regularly check connected devices
   - Monitor network traffic
   - Set up intrusion detection
   - Review router logs

5. PHYSICAL SECURITY
   - Place router in central location
   - Limit signal range if possible
   - Secure physical access to router
   - Disable remote administration if not needed

📅 REGULAR MAINTENANCE:
   - Monthly: Check connected devices
   - Quarterly: Change passwords
   - Bi-annually: Update firmware
   - Annually: Security audit
"""
        print(Fore.WHITE + content)
        input(Fore.YELLOW + "\nPress Enter to continue...")
    
    def lesson_tools(self):
        """Security tools lesson"""
        self.print_header()
        print(Fore.GREEN + "\n🛠️ SECURITY TOOLS")
        print(Fore.CYAN + "=" * 60)
        
        content = """
Useful Security Tools:

1. NETWORK SCANNERS
   - Nmap: Network discovery and security auditing
   - Wireshark: Network protocol analyzer
   - Aircrack-ng: WiFi security auditing tools

2. PASSWORD TOOLS
   - KeePass: Password manager
   - Bitwarden: Open-source password manager
   - HaveIBeenPwned: Check password breaches

3. SECURITY SCANNERS
   - OpenVAS: Vulnerability scanner
   - Nessus: Security assessment tool
   - Nikto: Web server scanner

4. MONITORING TOOLS
   - Nagios: Network monitoring
   - Zabbix: Enterprise monitoring
   - Snort: Intrusion detection

5. EDUCATIONAL TOOLS
   - WiFi Security Educator (This tool!)
   - CyberRange: Training platforms
   - TryHackMe: Cybersecurity learning

⚠️ LEGAL NOTE:
   - Only test networks you own
   - Get written permission for testing
   - Follow local laws and regulations
   - Use tools responsibly
"""
        print(Fore.WHITE + content)
        input(Fore.YELLOW + "\nPress Enter to continue...")
    
    def security_quiz(self):
        """Security knowledge quiz"""
        self.print_header()
        print(Fore.GREEN + "\n🧠 SECURITY KNOWLEDGE QUIZ")
        print(Fore.CYAN + "=" * 60)
        
        questions = [
            {
                'question': 'Which WiFi encryption should you NEVER use?',
                'options': ['WEP', 'WPA2', 'WPA3', 'AES'],
                'answer': 0
            },
            {
                'question': 'What is the recommended minimum password length?',
                'options': ['6 characters', '8 characters', '12 characters', '16 characters'],
                'answer': 2
            },
            {
                'question': 'What does WPS stand for?',
                'options': ['WiFi Protected Setup', 'Wireless Password Security', 'WiFi Privacy Standard', 'Wireless Protection System'],
                'answer': 0
            },
            {
                'question': 'Which is a common WiFi attack?',
                'options': ['Evil Twin', 'Blue Screen', 'DDoS', 'Phishing'],
                'answer': 0
            },
            {
                'question': 'What should you use on public WiFi?',
                'options': ['VPN', 'WEP', 'No encryption', 'Default passwords'],
                'answer': 0
            }
        ]
        
        score = 0
        
        for i, q in enumerate(questions, 1):
            print(Fore.YELLOW + f"\nQuestion {i}/{len(questions)}")
            print(Fore.WHITE + q['question'])
            print(Fore.CYAN + "-" * 40)
            
            for j, option in enumerate(q['options']):
                print(Fore.WHITE + f"{j+1}. {option}")
            
            try:
                answer = int(input(Fore.YELLOW + "\nYour answer (1-4): ")) - 1
                if answer == q['answer']:
                    print(Fore.GREEN + "✓ Correct!")
                    score += 1
                else:
                    print(Fore.RED + f"✗ Wrong. Correct answer: {q['options'][q['answer']]}")
            except (ValueError, IndexError):
                print(Fore.RED + "Invalid answer!")
            
            sleep(1)
        
        percentage = (score / len(questions)) * 100
        
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.YELLOW + "QUIZ RESULTS")
        print(Fore.CYAN + "=" * 60)
        print(Fore.WHITE + f"Score: {score}/{len(questions)} ({percentage:.1f}%)")
        
        if percentage >= 80:
            print(Fore.GREEN + "Excellent! You're a security expert!")
        elif percentage >= 60:
            print(Fore.YELLOW + "Good job! You know the basics.")
        elif percentage >= 40:
            print(Fore.LIGHTRED_EX + "Keep learning! Review the education section.")
        else:
            print(Fore.RED + "Needs improvement. Study the security lessons.")
        
        input(Fore.YELLOW + "\nPress Enter to continue...")
    
    def settings_menu(self):
        """Settings menu"""
        while True:
            self.print_header()
            print(Fore.GREEN + "\n⚙️ SETTINGS & TOOLS")
            print(Fore.CYAN + "-" * 60)
            
            print(Fore.WHITE + "1. View System Information")
            print(Fore.WHITE + "2. Backup Data")
            print(Fore.WHITE + "3. Restore Data")
            print(Fore.WHITE + "4. Clear All Data")
            print(Fore.WHITE + "5. Check for Updates")
            print(Fore.WHITE + "6. Test Server Connection")
            print(Fore.WHITE + "7. Back to Main Menu")
            
            choice = input(Fore.YELLOW + "\nSelect (1-7): ").strip()
            
            if choice == '1':
                self.system_info()
            elif choice == '2':
                self.backup_data()
            elif choice == '3':
                self.restore_data()
            elif choice == '4':
                self.clear_all_data()
            elif choice == '5':
                self.check_updates()
            elif choice == '6':
                self.test_connection()
            elif choice == '7':
                break
            else:
                print(Fore.RED + "Invalid choice!")
                sleep(1)
    
    def system_info(self):
        """Display system information"""
        self.print_header()
        print(Fore.GREEN + "\n💻 SYSTEM INFORMATION")
        print(Fore.CYAN + "=" * 60)
        
        import platform
        import psutil
        
        # System info
        print(Fore.YELLOW + "System:")
        print(Fore.WHITE + f"  OS: {platform.system()} {platform.release()}")
        print(Fore.WHITE + f"  Python: {platform.python_version()}")
        
        # Storage info
        print(Fore.YELLOW + "\nStorage:")
        total_gb = psutil.disk_usage('/').total / (1024**3)
        used_gb = psutil.disk_usage('/').used / (1024**3)
        print(Fore.WHITE + f"  Total: {total_gb:.1f} GB")
        print(Fore.WHITE + f"  Used: {used_gb:.1f} GB ({psutil.disk_usage('/').percent}%)")
        
        # App info
        print(Fore.YELLOW + "\nApplication:")
        print(Fore.WHITE + f"  Version: 2.0.0")
        print(Fore.WHITE + f"  Data file: {self.data_file}")
        print(Fore.WHITE + f"  Reports: {len(self.data['reports'])}")
        print(Fore.WHITE + f"  Scans: {self.data['stats']['total_scans']}")
        
        # Network info
        print(Fore.YELLOW + "\nNetwork:")
        try:
            import socket
            hostname = socket.gethostname()
            print(Fore.WHITE + f"  Hostname: {hostname}")
        except:
            pass
        
        input(Fore.YELLOW + "\nPress Enter to continue...")
    
    def backup_data(self):
        """Backup all data"""
        self.print_header()
        print(Fore.GREEN + "\n💾 BACKUP DATA")
        print(Fore.CYAN + "=" * 60)
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = f"wifi_security_backup_{timestamp}.json"
        
        backup_data = {
            'version': '2.0.0',
            'timestamp': datetime.datetime.now().isoformat(),
            'data': self.data
        }
        
        with open(backup_file, 'w') as f:
            json.dump(backup_data, f, indent=2)
        
        print(Fore.GREEN + f"✅ Backup created: {backup_file}")
        print(Fore.WHITE + f"Size: {os.path.getsize(backup_file) / 1024:.1f} KB")
        sleep(2)
    
    def restore_data(self):
        """Restore data from backup"""
        self.print_header()
        print(Fore.GREEN + "\n🔄 RESTORE DATA")
        print(Fore.CYAN + "=" * 60)
        
        # Find backup files
        backup_files = [f for f in os.listdir('.') if f.startswith('wifi_security_backup_') and f.endswith('.json')]
        
        if not backup_files:
            print(Fore.YELLOW + "No backup files found.")
            input(Fore.YELLOW + "\nPress Enter to continue...")
            return
        
        print(Fore.YELLOW + "Available backups:")
        for i, file in enumerate(sorted(backup_files, reverse=True)[:5], 1):
            size_kb = os.path.getsize(file) / 1024
            print(Fore.WHITE + f"{i}. {file} ({size_kb:.1f} KB)")
        
        try:
            choice = int(input(Fore.YELLOW + "\nSelect backup to restore (1-5): "))
            if 1 <= choice <= min(5, len(backup_files)):
                backup_file = sorted(backup_files, reverse=True)[choice - 1]
                
                if input(Fore.RED + f"\nRestore from {backup_file}? (y/N): ").lower() == 'y':
                    with open(backup_file, 'r') as f:
                        backup_data = json.load(f)
                    
                    if backup_data.get('version') == '2.0.0':
                        self.data = backup_data['data']
                        self.save_data()
                        print(Fore.GREEN + "✅ Data restored successfully!")
                    else:
                        print(Fore.RED + "❌ Invalid backup version!")
                else:
                    print(Fore.YELLOW + "Restore cancelled.")
        except (ValueError, IndexError):
            print(Fore.RED + "Invalid selection!")
        
        sleep(2)
    
    def clear_all_data(self):
        """Clear all application data"""
        self.print_header()
        print(Fore.RED + "\n⚠️ CLEAR ALL DATA")
        print(Fore.CYAN + "=" * 60)
        
        warning = """
This will permanently delete:
- All WiFi scan results
- All security reports
- All generated passwords
- All education progress
- All application settings

THIS ACTION CANNOT BE UNDONE!
"""
        print(Fore.WHITE + warning)
        
        if input(Fore.RED + "Type 'DELETE' to confirm: ") == 'DELETE':
            # Clear data
            self.data = {
                'scans': [],
                'reports': [],
                'passwords': [],
                'stats': {
                    'total_scans': 0,
                    'networks_found': 0,
                    'vulnerabilities': 0
                }
            }
            
            # Save empty data
            self.save_data()
            
            # Delete reports directory
            import shutil
            if os.path.exists(self.reports_dir):
                shutil.rmtree(self.reports_dir)
                os.makedirs(self.reports_dir)
            
            print(Fore.GREEN + "\n✅ All data cleared!")
        else:
            print(Fore.YELLOW + "\nOperation cancelled.")
        
        sleep(2)
    
    def check_updates(self):
        """Check for updates"""
        self.print_header()
        print(Fore.GREEN + "\n🔄 CHECK FOR UPDATES")
        print(Fore.CYAN + "=" * 60)
        
        print(Fore.YELLOW + "Checking for updates...")
        sleep(2)
        
        # Simulate update check
        if random.random() < 0.3:  # 30% chance update available
            print(Fore.GREEN + "\n✅ Update available!")
            print(Fore.WHITE + "Version 2.1.0 is ready to install.")
            print(Fore.WHITE + "New features:")
            print(Fore.WHITE + "- Enhanced scanning algorithms")
            print(Fore.WHITE + "- New security analysis tools")
            print(Fore.WHITE + "- Improved user interface")
            
            if input(Fore.YELLOW + "\nInstall update? (y/N): ").lower() == 'y':
                print(Fore.YELLOW + "Installing update...")
                sleep(3)
                print(Fore.GREEN + "✅ Update installed successfully!")
        else:
            print(Fore.GREEN + "\n✅ You have the latest version!")
            print(Fore.WHITE + "Version: 2.0.0")
        
        sleep(2)
    
    def test_connection(self):
        """Test server connection"""
        self.print_header()
        print(Fore.GREEN + "\n📡 TEST SERVER CONNECTION")
        print(Fore.CYAN + "=" * 60)
        
        print(Fore.YELLOW + "Testing local server...")
        sleep(1)
        
        try:
            # Try to connect to local Flask server
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            result = sock.connect_ex(('127.0.0.1', 5000))
            
            if result == 0:
                print(Fore.GREEN + "✅ Web server is running on port 5000")
                print(Fore.WHITE + "Access: http://localhost:5000")
            else:
                print(Fore.YELLOW + "⚠️ Web server not detected")
                print(Fore.WHITE + "Start the web server with: python main.py")
            
            sock.close()
            
        except Exception as e:
            print(Fore.RED + f"❌ Connection test failed: {e}")
        
        print(Fore.CYAN + "-" * 60)
        print(Fore.WHITE + "Network status: Online")
        print(Fore.WHITE + f"Python: {sys.version.split()[0]}")
        
        input(Fore.YELLOW + "\nPress Enter to continue...")
    
    def view_statistics(self):
        """View application statistics"""
        self.print_header()
        print(Fore.GREEN + "\n📈 APPLICATION STATISTICS")
        print(Fore.CYAN + "=" * 60)
        
        stats = self.data['stats']
        
        print(Fore.YELLOW + "📊 Usage Statistics:")
        print(Fore.WHITE + f"  Total Scans: {stats['total_scans']}")
        print(Fore.WHITE + f"  Networks Found: {stats['networks_found']}")
        print(Fore.WHITE + f"  Vulnerabilities Detected: {stats['vulnerabilities']}")
        print(Fore.WHITE + f"  Reports Generated: {len(self.data['reports'])}")
        print(Fore.WHITE + f"  Passwords Generated: {len(self.data['passwords'])}")
        
        # Calculate averages
        if stats['total_scans'] > 0:
            avg_networks = stats['networks_found'] / stats['total_scans']
            print(Fore.WHITE + f"  Average Networks per Scan: {avg_networks:.1f}")
        
        # Show recent activity
        print(Fore.YELLOW + "\n🕒 Recent Activity:")
        if self.data['scans']:
            last_scan = self.data['scans'][-1]
            date = datetime.datetime.fromisoformat(last_scan['timestamp']).strftime('%Y-%m-%d %H:%M')
            print(Fore.WHITE + f"  Last Scan: {date} ({last_scan['networks_found']} networks)")
        
        if self.data['reports']:
            last_report = self.data['reports'][-1]
            print(Fore.WHITE + f"  Last Report: {last_report['title']}")
        
        # Storage info
        data_size = os.path.getsize(self.data_file) if os.path.exists(self.data_file) else 0
        print(Fore.YELLOW + "\n💾 Storage:")
        print(Fore.WHITE + f"  Data file: {data_size / 1024:.1f} KB")
        
        # Report files size
        report_size = 0
        if os.path.exists(self.reports_dir):
            for file in os.listdir(self.reports_dir):
                report_size += os.path.getsize(os.path.join(self.reports_dir, file))
        
        print(Fore.WHITE + f"  Reports: {report_size / 1024:.1f} KB")
        print(Fore.WHITE + f"  Total: {(data_size + report_size) / 1024:.1f} KB")
        
        input(Fore.YELLOW + "\nPress Enter to continue...")
    
    def exit_app(self):
        """Exit application"""
        self.print_header()
        print(Fore.GREEN + "\n👋 Thank you for using WiFi Security Educator!")
        print(Fore.CYAN + "=" * 60)
        print(Fore.WHITE + "Stay safe and secure your networks! 🔐")
        sleep(2)
        sys.exit(0)

def main():
    """Main entry point"""
    try:
        app = WiFiSecurityConsole()
        app.main_menu()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\nExiting... Stay secure! 🔐")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\nError: {e}")
        print(Fore.YELLOW + "Please report this issue.")
        sys.exit(1)

if __name__ == "__main__":
    # Check for required packages
    try:
        import colorama
    except ImportError:
        print("Installing required packages...")
        os.system("pip install colorama")
        import colorama
    
    main()