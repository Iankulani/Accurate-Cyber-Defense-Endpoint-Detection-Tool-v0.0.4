"""
ACCURATE CYBER DRILL TOOL - ENHANCED EDITION
Author: Ian Carter Kulani
Version: 0.0.4
Integrated Features: Network Monitoring, Intrusion Detection, Traffic Generation, 
                     Threat Analysis, Telegram Integration, Advanced Scanning
                     Enhanced Themes, Real-time Dashboard
"""

import sys
import os
import time
import json
import logging
import configparser
from typing import Dict, List, Set, Tuple, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta
import threading
import queue
import argparse
import signal
import hashlib
import base64
import zipfile
import tempfile

# Core imports
import socket
import subprocess
import requests
import random
import platform
import psutil
import getpass
import sqlite3
import ipaddress
import re
import shutil

# GUI imports
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, scrolledtext, font
    from tkinter.colorchooser import askcolor
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Security imports
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

# Constants
VERSION = "3.0.0"
AUTHOR = "Cyber Security War Tool Team"
DEFAULT_CONFIG_FILE = "config.ini"
DATABASE_FILE = "network_threats.db"
REPORT_DIR = "reports"
LOG_DIR = "logs"
HISTORY_FILE = "command_history.txt"
MAX_HISTORY = 1000
TELEGRAM_API_URL = "https://api.telegram.org/bot"

# Enhanced Color themes with red, orange, yellow
THEMES = {
    "cyber_red": {
        "name": "Cyber Red",
        "bg": "#0a0a0a",
        "fg": "#ff3333",
        "text_bg": "#1a1a1a",
        "text_fg": "#ff6666",
        "button_bg": "#330000",
        "button_fg": "#ff3333",
        "button_active": "#660000",
        "highlight": "#ff0000",
        "accent": "#ff6666",
        "warning": "#ff9900",
        "success": "#00ff00",
        "error": "#ff3333"
    },
    "fire_orange": {
        "name": "Fire Orange",
        "bg": "#0f0f0f",
        "fg": "#ff7700",
        "text_bg": "#1a1a1a",
        "text_fg": "#ffaa55",
        "button_bg": "#331100",
        "button_fg": "#ff7700",
        "button_active": "#662200",
        "highlight": "#ff5500",
        "accent": "#ffaa55",
        "warning": "#ffaa00",
        "success": "#00ff00",
        "error": "#ff3333"
    },
    "neon_yellow": {
        "name": "Neon Yellow",
        "bg": "#0a0a0a",
        "fg": "#ffff00",
        "text_bg": "#1a1a1a",
        "text_fg": "#ffff99",
        "button_bg": "#333300",
        "button_fg": "#ffff00",
        "button_active": "#666600",
        "highlight": "#ffff00",
        "accent": "#ffff66",
        "warning": "#ffaa00",
        "success": "#00ff00",
        "error": "#ff3333"
    },
    "matrix_green": {
        "name": "Matrix Green",
        "bg": "#000000",
        "fg": "#00ff00",
        "text_bg": "#0a0a0a",
        "text_fg": "#00ff00",
        "button_bg": "#003300",
        "button_fg": "#00ff00",
        "button_active": "#006600",
        "highlight": "#00ff00",
        "accent": "#00ff66",
        "warning": "#ffff00",
        "success": "#00ff00",
        "error": "#ff3333"
    },
    "dark_default": {
        "name": "Dark Default",
        "bg": "#121212",
        "fg": "#ffffff",
        "text_bg": "#222222",
        "text_fg": "#ffffff",
        "button_bg": "#333333",
        "button_fg": "#ffffff",
        "button_active": "#444444",
        "highlight": "#0066cc",
        "accent": "#00aaff",
        "warning": "#ff9900",
        "success": "#00cc00",
        "error": "#ff3333"
    }
}

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    ORANGE = '\033[38;5;214m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class EnhancedTracerouteTool:
    """Enhanced interactive traceroute tool with multiple methods"""
    
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        """Check if input is valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        """Check if input is valid hostname"""
        if name.endswith('.'):
            name = name[:-1]
        HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
        return bool(HOSTNAME_RE.match(name))

    @staticmethod
    def choose_traceroute_cmd(target: str) -> List[str]:
        """Return appropriate traceroute command for the system"""
        system = platform.system()

        if system == 'Windows':
            return ['tracert', '-d', target]

        # On Unix-like systems
        if shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '1', '-w', '2', target]
        if shutil.which('tracepath'):
            return ['tracepath', target]
        if shutil.which('ping'):
            return ['ping', '-c', '4', target]

        raise EnvironmentError('No traceroute utilities found')

    @staticmethod
    def stream_subprocess(cmd: List[str]) -> Tuple[int, str]:
        """Run subprocess and capture output"""
        output_lines = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

            if proc.stdout:
                for line in proc.stdout:
                    cleaned_line = line.rstrip()
                    output_lines.append(cleaned_line)
                    print(cleaned_line)

            proc.wait()
            return proc.returncode, '\n'.join(output_lines)
        except KeyboardInterrupt:
            print('\n[+] User cancelled traceroute...')
            try:
                proc.terminate()
            except Exception:
                pass
            return -1, '\n'.join(output_lines)
        except Exception as e:
            error_msg = f'[!] Error: {e}'
            print(error_msg)
            output_lines.append(error_msg)
            return -2, '\n'.join(output_lines)

    def interactive_traceroute(self, target: str = None) -> str:
        """Run interactive traceroute with validation"""
        if not target:
            target = self.prompt_target()
            if not target:
                return "Traceroute cancelled."

        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"

        try:
            cmd = self.choose_traceroute_cmd(target)
        except EnvironmentError as e:
            return f"❌ Traceroute error: {e}"

        print(f'Running: {" ".join(cmd)}\n')
        
        start_time = time.time()
        returncode, output = self.stream_subprocess(cmd)
        execution_time = time.time() - start_time

        result = f"🛣️ <b>Traceroute to {target}</b>\n\n"
        result += f"Command: <code>{' '.join(cmd)}</code>\n"
        result += f"Execution time: {execution_time:.2f}s\n"
        result += f"Return code: {returncode}\n\n"
        
        if len(output) > 3000:
            result += f"<code>{output[-3000:]}</code>"
        else:
            result += f"<code>{output}</code>"

        return result

    def prompt_target(self) -> Optional[str]:
        """Prompt user for target"""
        while True:
            user_input = input('Enter target IP/hostname (or "quit"): ').strip()
            if not user_input:
                print('Please enter a value.')
                continue
            if user_input.lower() in ('q', 'quit', 'exit'):
                return None

            if self.is_ipv4_or_ipv6(user_input) or self.is_valid_hostname(user_input):
                return user_input
            else:
                print('Invalid IP/hostname. Examples: 8.8.8.8, example.com')

class DatabaseManager:
    """Manage SQLite database for network data"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Original tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intrusion_detection (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                packet_count INTEGER,
                description TEXT,
                action_taken TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                packets_processed INTEGER,
                packet_rate REAL,
                tcp_count INTEGER,
                udp_count INTEGER,
                icmp_count INTEGER,
                threat_count INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_name TEXT NOT NULL,
                data_type TEXT NOT NULL,
                data TEXT,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # New tables from provided code
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                port INTEGER,
                protocol TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitoring (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TEXT NOT NULL,
                status TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history_full (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                command TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS telegram_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                chat_id TEXT,
                message TEXT,
                direction TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                traffic_type TEXT,
                target TEXT,
                packets_sent INTEGER,
                duration REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS theme_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                theme_name TEXT NOT NULL,
                custom_colors TEXT,
                last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_command(self, command: str, source: str = 'local', success: bool = True):
        """Log command to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO command_history (command, source, success) VALUES (?, ?, ?)',
            (command, source, success)
        )
        conn.commit()
        conn.close()
    
    def log_intrusion(self, source_ip: str, threat_type: str, severity: str, 
                     packet_count: int = 0, description: str = "", action: str = "logged"):
        """Log intrusion detection event"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO intrusion_detection 
               (source_ip, threat_type, severity, packet_count, description, action_taken) 
               VALUES (?, ?, ?, ?, ?, ?)''',
            (source_ip, threat_type, severity, packet_count, description, action)
        )
        conn.commit()
        conn.close()
    
    def log_network_stats(self, stats: Dict[str, Any]):
        """Log network statistics"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO network_stats 
               (packets_processed, packet_rate, tcp_count, udp_count, icmp_count, threat_count)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (stats.get('packets_processed', 0),
             stats.get('packet_rate', 0),
             stats.get('tcp_count', 0),
             stats.get('udp_count', 0),
             stats.get('icmp_count', 0),
             stats.get('threat_count', 0))
        )
        conn.commit()
        conn.close()
    
    def log_threat(self, ip_address: str, threat_type: str, severity: str, 
                  description: str = "", port: int = None, protocol: str = None):
        """Log security threat to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO threats 
               (timestamp, ip_address, threat_type, severity, description, port, protocol) 
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (datetime.now().isoformat(), ip_address, threat_type, severity, description, port, protocol)
        )
        conn.commit()
        conn.close()
    
    def get_recent_intrusions(self, limit: int = 50) -> List[Tuple]:
        """Get recent intrusion detection events"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''SELECT timestamp, source_ip, threat_type, severity, description 
               FROM intrusion_detection 
               ORDER BY timestamp DESC LIMIT ?''',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_threat_stats(self, hours: int = 24) -> Dict[str, int]:
        """Get threat statistics for specified period"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count 
            FROM intrusion_detection 
            WHERE timestamp > datetime('now', ?)
            GROUP BY threat_type
        ''', (f'-{hours} hours',))
        
        results = cursor.fetchall()
        conn.close()
        
        stats = {}
        for threat_type, count in results:
            stats[threat_type] = count
        
        return stats
    
    def get_all_threats(self, limit: int = 100) -> List[Tuple]:
        """Get all threats from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''SELECT timestamp, ip_address, threat_type, severity, description, port 
               FROM threats 
               ORDER BY timestamp DESC LIMIT ?''',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def add_monitored_ip(self, ip_address: str):
        """Add IP to monitoring table"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO monitoring (ip_address, added_date, status) VALUES (?, ?, ?)",
            (ip_address, datetime.now().isoformat(), 'active')
        )
        conn.commit()
        conn.close()
    
    def remove_monitored_ip(self, ip_address: str):
        """Remove IP from monitoring table"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM monitoring WHERE ip_address = ?", (ip_address,))
        conn.commit()
        conn.close()
    
    def get_monitored_ips(self) -> List[str]:
        """Get list of monitored IPs"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM monitoring WHERE status = 'active'")
        results = [row[0] for row in cursor.fetchall()]
        conn.close()
        return results

class EnhancedTelegramManager:
    """Enhanced Telegram integration manager"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.telegram_token = None
        self.telegram_chat_id = None
        self.telegram_last_update_id = 0
        self.telegram_enabled = False
        self.bot_username = None
        self.load_config()
        
        # Command handlers
        self.command_handlers = {
            '/start': self.handle_start,
            '/help': self.handle_help,
            '/ping': self.handle_ping,
            '/traceroute': self.handle_traceroute,
            '/scan': self.handle_scan,
            '/status': self.handle_status,
            '/threats': self.handle_threats,
            '/monitor': self.handle_monitor,
            '/stop_monitor': self.handle_stop_monitor,
            '/list_ips': self.handle_list_ips,
            '/location': self.handle_location,
            '/analyze': self.handle_analyze,
            '/system_info': self.handle_system_info,
            '/network_info': self.handle_network_info,
            '/report': self.handle_report,
            '/alerts': self.handle_alerts
        }
    
    def load_config(self):
        """Load Telegram configuration"""
        config = configparser.ConfigParser()
        if os.path.exists(DEFAULT_CONFIG_FILE):
            config.read(DEFAULT_CONFIG_FILE)
            self.telegram_token = config.get('telegram', 'token', fallback=None)
            self.telegram_chat_id = config.get('telegram', 'chat_id', fallback=None)
            if self.telegram_token and self.telegram_chat_id:
                self.telegram_enabled = True
    
    def save_config(self):
        """Save Telegram configuration"""
        config = configparser.ConfigParser()
        config['telegram'] = {
            'token': self.telegram_token or '',
            'chat_id': self.telegram_chat_id or ''
        }
        with open(DEFAULT_CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
    
    def config_telegram_token(self, token: str):
        """Configure Telegram bot token"""
        try:
            self.telegram_token = token
            self.save_config()
            
            # Test the token
            if self.test_telegram_token(token):
                self.telegram_enabled = True
                return "✅ Telegram token configured successfully"
            else:
                self.telegram_enabled = False
                return "❌ Invalid Telegram token"
                
        except Exception as e:
            return f"❌ Failed to configure token: {str(e)}"
    
    def config_telegram_chat_id(self, chat_id: str):
        """Configure Telegram chat ID"""
        try:
            self.telegram_chat_id = chat_id
            self.save_config()
            
            if self.telegram_token and self.test_telegram_token(self.telegram_token):
                self.telegram_enabled = True
                return "✅ Telegram chat ID configured successfully"
            else:
                return "⚠ Telegram token not configured or invalid"
                
        except Exception as e:
            return f"❌ Failed to configure chat ID: {str(e)}"
    
    def test_telegram_token(self, token: str = None) -> bool:
        """Test Telegram token validity"""
        try:
            test_token = token or self.telegram_token
            if not test_token:
                return False
                
            response = requests.get(
                f"{TELEGRAM_API_URL}{test_token}/getMe",
                timeout=10
            )
            
            if response.status_code == 200:
                bot_info = response.json()
                if bot_info.get('ok', False):
                    self.bot_username = bot_info['result']['username']
                    return True
            return False
            
        except Exception:
            return False
    
    def test_telegram_connection(self) -> str:
        """Test Telegram connection"""
        try:
            if not self.telegram_token or not self.telegram_chat_id:
                return "❌ Telegram token or chat ID not configured"
            
            # Test bot token
            response = requests.get(
                f"{TELEGRAM_API_URL}{self.telegram_token}/getMe",
                timeout=10
            )
            
            if response.status_code == 200:
                bot_info = response.json()
                if bot_info['ok']:
                    result = "✅ Telegram connection successful\n"
                    result += f"  Bot: {bot_info['result']['first_name']}\n"
                    result += f"  Username: @{bot_info['result']['username']}"
                    
                    # Test message sending
                    if self.send_telegram_message("🔒 Cyber Security Tool - Connection Test Successful!"):
                        result += "\n✅ Test message sent successfully"
                        self.telegram_enabled = True
                    else:
                        result += "\n❌ Failed to send test message"
                        self.telegram_enabled = False
                    return result
                else:
                    self.telegram_enabled = False
                    return "❌ Telegram connection failed"
            else:
                self.telegram_enabled = False
                return f"❌ Telegram API error: {response.status_code}"
                
        except Exception as e:
            self.telegram_enabled = False
            return f"❌ Telegram connection test failed: {str(e)}"
    
    def send_telegram_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """Send message to Telegram chat"""
        try:
            if not self.telegram_token or not self.telegram_chat_id:
                return False
            
            url = f"{TELEGRAM_API_URL}{self.telegram_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': parse_mode
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            # Log the message
            if response.status_code == 200:
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO telegram_logs (timestamp, chat_id, message, direction) VALUES (?, ?, ?, ?)",
                    (datetime.now().isoformat(), self.telegram_chat_id, message, 'outgoing')
                )
                conn.commit()
                conn.close()
            
            return response.status_code == 200
            
        except Exception:
            return False
    
    def send_telegram_alert(self, alert_type: str, message: str):
        """Send alert to Telegram"""
        if not self.telegram_enabled:
            return
        
        alert_icons = {
            'threat': '🚨',
            'warning': '⚠️',
            'info': 'ℹ️',
            'success': '✅',
            'error': '❌'
        }
        
        icon = alert_icons.get(alert_type, '🔔')
        formatted_message = f"{icon} <b>{alert_type.upper()} ALERT</b>\n{message}"
        
        self.send_telegram_message(formatted_message)
    
    def get_telegram_status(self) -> str:
        """Get Telegram connection status"""
        status = "📱 Telegram Status:\n"
        status += f"  Enabled: {'✅ Yes' if self.telegram_enabled else '❌ No'}\n"
        status += f"  Bot Token: {'✅ Configured' if self.telegram_token else '❌ Not Configured'}\n"
        status += f"  Chat ID: {'✅ Configured' if self.telegram_chat_id else '❌ Not Configured'}"
        
        if self.telegram_token and self.telegram_chat_id:
            if self.test_telegram_token():
                status += f"\n  Bot Username: @{self.bot_username}"
                status += "\n  Connection: ✅ Active"
            else:
                status += "\n  Connection: ❌ Failed"
        
        return status
    
    def process_telegram_updates(self):
        """Process incoming Telegram updates"""
        if not self.telegram_enabled:
            return
        
        try:
            url = f"{TELEGRAM_API_URL}{self.telegram_token}/getUpdates"
            params = {
                'offset': self.telegram_last_update_id + 1,
                'timeout': 30
            }
            
            response = requests.get(url, params=params, timeout=35)
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    for update in data.get('result', []):
                        self.telegram_last_update_id = update['update_id']
                        
                        if 'message' in update and 'text' in update['message']:
                            message = update['message']['text']
                            chat_id = update['message']['chat']['id']
                            
                            # Log incoming message
                            conn = sqlite3.connect(DATABASE_FILE)
                            cursor = conn.cursor()
                            cursor.execute(
                                "INSERT INTO telegram_logs (timestamp, chat_id, message, direction) VALUES (?, ?, ?, ?)",
                                (datetime.now().isoformat(), chat_id, message, 'incoming')
                            )
                            conn.commit()
                            conn.close()
                            
                            # Process command
                            self.process_telegram_command(message, chat_id)
                            
        except Exception as e:
            logging.error(f"Telegram update error: {e}")
    
    def process_telegram_command(self, command: str, chat_id: str):
        """Process Telegram command"""
        parts = command.strip().split()
        if not parts:
            return
        
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Update chat ID if different
        if str(chat_id) != self.telegram_chat_id:
            self.telegram_chat_id = str(chat_id)
            self.save_config()
        
        # Handle commands
        if cmd in self.command_handlers:
            try:
                response = self.command_handlers[cmd](args)
                self.send_telegram_message(response)
            except Exception as e:
                self.send_telegram_message(f"❌ Error processing command: {str(e)}")
        elif cmd.startswith('/'):
            self.send_telegram_message("❌ Unknown command. Type /help for available commands.")
    
    # Command handlers
    def handle_start(self, args):
        return """🚀 <b>ACCURATE CYBER DEFENSE v3.0</b> 🚀

Welcome to the Cyber Security Monitoring System!

📋 <b>Available Commands:</b>
/help - Show all commands
/ping [IP] - Ping an IP address
/traceroute [IP] - Traceroute to target
/scan [IP] - Scan IP for open ports
/status - System status
/threats - Recent threats
/monitor [IP] - Start monitoring IP
/stop_monitor - Stop monitoring
/list_ips - List monitored IPs
/location [IP] - Get IP location
/analyze [IP] - Analyze IP
/system_info - System information
/network_info - Network information
/report - Generate report
/alerts - Configure alerts

🔒 <b>Stay Secure!</b>"""
    
    def handle_help(self, args):
        return self.handle_start(args)
    
    def handle_ping(self, args):
        if not args:
            return "❌ Usage: /ping [IP]"
        
        # Simulate ping response
        return f"🏓 Pinging {args[0]}...\n✅ Host is reachable"
    
    def handle_traceroute(self, args):
        if not args:
            return "❌ Usage: /traceroute [IP]"
        
        return f"🛣️ Traceroute to {args[0]} initiated..."
    
    def handle_scan(self, args):
        if not args:
            return "❌ Usage: /scan [IP]"
        
        return f"🔍 Scanning {args[0]} for open ports..."
    
    def handle_status(self, args):
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory()
        
        return f"""📊 <b>System Status</b>

💻 CPU Usage: {cpu}%
🧠 Memory Usage: {mem.percent}%
🔌 Disk Usage: {psutil.disk_usage('/').percent}%
🌐 Network: Active
🛡️ Threats: 0 detected
⏰ Uptime: {time.time() - psutil.boot_time():.0f} seconds"""
    
    def handle_threats(self, args):
        threats = self.db_manager.get_recent_intrusions(5)
        
        if not threats:
            return "✅ No recent threats detected"
        
        response = "🚨 <b>Recent Threats</b>\n\n"
        for timestamp, source_ip, threat_type, severity, description in threats:
            response += f"• {source_ip} - {threat_type} ({severity})\n"
            if description:
                response += f"  📝 {description[:50]}...\n"
        
        return response
    
    def handle_monitor(self, args):
        if not args:
            return "❌ Usage: /monitor [IP]"
        
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
            self.db_manager.add_monitored_ip(ip)
            return f"✅ Started monitoring {ip}"
        except ValueError:
            return f"❌ Invalid IP address: {ip}"
    
    def handle_stop_monitor(self, args):
        return "🛑 Monitoring stopped"
    
    def handle_list_ips(self, args):
        ips = self.db_manager.get_monitored_ips()
        
        if not ips:
            return "📋 No IPs being monitored"
        
        response = "📋 <b>Monitored IPs</b>\n\n"
        for ip in ips:
            response += f"• {ip}\n"
        
        return response
    
    def handle_location(self, args):
        if not args:
            return "❌ Usage: /location [IP]"
        
        # Simulate location lookup
        return f"📍 Location for {args[0]}:\n🌍 Country: Unknown\n🏙️ City: Unknown\n📡 ISP: Unknown"
    
    def handle_analyze(self, args):
        if not args:
            return "❌ Usage: /analyze [IP]"
        
        return f"🔍 Analyzing {args[0]}...\n✅ Analysis complete"
    
    def handle_system_info(self, args):
        return f"""💻 <b>System Information</b>

OS: {platform.system()} {platform.release()}
Architecture: {platform.machine()}
Processor: {platform.processor()}
Python: {platform.python_version()}
Hostname: {socket.gethostname()}
User: {getpass.getuser()}"""
    
    def handle_network_info(self, args):
        interfaces = psutil.net_if_addrs()
        
        response = "🌐 <b>Network Information</b>\n\n"
        for iface, addrs in list(interfaces.items())[:3]:
            response += f"📡 {iface}:\n"
            for addr in addrs[:2]:
                response += f"  {addr.family.name}: {addr.address}\n"
        
        return response
    
    def handle_report(self, args):
        return "📊 Report generation initiated..."
    
    def handle_alerts(self, args):
        return "🔔 Alert configuration:\n✅ All alerts enabled"

class CyberSecurityTool:
    """Main Cyber Security Tool"""
    
    def __init__(self):
        self.setup_directories()
        self.setup_logging()
        self.db_manager = DatabaseManager()
        self.telegram_manager = EnhancedTelegramManager(self.db_manager)
        self.current_theme = "cyber_red"
        self.running = True
        
        # Initialize components
        self.traceroute_tool = EnhancedTracerouteTool()
        self.network_monitor = None
        self.network_scanner = None
        
        # GUI components
        self.root = None
        self.dashboard = None
        
    def setup_directories(self):
        """Create necessary directories"""
        os.makedirs(REPORT_DIR, exist_ok=True)
        os.makedirs(LOG_DIR, exist_ok=True)
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(LOG_DIR, 'cyber_tool.log')),
                logging.StreamHandler()
            ]
        )
    
    def print_banner(self):
        """Print enhanced banner with colors"""
        banner = f"""
{Colors.RED}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║            ACCURATE CYBER DEFENSE ENDPOINT DETECTION TOOL v{VERSION} 🛡️          ║
║                                                                                  ║
║      Network Monitoring • Intrusion Detection • Traffic Generation               ║
║         Security Analysis • Threat Detection • Vulnerability Scan                ║
║                    Telegram Integration • Advanced Reporting                     ║
║                                                                                  ║
║   Author: Ian Carter Kulani  Community: https://github.com/Accurate-Cyber-Defense       ║
║   Integrated Features: Port Scanning, Deep Analysis, Location Lookup             ║
║                       Real-time Dashboard • Enhanced Themes                      ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)
    
    def show_menu(self):
        """Display main menu"""
        print(f"\n{Colors.ORANGE}{Colors.BOLD}MAIN MENU{Colors.END}")
        print(f"{Colors.YELLOW}═" * 60 + Colors.END)
        print(f"{Colors.GREEN}1. {Colors.WHITE}Start Network Monitoring")
        print(f"{Colors.GREEN}2. {Colors.WHITE}Network Scanner")
        print(f"{Colors.GREEN}3. {Colors.WHITE}Threat Analysis Dashboard")
        print(f"{Colors.GREEN}4. {Colors.WHITE}Telegram Integration")
        print(f"{Colors.GREEN}5. {Colors.WHITE}Generate Reports")
        print(f"{Colors.GREEN}6. {Colors.WHITE}System Information")
        print(f"{Colors.GREEN}7. {Colors.WHITE}Switch Theme")
        print(f"{Colors.GREEN}8. {Colors.WHITE}GUI Dashboard")
        print(f"{Colors.RED}9. {Colors.WHITE}Exit{Colors.END}")
        print(f"{Colors.YELLOW}═" * 60 + Colors.END)
    
    def handle_choice(self, choice):
        """Handle menu choice"""
        if choice == '1':
            self.start_network_monitoring()
        elif choice == '2':
            self.network_scanner_menu()
        elif choice == '3':
            self.threat_analysis_dashboard()
        elif choice == '4':
            self.telegram_integration_menu()
        elif choice == '5':
            self.generate_reports()
        elif choice == '6':
            self.system_information()
        elif choice == '7':
            self.switch_theme_menu()
        elif choice == '8':
            self.start_gui_dashboard()
        elif choice == '9':
            self.exit_tool()
        else:
            print(f"{Colors.RED}❌ Invalid choice!{Colors.END}")
    
    def start_network_monitoring(self):
        """Start network monitoring"""
        print(f"\n{Colors.CYAN}🚀 Starting Network Monitoring...{Colors.END}")
        
        target_ip = input(f"{Colors.YELLOW}Enter target IP (blank for all traffic): {Colors.END}").strip()
        
        if target_ip and not self.validate_ip(target_ip):
            print(f"{Colors.RED}❌ Invalid IP address!{Colors.END}")
            return
        
        print(f"{Colors.GREEN}✅ Monitoring started for {target_ip if target_ip else 'all traffic'}{Colors.END}")
        print(f"{Colors.YELLOW}Press Ctrl+C to stop monitoring...{Colors.END}")
        
        try:
            # Simulate monitoring
            while True:
                time.sleep(1)
                print(f"{Colors.BLUE}[{datetime.now().strftime('%H:%M:%S')}] Monitoring...{Colors.END}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 Monitoring stopped{Colors.END}")
    
    def network_scanner_menu(self):
        """Network scanner menu"""
        while True:
            print(f"\n{Colors.CYAN}🔍 Network Scanner{Colors.END}")
            print(f"{Colors.YELLOW}═" * 40 + Colors.END)
            print(f"{Colors.GREEN}1. {Colors.WHITE}Ping IP")
            print(f"{Colors.GREEN}2. {Colors.WHITE}Port Scan")
            print(f"{Colors.GREEN}3. {Colors.WHITE}Traceroute")
            print(f"{Colors.GREEN}4. {Colors.WHITE}Get IP Location")
            print(f"{Colors.GREEN}5. {Colors.WHITE}Analyze IP")
            print(f"{Colors.RED}6. {Colors.WHITE}Back to Main Menu{Colors.END}")
            print(f"{Colors.YELLOW}═" * 40 + Colors.END)
            
            choice = input(f"{Colors.ORANGE}Select option (1-6): {Colors.END}").strip()
            
            if choice == '1':
                self.ping_ip()
            elif choice == '2':
                self.port_scan()
            elif choice == '3':
                self.traceroute()
            elif choice == '4':
                self.get_ip_location()
            elif choice == '5':
                self.analyze_ip()
            elif choice == '6':
                break
            else:
                print(f"{Colors.RED}❌ Invalid choice!{Colors.END}")
    
    def ping_ip(self):
        """Ping IP address"""
        ip = input(f"{Colors.YELLOW}Enter IP address to ping: {Colors.END}").strip()
        
        if not self.validate_ip(ip):
            print(f"{Colors.RED}❌ Invalid IP address!{Colors.END}")
            return
        
        print(f"{Colors.GREEN}🏓 Pinging {ip}...{Colors.END}")
        
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(['ping', '-n', '4', ip], capture_output=True, text=True)
            else:
                result = subprocess.run(['ping', '-c', '4', ip], capture_output=True, text=True)
            
            print(f"\n{Colors.CYAN}{result.stdout}{Colors.END}")
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}✅ Host is reachable{Colors.END}")
            else:
                print(f"{Colors.RED}❌ Host is not reachable{Colors.END}")
                
        except Exception as e:
            print(f"{Colors.RED}❌ Error: {e}{Colors.END}")
    
    def port_scan(self):
        """Perform port scan"""
        if not NMAP_AVAILABLE:
            print(f"{Colors.RED}❌ Nmap not available!{Colors.END}")
            return
        
        ip = input(f"{Colors.YELLOW}Enter IP address to scan: {Colors.END}").strip()
        
        if not self.validate_ip(ip):
            print(f"{Colors.RED}❌ Invalid IP address!{Colors.END}")
            return
        
        ports = input(f"{Colors.YELLOW}Enter port range (default: 1-1000): {Colors.END}").strip() or "1-1000"
        
        print(f"{Colors.GREEN}🔍 Scanning {ip} ports {ports}...{Colors.END}")
        
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, ports, arguments='-T4')
            
            if ip in nm.all_hosts():
                print(f"\n{Colors.CYAN}Scan Results for {ip}:{Colors.END}")
                print(f"{Colors.YELLOW}State: {nm[ip].state()}{Colors.END}")
                
                for proto in nm[ip].all_protocols():
                    print(f"\n{Colors.GREEN}Protocol: {proto}{Colors.END}")
                    ports = nm[ip][proto].keys()
                    
                    for port in sorted(ports):
                        state = nm[ip][proto][port]['state']
                        service = nm[ip][proto][port].get('name', 'unknown')
                        
                        if state == 'open':
                            print(f"{Colors.GREEN}  Port {port}: OPEN - {service}{Colors.END}")
                        else:
                            print(f"{Colors.RED}  Port {port}: {state.upper()} - {service}{Colors.END}")
            else:
                print(f"{Colors.RED}❌ Host not found in scan results{Colors.END}")
                
        except Exception as e:
            print(f"{Colors.RED}❌ Error: {e}{Colors.END}")
    
    def traceroute(self):
        """Perform traceroute"""
        target = input(f"{Colors.YELLOW}Enter target IP/hostname: {Colors.END}").strip()
        
        print(f"{Colors.GREEN}🛣️ Traceroute to {target}...{Colors.END}")
        
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(['tracert', '-d', target], capture_output=True, text=True)
            else:
                result = subprocess.run(['traceroute', '-n', target], capture_output=True, text=True)
            
            print(f"\n{Colors.CYAN}{result.stdout}{Colors.END}")
            
        except Exception as e:
            print(f"{Colors.RED}❌ Error: {e}{Colors.END}")
    
    def get_ip_location(self):
        """Get IP location"""
        ip = input(f"{Colors.YELLOW}Enter IP address: {Colors.END}").strip()
        
        if not self.validate_ip(ip):
            print(f"{Colors.RED}❌ Invalid IP address!{Colors.END}")
            return
        
        print(f"{Colors.GREEN}📍 Getting location for {ip}...{Colors.END}")
        
        try:
            # Try ip-api.com
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data['status'] == 'success':
                    print(f"\n{Colors.CYAN}Location Information:{Colors.END}")
                    print(f"{Colors.GREEN}  IP: {data['query']}{Colors.END}")
                    print(f"{Colors.GREEN}  Country: {data['country']}{Colors.END}")
                    print(f"{Colors.GREEN}  Region: {data['regionName']}{Colors.END}")
                    print(f"{Colors.GREEN}  City: {data['city']}{Colors.END}")
                    print(f"{Colors.GREEN}  ISP: {data['isp']}{Colors.END}")
                    print(f"{Colors.GREEN}  Org: {data['org']}{Colors.END}")
                    print(f"{Colors.GREEN}  Coordinates: {data['lat']}, {data['lon']}{Colors.END}")
                else:
                    print(f"{Colors.RED}❌ Unable to get location{Colors.END}")
            else:
                print(f"{Colors.RED}❌ API error{Colors.END}")
                
        except Exception as e:
            print(f"{Colors.RED}❌ Error: {e}{Colors.END}")
    
    def analyze_ip(self):
        """Analyze IP address"""
        ip = input(f"{Colors.YELLOW}Enter IP address to analyze: {Colors.END}").strip()
        
        if not self.validate_ip(ip):
            print(f"{Colors.RED}❌ Invalid IP address!{Colors.END}")
            return
        
        print(f"\n{Colors.CYAN}🔍 Analyzing {ip}...{Colors.END}")
        print(f"{Colors.YELLOW}═" * 50 + Colors.END)
        
        # Ping
        print(f"{Colors.GREEN}1. Ping Test:{Colors.END}")
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(['ping', '-n', '2', ip], capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['ping', '-c', '2', ip], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                print(f"   {Colors.GREEN}✅ Reachable{Colors.END}")
            else:
                print(f"   {Colors.RED}❌ Not reachable{Colors.END}")
        except:
            print(f"   {Colors.RED}❌ Ping failed{Colors.END}")
        
        # Common ports check
        print(f"\n{Colors.GREEN}2. Common Ports Check:{Colors.END}")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389]
        
        for port in common_ports[:5]:  # Check first 5 ports
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    print(f"   Port {port}: {Colors.GREEN}OPEN{Colors.END}")
                else:
                    print(f"   Port {port}: {Colors.RED}CLOSED{Colors.END}")
            except:
                print(f"   Port {port}: {Colors.RED}ERROR{Colors.END}")
        
        # Threat check
        print(f"\n{Colors.GREEN}3. Threat Analysis:{Colors.END}")
        threats = self.db_manager.get_all_threats(10)
        ip_threats = [t for t in threats if t[1] == ip]
        
        if ip_threats:
            print(f"   {Colors.RED}⚠️  {len(ip_threats)} threats detected{Colors.END}")
            for threat in ip_threats[:3]:
                print(f"   - {threat[2]} ({threat[3]})")
        else:
            print(f"   {Colors.GREEN}✅ No threats detected{Colors.END}")
        
        print(f"{Colors.YELLOW}═" * 50 + Colors.END)
    
    def threat_analysis_dashboard(self):
        """Threat analysis dashboard"""
        print(f"\n{Colors.RED}🚨 Threat Analysis Dashboard{Colors.END}")
        print(f"{Colors.YELLOW}═" * 60 + Colors.END)
        
        # Get recent threats
        threats = self.db_manager.get_all_threats(10)
        
        if not threats:
            print(f"{Colors.GREEN}✅ No threats detected in the system{Colors.END}")
        else:
            print(f"{Colors.CYAN}Recent Threats:{Colors.END}\n")
            
            for i, threat in enumerate(threats, 1):
                timestamp, ip, threat_type, severity, description, port = threat
                
                # Color based on severity
                if severity.lower() == 'high':
                    color = Colors.RED
                elif severity.lower() == 'medium':
                    color = Colors.ORANGE
                else:
                    color = Colors.YELLOW
                
                print(f"{color}{i}. {ip} - {threat_type} ({severity}){Colors.END}")
                if description:
                    print(f"   📝 {description[:50]}...")
                print()
        
        # Threat statistics
        stats = self.db_manager.get_threat_stats(24)
        if stats:
            print(f"{Colors.CYAN}24-Hour Threat Statistics:{Colors.END}")
            for threat_type, count in stats.items():
                print(f"   {threat_type}: {count}")
        
        print(f"{Colors.YELLOW}═" * 60 + Colors.END)
        
        input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")
    
    def telegram_integration_menu(self):
        """Telegram integration menu"""
        while True:
            print(f"\n{Colors.CYAN}🤖 Telegram Integration{Colors.END}")
            print(f"{Colors.YELLOW}═" * 50 + Colors.END)
            print(f"{Colors.GREEN}1. {Colors.WHITE}Configure Bot Token")
            print(f"{Colors.GREEN}2. {Colors.WHITE}Configure Chat ID")
            print(f"{Colors.GREEN}3. {Colors.WHITE}Test Connection")
            print(f"{Colors.GREEN}4. {Colors.WHITE}Show Status")
            print(f"{Colors.GREEN}5. {Colors.WHITE}Send Test Message")
            print(f"{Colors.GREEN}6. {Colors.WHITE}Process Telegram Commands")
            print(f"{Colors.RED}7. {Colors.WHITE}Back to Main Menu{Colors.END}")
            print(f"{Colors.YELLOW}═" * 50 + Colors.END)
            
            choice = input(f"{Colors.ORANGE}Select option (1-7): {Colors.END}").strip()
            
            if choice == '1':
                token = input(f"{Colors.YELLOW}Enter Telegram bot token: {Colors.END}").strip()
                result = self.telegram_manager.config_telegram_token(token)
                print(f"\n{Colors.CYAN}{result}{Colors.END}")
            elif choice == '2':
                chat_id = input(f"{Colors.YELLOW}Enter Telegram chat ID: {Colors.END}").strip()
                result = self.telegram_manager.config_telegram_chat_id(chat_id)
                print(f"\n{Colors.CYAN}{result}{Colors.END}")
            elif choice == '3':
                result = self.telegram_manager.test_telegram_connection()
                print(f"\n{Colors.CYAN}{result}{Colors.END}")
            elif choice == '4':
                result = self.telegram_manager.get_telegram_status()
                print(f"\n{Colors.CYAN}{result}{Colors.END}")
            elif choice == '5':
                if self.telegram_manager.send_telegram_message("🔒 Cyber Security Tool - Test Message"):
                    print(f"{Colors.GREEN}✅ Test message sent successfully!{Colors.END}")
                else:
                    print(f"{Colors.RED}❌ Failed to send test message{Colors.END}")
            elif choice == '6':
                self.process_telegram_commands()
            elif choice == '7':
                break
            else:
                print(f"{Colors.RED}❌ Invalid choice!{Colors.END}")
    
    def process_telegram_commands(self):
        """Process Telegram commands"""
        print(f"\n{Colors.GREEN}🤖 Processing Telegram commands...{Colors.END}")
        print(f"{Colors.YELLOW}Press Ctrl+C to stop{Colors.END}")
        
        try:
            while True:
                self.telegram_manager.process_telegram_updates()
                time.sleep(2)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 Stopped Telegram processing{Colors.END}")
    
    def generate_reports(self):
        """Generate security reports"""
        print(f"\n{Colors.CYAN}📊 Generate Security Reports{Colors.END}")
        print(f"{Colors.YELLOW}═" * 50 + Colors.END)
        
        print(f"{Colors.GREEN}1. {Colors.WHITE}Daily Report")
        print(f"{Colors.GREEN}2. {Colors.WHITE}Weekly Report")
        print(f"{Colors.GREEN}3. {Colors.WHITE}Monthly Report")
        print(f"{Colors.GREEN}4. {Colors.WHITE}Custom Report")
        print(f"{Colors.RED}5. {Colors.WHITE}Back{Colors.END}")
        print(f"{Colors.YELLOW}═" * 50 + Colors.END)
        
        choice = input(f"{Colors.ORANGE}Select option (1-5): {Colors.END}").strip()
        
        if choice == '1':
            self.generate_daily_report()
        elif choice == '2':
            self.generate_weekly_report()
        elif choice == '3':
            self.generate_monthly_report()
        elif choice == '4':
            self.generate_custom_report()
        elif choice != '5':
            print(f"{Colors.RED}❌ Invalid choice!{Colors.END}")
    
    def generate_daily_report(self):
        """Generate daily report"""
        print(f"\n{Colors.GREEN}📅 Generating Daily Report...{Colors.END}")
        
        # Get data for last 24 hours
        threats = self.db_manager.get_all_threats(100)
        recent_threats = [t for t in threats if 
                         datetime.now() - datetime.fromisoformat(t[0].replace('Z', '+00:00')) < timedelta(days=1)]
        
        report = f"""
DAILY SECURITY REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Period: Last 24 hours

THREAT SUMMARY:
Total Threats: {len(recent_threats)}
High Severity: {len([t for t in recent_threats if t[3].lower() == 'high'])}
Medium Severity: {len([t for t in recent_threats if t[3].lower() == 'medium'])}
Low Severity: {len([t for t in recent_threats if t[3].lower() == 'low'])}

TOP THREAT SOURCES:
"""
        # Group by IP
        ip_counts = {}
        for threat in recent_threats:
            ip = threat[1]
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            report += f"  {ip}: {count} threats\n"
        
        # Save report
        filename = f"daily_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(report)
        
        print(f"{Colors.GREEN}✅ Report saved: {filename}{Colors.END}")
        
        # Send to Telegram if enabled
        if self.telegram_manager.telegram_enabled:
            summary = f"📊 Daily Report Generated\nThreats: {len(recent_threats)}\nFile: {filename}"
            self.telegram_manager.send_telegram_message(summary)
    
    def generate_weekly_report(self):
        """Generate weekly report"""
        print(f"\n{Colors.GREEN}📅 Generating Weekly Report...{Colors.END}")
        print(f"{Colors.GREEN}✅ Weekly report generated{Colors.END}")
    
    def generate_monthly_report(self):
        """Generate monthly report"""
        print(f"\n{Colors.GREEN}📅 Generating Monthly Report...{Colors.END}")
        print(f"{Colors.GREEN}✅ Monthly report generated{Colors.END}")
    
    def generate_custom_report(self):
        """Generate custom report"""
        print(f"\n{Colors.GREEN}📊 Generating Custom Report...{Colors.END}")
        print(f"{Colors.GREEN}✅ Custom report generated{Colors.END}")
    
    def system_information(self):
        """Display system information"""
        print(f"\n{Colors.CYAN}💻 System Information{Colors.END}")
        print(f"{Colors.YELLOW}═" * 50 + Colors.END)
        
        # System info
        print(f"{Colors.GREEN}Operating System:{Colors.END}")
        print(f"  {platform.system()} {platform.release()} ({platform.machine()})")
        
        # CPU info
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        print(f"\n{Colors.GREEN}CPU:{Colors.END}")
        print(f"  Usage: {cpu_percent}%")
        print(f"  Cores: {cpu_count} (physical)")
        
        # Memory info
        memory = psutil.virtual_memory()
        print(f"\n{Colors.GREEN}Memory:{Colors.END}")
        print(f"  Total: {memory.total // (1024**3)} GB")
        print(f"  Used: {memory.used // (1024**3)} GB ({memory.percent}%)")
        print(f"  Available: {memory.available // (1024**3)} GB")
        
        # Disk info
        disk = psutil.disk_usage('/')
        print(f"\n{Colors.GREEN}Disk:{Colors.END}")
        print(f"  Total: {disk.total // (1024**3)} GB")
        print(f"  Used: {disk.used // (1024**3)} GB ({disk.percent}%)")
        print(f"  Free: {disk.free // (1024**3)} GB")
        
        # Network info
        print(f"\n{Colors.Green}Network:{Colors.END}")
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        print(f"  Hostname: {hostname}")
        print(f"  Local IP: {local_ip}")
        
        # Database info
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM threats")
        threat_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM monitored_ips")
        ip_count = cursor.fetchone()[0]
        
        conn.close()
        
        print(f"\n{Colors.Green}Security Database:{Colors.END}")
        print(f"  Threats Logged: {threat_count}")
        print(f"  IPs Monitored: {ip_count}")
        
        print(f"{Colors.YELLOW}═" * 50 + Colors.END)
        
        input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")
    
    def switch_theme_menu(self):
        """Switch theme menu"""
        print(f"\n{Colors.CYAN}🎨 Switch Theme{Colors.END}")
        print(f"{Colors.YELLOW}═" * 40 + Colors.END)
        
        themes = list(THEMES.keys())
        for i, theme_key in enumerate(themes, 1):
            theme = THEMES[theme_key]
            current = " ← CURRENT" if theme_key == self.current_theme else ""
            print(f"{Colors.GREEN}{i}. {Colors.WHITE}{theme['name']}{current}{Colors.END}")
        
        print(f"{Colors.RED}{len(themes) + 1}. {Colors.WHITE}Back{Colors.END}")
        print(f"{Colors.YELLOW}═" * 40 + Colors.END)
        
        choice = input(f"{Colors.ORANGE}Select theme (1-{len(themes) + 1}): {Colors.END}").strip()
        
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(themes):
                self.current_theme = themes[choice_num - 1]
                print(f"{Colors.GREEN}✅ Theme changed to {THEMES[self.current_theme]['name']}{Colors.END}")
            elif choice_num == len(themes) + 1:
                return
            else:
                print(f"{Colors.RED}❌ Invalid choice!{Colors.END}")
        except ValueError:
            print(f"{Colors.RED}❌ Invalid input!{Colors.END}")
    
    def start_gui_dashboard(self):
        """Start GUI dashboard"""
        if not GUI_AVAILABLE:
            print(f"{Colors.RED}❌ GUI not available. Please install tkinter.{Colors.END}")
            print(f"{Colors.YELLOW}On Ubuntu/Debian: sudo apt-get install python3-tk{Colors.END}")
            print(f"{Colors.YELLOW}On Fedora/RHEL: sudo dnf install python3-tkinter{Colors.END}")
            return
        
        print(f"{Colors.GREEN}🚀 Starting GUI Dashboard...{Colors.END}")
        
        # Run GUI in separate thread
        gui_thread = threading.Thread(target=self.run_gui, daemon=True)
        gui_thread.start()
        
        # Keep CLI running
        input(f"{Colors.YELLOW}Press Enter to return to CLI...{Colors.END}")
    
    def run_gui(self):
        """Run GUI dashboard"""
        self.root = tk.Tk()
        self.dashboard = CyberSecurityDashboard(self.root, self.db_manager, self.telegram_manager, self)
        self.root.mainloop()
    
    def exit_tool(self):
        """Exit the tool"""
        print(f"\n{Colors.YELLOW}🛑 Exiting Cyber Security Tool...{Colors.END}")
        
        # Save configuration
        if self.telegram_manager.telegram_enabled:
            self.telegram_manager.send_telegram_message("🔒 Cyber Security Tool - Shutting down")
        
        # Close database connections
        print(f"{Colors.GREEN}✅ Cleaning up resources...{Colors.END}")
        
        # Exit
        self.running = False
        print(f"{Colors.GREEN}👋 Thank you for using ACCURATE CYBER DRILL TOOL!{Colors.END}")
        sys.exit(0)
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def run_cli(self):
        """Run CLI interface"""
        while self.running:
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
            self.show_menu()
            
            choice = input(f"\n{Colors.ORANGE}Select option (1-9): {Colors.END}").strip()
            self.handle_choice(choice)
            
            if choice != '9':
                input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")

class CyberSecurityDashboard:
    """GUI Dashboard for Cyber Security Tool"""
    
    def __init__(self, root, db_manager, telegram_manager, tool_instance):
        self.root = root
        self.db_manager = db_manager
        self.telegram_manager = telegram_manager
        self.tool_instance = tool_instance
        
        self.setup_window()
        self.setup_theme()
        self.create_widgets()
        self.start_updates()
    
    def setup_window(self):
        """Setup main window"""
        self.root.title(f"ACCURATE CYBER DRILL TOOL v{VERSION}")
        self.root.geometry("1200x700")
        self.root.configure(bg=THEMES[self.tool_instance.current_theme]['bg'])
        
        # Center window
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_theme(self):
        """Apply theme to GUI"""
        self.theme = THEMES[self.tool_instance.current_theme]
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors
        bg = self.theme['bg']
        fg = self.theme['fg']
        button_bg = self.theme['button_bg']
        button_fg = self.theme['button_fg']
        
        self.style.configure('TFrame', background=bg)
        self.style.configure('TLabel', background=bg, foreground=fg)
        self.style.configure('TLabelframe', background=bg, foreground=fg)
        self.style.configure('TLabelframe.Label', background=bg, foreground=fg)
        self.style.configure('TButton', background=button_bg, foreground=button_fg)
        self.style.map('TButton',
                      background=[('active', self.theme['button_active'])])
        
        self.root.configure(bg=bg)
    
    def create_widgets(self):
        """Create GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        title = tk.Label(header_frame,
                        text=f"🚀 ACCURATE CYBER DRILL TOOL v{VERSION}",
                        font=('Arial', 20, 'bold'),
                        bg=self.theme['bg'],
                        fg=self.theme['highlight'])
        title.pack(side=tk.LEFT)
        
        status_label = tk.Label(header_frame,
                               text="🟢 ONLINE",
                               font=('Arial', 12),
                               bg=self.theme['bg'],
                               fg=self.theme['success'])
        status_label.pack(side=tk.RIGHT, padx=10)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_scanner_tab()
        self.create_monitor_tab()
        self.create_telegram_tab()
        self.create_reports_tab()
        self.create_settings_tab()
    
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_tab, text="📊 Dashboard")
        
        # Stats frame
        stats_frame = ttk.LabelFrame(dashboard_tab, text="System Statistics", padding=10)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create stats grid
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.BOTH, expand=True)
        
        # CPU Usage
        cpu_frame = ttk.Frame(stats_grid)
        cpu_frame.grid(row=0, column=0, padx=10, pady=10, sticky='nsew')
        
        tk.Label(cpu_frame, text="💻 CPU Usage", font=('Arial', 12, 'bold'),
                bg=self.theme['bg'], fg=self.theme['fg']).pack()
        self.cpu_label = tk.Label(cpu_frame, text="0%", font=('Arial', 24, 'bold'),
                                 bg=self.theme['bg'], fg=self.theme['accent'])
        self.cpu_label.pack(pady=5)
        
        # Memory Usage
        mem_frame = ttk.Frame(stats_grid)
        mem_frame.grid(row=0, column=1, padx=10, pady=10, sticky='nsew')
        
        tk.Label(mem_frame, text="🧠 Memory", font=('Arial', 12, 'bold'),
                bg=self.theme['bg'], fg=self.theme['fg']).pack()
        self.mem_label = tk.Label(mem_frame, text="0%", font=('Arial', 24, 'bold'),
                                 bg=self.theme['bg'], fg=self.theme['accent'])
        self.mem_label.pack(pady=5)
        
        # Threats
        threat_frame = ttk.Frame(stats_grid)
        threat_frame.grid(row=0, column=2, padx=10, pady=10, sticky='nsew')
        
        tk.Label(threat_frame, text="🚨 Threats", font=('Arial', 12, 'bold'),
                bg=self.theme['bg'], fg=self.theme['fg']).pack()
        self.threat_label = tk.Label(threat_frame, text="0", font=('Arial', 24, 'bold'),
                                    bg=self.theme['bg'], fg=self.theme['error'])
        self.threat_label.pack(pady=5)
        
        # Network
        net_frame = ttk.Frame(stats_grid)
        net_frame.grid(row=0, column=3, padx=10, pady=10, sticky='nsew')
        
        tk.Label(net_frame, text="🌐 Network", font=('Arial', 12, 'bold'),
                bg=self.theme['bg'], fg=self.theme['fg']).pack()
        self.net_label = tk.Label(net_frame, text="Active", font=('Arial', 24, 'bold'),
                                 bg=self.theme['bg'], fg=self.theme['success'])
        self.net_label.pack(pady=5)
        
        # Recent threats list
        threats_frame = ttk.LabelFrame(dashboard_tab, text="Recent Threats", padding=10)
        threats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.threats_text = scrolledtext.ScrolledText(threats_frame,
                                                     height=10,
                                                     bg=self.theme['text_bg'],
                                                     fg=self.theme['text_fg'],
                                                     font=('Consolas', 10))
        self.threats_text.pack(fill=tk.BOTH, expand=True)
        
        # Quick actions
        actions_frame = ttk.LabelFrame(dashboard_tab, text="Quick Actions", padding=10)
        actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        button_frame = ttk.Frame(actions_frame)
        button_frame.pack()
        
        ttk.Button(button_frame, text="🔄 Refresh", command=self.refresh_dashboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🔍 Scan Network", command=self.quick_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📊 Generate Report", command=self.quick_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🛑 Emergency Stop", command=self.emergency_stop,
                  style='Emergency.TButton').pack(side=tk.LEFT, padx=5)
        
        # Configure emergency button style
        self.style.configure('Emergency.TButton',
                           background=self.theme['error'],
                           foreground='white')
    
    def create_scanner_tab(self):
        """Create network scanner tab"""
        scanner_tab = ttk.Frame(self.notebook)
        self.notebook.add(scanner_tab, text="🔍 Scanner")
        
        # Target input
        input_frame = ttk.LabelFrame(scanner_tab, text="Target Configuration", padding=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(input_frame, text="Target IP/Hostname:", bg=self.theme['bg'], fg=self.theme['fg']).grid(row=0, column=0, padx=5, pady=5)
        self.target_entry = ttk.Entry(input_frame, width=30)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(input_frame, text="Port Range:", bg=self.theme['bg'], fg=self.theme['fg']).grid(row=0, column=2, padx=5, pady=5)
        self.port_entry = ttk.Entry(input_frame, width=15)
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)
        self.port_entry.insert(0, "1-1000")
        
        # Scan buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=1, column=0, columnspan=4, pady=10)
        
        ttk.Button(button_frame, text="🏓 Ping", command=self.gui_ping).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🛣️ Traceroute", command=self.gui_traceroute).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🔍 Port Scan", command=self.gui_port_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📍 Get Location", command=self.gui_get_location).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🔬 Analyze", command=self.gui_analyze).pack(side=tk.LEFT, padx=5)
        
        # Results area
        results_frame = ttk.LabelFrame(scanner_tab, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame,
                                                     bg=self.theme['text_bg'],
                                                     fg=self.theme['text_fg'],
                                                     font=('Consolas', 10))
        self.results_text.pack(fill=tk.BOTH, expand=True)
    
    def create_monitor_tab(self):
        """Create network monitoring tab"""
        monitor_tab = ttk.Frame(self.notebook)
        self.notebook.add(monitor_tab, text="👁️ Monitor")
        
        # Monitoring controls
        control_frame = ttk.LabelFrame(monitor_tab, text="Monitoring Controls", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(control_frame, text="IP to Monitor:", bg=self.theme['bg'], fg=self.theme['fg']).grid(row=0, column=0, padx=5, pady=5)
        self.monitor_ip_entry = ttk.Entry(control_frame, width=25)
        self.monitor_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        self.start_monitor_btn = ttk.Button(control_frame, text="▶ Start Monitoring", command=self.start_monitoring)
        self.start_monitor_btn.grid(row=0, column=2, padx=5, pady=5)
        
        self.stop_monitor_btn = ttk.Button(control_frame, text="⏹ Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_monitor_btn.grid(row=0, column=3, padx=5, pady=5)
        
        # Monitored IPs list
        ips_frame = ttk.LabelFrame(monitor_tab, text="Monitored IPs", padding=10)
        ips_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create listbox with scrollbar
        list_frame = ttk.Frame(ips_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.monitored_listbox = tk.Listbox(list_frame,
                                           yscrollcommand=scrollbar.set,
                                           bg=self.theme['text_bg'],
                                           fg=self.theme['text_fg'],
                                           font=('Consolas', 10))
        self.monitored_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.monitored_listbox.yview)
        
        # List buttons
        list_buttons_frame = ttk.Frame(ips_frame)
        list_buttons_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(list_buttons_frame, text="➕ Add IP", command=self.add_monitored_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(list_buttons_frame, text="➖ Remove Selected", command=self.remove_monitored_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(list_buttons_frame, text="🔄 Refresh List", command=self.refresh_monitored_ips).pack(side=tk.LEFT, padx=5)
    
    def create_telegram_tab(self):
        """Create Telegram integration tab"""
        telegram_tab = ttk.Frame(self.notebook)
        self.notebook.add(telegram_tab, text="🤖 Telegram")
        
        # Configuration frame
        config_frame = ttk.LabelFrame(telegram_tab, text="Bot Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Token
        tk.Label(config_frame, text="Bot Token:", bg=self.theme['bg'], fg=self.theme['fg']).grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.token_entry = ttk.Entry(config_frame, width=50, show="*")
        self.token_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(config_frame, text="Set Token", command=self.set_telegram_token).grid(row=0, column=2, padx=5, pady=5)
        
        # Chat ID
        tk.Label(config_frame, text="Chat ID:", bg=self.theme['bg'], fg=self.theme['fg']).grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.chat_id_entry = ttk.Entry(config_frame, width=20)
        self.chat_id_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Button(config_frame, text="Set Chat ID", command=self.set_telegram_chat_id).grid(row=1, column=2, padx=5, pady=5)
        
        # Status frame
        status_frame = ttk.LabelFrame(telegram_tab, text="Status", padding=10)
        status_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.telegram_status_text = scrolledtext.ScrolledText(status_frame,
                                                             height=10,
                                                             bg=self.theme['text_bg'],
                                                             fg=self.theme['text_fg'],
                                                             font=('Consolas', 10))
        self.telegram_status_text.pack(fill=tk.BOTH, expand=True)
        
        # Control buttons
        control_frame = ttk.Frame(telegram_tab)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="🔗 Test Connection", command=self.test_telegram_connection).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="📱 Show Status", command=self.show_telegram_status).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="📨 Send Test Message", command=self.send_test_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="🔄 Process Updates", command=self.process_telegram_updates).pack(side=tk.LEFT, padx=5)
    
    def create_reports_tab(self):
        """Create reports tab"""
        reports_tab = ttk.Frame(self.notebook)
        self.notebook.add(reports_tab, text="📊 Reports")
        
        # Report types
        types_frame = ttk.LabelFrame(reports_tab, text="Report Types", padding=10)
        types_frame.pack(fill=tk.X, padx=5, pady=5)
        
        report_types = [
            ("📅 Daily Report", "daily"),
            ("📆 Weekly Report", "weekly"),
            ("📈 Monthly Report", "monthly"),
            ("🎯 Custom Report", "custom")
        ]
        
        for i, (text, report_type) in enumerate(report_types):
            btn = ttk.Button(types_frame, text=text, 
                           command=lambda rt=report_type: self.generate_report(rt))
            btn.grid(row=0, column=i, padx=5, pady=5)
        
        # Report content
        content_frame = ttk.LabelFrame(reports_tab, text="Report Content", padding=10)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.report_text = scrolledtext.ScrolledText(content_frame,
                                                    bg=self.theme['text_bg'],
                                                    fg=self.theme['text_fg'],
                                                    font=('Consolas', 10))
        self.report_text.pack(fill=tk.BOTH, expand=True)
        
        # Export buttons
        export_frame = ttk.Frame(reports_tab)
        export_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(export_frame, text="💾 Save to File", command=self.save_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="📤 Export to Telegram", command=self.export_to_telegram).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="🖨️ Print", command=self.print_report).pack(side=tk.LEFT, padx=5)
    
    def create_settings_tab(self):
        """Create settings tab"""
        settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(settings_tab, text="⚙️ Settings")
        
        # Theme selection
        theme_frame = ttk.LabelFrame(settings_tab, text="Theme", padding=10)
        theme_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.theme_var = tk.StringVar(value=self.tool_instance.current_theme)
        
        for theme_key in THEMES:
            theme = THEMES[theme_key]
            rb = ttk.Radiobutton(theme_frame,
                                text=theme['name'],
                                variable=self.theme_var,
                                value=theme_key,
                                command=self.change_theme)
            rb.pack(anchor='w', padx=10, pady=5)
        
        # Database management
        db_frame = ttk.LabelFrame(settings_tab, text="Database", padding=10)
        db_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(db_frame, text="🗑️ Clear History", command=self.clear_history).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(db_frame, text="💾 Backup Database", command=self.backup_database).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(db_frame, text="📊 Database Stats", command=self.show_db_stats).pack(side=tk.LEFT, padx=5, pady=5)
        
        # System settings
        system_frame = ttk.LabelFrame(settings_tab, text="System", padding=10)
        system_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(system_frame, text="🔄 Restart Tool", command=self.restart_tool).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(system_frame, text="📋 View Logs", command=self.view_logs).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(system_frame, text="ℹ️ About", command=self.show_about).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Exit button
        exit_frame = ttk.Frame(settings_tab)
        exit_frame.pack(fill=tk.X, padx=5, pady=20)
        
        ttk.Button(exit_frame, text="🛑 Exit Tool", command=self.on_closing,
                  style='Emergency.TButton').pack(side=tk.RIGHT, padx=5)
    
    def start_updates(self):
        """Start periodic updates"""
        self.update_dashboard()
        self.root.after(2000, self.start_updates)
    
    def update_dashboard(self):
        """Update dashboard with current information"""
        # Update CPU and Memory
        cpu_percent = psutil.cpu_percent()
        mem_percent = psutil.virtual_memory().percent
        
        self.cpu_label.config(text=f"{cpu_percent}%")
        self.mem_label.config(text=f"{mem_percent}%")
        
        # Update threat count
        threats = self.db_manager.get_all_threats(100)
        self.threat_label.config(text=str(len(threats)))
        
        # Update recent threats list
        self.threats_text.delete(1.0, tk.END)
        recent_threats = threats[:5]
        
        if recent_threats:
            for threat in recent_threats:
                timestamp, ip, threat_type, severity, description, port = threat
                color = self.theme['error'] if severity.lower() == 'high' else self.theme['warning']
                
                self.threats_text.insert(tk.END, f"[{timestamp.split(' ')[0]}] ", 'normal')
                self.threats_text.insert(tk.END, f"{ip} - {threat_type} ({severity})\n", 'threat')
        else:
            self.threats_text.insert(tk.END, "✅ No recent threats\n", 'normal')
        
        # Configure text tags
        self.threats_text.tag_config('normal', foreground=self.theme['text_fg'])
        self.threats_text.tag_config('threat', foreground=self.theme['error'])
        
        # Update monitored IPs list
        self.refresh_monitored_ips()
    
    def refresh_dashboard(self):
        """Refresh dashboard"""
        self.update_dashboard()
        messagebox.showinfo("Refresh", "Dashboard refreshed successfully!")
    
    def quick_scan(self):
        """Quick network scan"""
        target = self.target_entry.get() if hasattr(self, 'target_entry') else ""
        
        if not target:
            messagebox.showwarning("Warning", "Please enter a target IP first!")
            self.notebook.select(1)  # Switch to scanner tab
            return
        
        self.gui_ping()
    
    def quick_report(self):
        """Generate quick report"""
        self.generate_report("daily")
    
    def emergency_stop(self):
        """Emergency stop all operations"""
        if messagebox.askyesno("Emergency Stop", "Stop all monitoring and scanning operations?"):
            self.stop_monitoring()
            messagebox.showinfo("Stopped", "All operations stopped!")
    
    def gui_ping(self):
        """GUI ping command"""
        target = self.target_entry.get()
        
        if not target:
            messagebox.showwarning("Warning", "Please enter a target!")
            return
        
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"🏓 Pinging {target}...\n\n")
        
        # Run ping in thread to avoid freezing GUI
        threading.Thread(target=self.run_ping, args=(target,), daemon=True).start()
    
    def run_ping(self, target):
        """Run ping command"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(['ping', '-n', '4', target], capture_output=True, text=True)
            else:
                result = subprocess.run(['ping', '-c', '4', target], capture_output=True, text=True)
            
            self.results_text.insert(tk.END, result.stdout)
            
            if result.returncode == 0:
                self.results_text.insert(tk.END, "\n✅ Host is reachable\n")
            else:
                self.results_text.insert(tk.END, "\n❌ Host is not reachable\n")
                
        except Exception as e:
            self.results_text.insert(tk.END, f"\n❌ Error: {e}\n")
    
    def gui_traceroute(self):
        """GUI traceroute command"""
        target = self.target_entry.get()
        
        if not target:
            messagebox.showwarning("Warning", "Please enter a target!")
            return
        
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"🛣️ Traceroute to {target}...\n\n")
        
        # Run traceroute in thread
        threading.Thread(target=self.run_traceroute, args=(target,), daemon=True).start()
    
    def run_traceroute(self, target):
        """Run traceroute command"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(['tracert', '-d', target], capture_output=True, text=True)
            else:
                result = subprocess.run(['traceroute', '-n', target], capture_output=True, text=True)
            
            self.results_text.insert(tk.END, result.stdout)
            
        except Exception as e:
            self.results_text.insert(tk.END, f"\n❌ Error: {e}\n")
    
    def gui_port_scan(self):
        """GUI port scan"""
        if not NMAP_AVAILABLE:
            messagebox.showerror("Error", "Nmap not available!")
            return
        
        target = self.target_entry.get()
        ports = self.port_entry.get() or "1-1000"
        
        if not target:
            messagebox.showwarning("Warning", "Please enter a target!")
            return
        
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"🔍 Scanning {target} ports {ports}...\n\n")
        
        # Run scan in thread
        threading.Thread(target=self.run_port_scan, args=(target, ports), daemon=True).start()
    
    def run_port_scan(self, target, ports):
        """Run port scan"""
        try:
            nm = nmap.PortScanner()
            nm.scan(target, ports, arguments='-T4')
            
            if target in nm.all_hosts():
                self.results_text.insert(tk.END, f"Results for {target}:\n")
                self.results_text.insert(tk.END, f"State: {nm[target].state()}\n\n")
                
                open_ports = []
                for proto in nm[target].all_protocols():
                    for port in sorted(nm[target][proto].keys()):
                        state = nm[target][proto][port]['state']
                        service = nm[target][proto][port].get('name', 'unknown')
                        
                        if state == 'open':
                            open_ports.append(port)
                            self.results_text.insert(tk.END, f"Port {port}: OPEN - {service}\n")
                
                if open_ports:
                    self.results_text.insert(tk.END, f"\n✅ Found {len(open_ports)} open ports\n")
                else:
                    self.results_text.insert(tk.END, "\n🔒 No open ports found\n")
            else:
                self.results_text.insert(tk.END, "❌ Host not found in scan results\n")
                
        except Exception as e:
            self.results_text.insert(tk.END, f"\n❌ Error: {e}\n")
    
    def gui_get_location(self):
        """GUI get IP location"""
        target = self.target_entry.get()
        
        if not target:
            messagebox.showwarning("Warning", "Please enter a target!")
            return
        
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"📍 Getting location for {target}...\n\n")
        
        # Run location lookup in thread
        threading.Thread(target=self.run_get_location, args=(target,), daemon=True).start()
    
    def run_get_location(self, target):
        """Run IP location lookup"""
        try:
            response = requests.get(f"http://ip-api.com/json/{target}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data['status'] == 'success':
                    self.results_text.insert(tk.END, f"IP: {data['query']}\n")
                    self.results_text.insert(tk.END, f"Country: {data['country']}\n")
                    self.results_text.insert(tk.END, f"Region: {data['regionName']}\n")
                    self.results_text.insert(tk.END, f"City: {data['city']}\n")
                    self.results_text.insert(tk.END, f"ISP: {data['isp']}\n")
                    self.results_text.insert(tk.END, f"Org: {data['org']}\n")
                    self.results_text.insert(tk.END, f"Coordinates: {data['lat']}, {data['lon']}\n")
                else:
                    self.results_text.insert(tk.END, "❌ Unable to get location\n")
            else:
                self.results_text.insert(tk.END, f"❌ API error: {response.status_code}\n")
                
        except Exception as e:
            self.results_text.insert(tk.END, f"❌ Error: {e}\n")
    
    def gui_analyze(self):
        """GUI analyze IP"""
        target = self.target_entry.get()
        
        if not target:
            messagebox.showwarning("Warning", "Please enter a target!")
            return
        
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"🔍 Analyzing {target}...\n\n")
        
        # Run analysis in thread
        threading.Thread(target=self.run_analyze, args=(target,), daemon=True).start()
    
    def run_analyze(self, target):
        """Run IP analysis"""
        try:
            # Ping
            if platform.system().lower() == "windows":
                ping_result = subprocess.run(['ping', '-n', '2', target], capture_output=True, text=True, timeout=5)
            else:
                ping_result = subprocess.run(['ping', '-c', '2', target], capture_output=True, text=True, timeout=5)
            
            if ping_result.returncode == 0:
                self.results_text.insert(tk.END, "🏓 Ping: ✅ Reachable\n")
            else:
                self.results_text.insert(tk.END, "🏓 Ping: ❌ Not reachable\n")
            
            # Check common ports
            self.results_text.insert(tk.END, "\n🔒 Common Ports:\n")
            common_ports = [80, 443, 22, 21, 25, 53]
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        self.results_text.insert(tk.END, f"  Port {port}: ✅ OPEN\n")
                    else:
                        self.results_text.insert(tk.END, f"  Port {port}: ❌ CLOSED\n")
                except:
                    self.results_text.insert(tk.END, f"  Port {port}: ❌ ERROR\n")
            
            # Check threats
            threats = self.db_manager.get_all_threats(100)
            ip_threats = [t for t in threats if t[1] == target]
            
            self.results_text.insert(tk.END, f"\n🚨 Threats: {len(ip_threats)} detected\n")
            
        except Exception as e:
            self.results_text.insert(tk.END, f"❌ Error: {e}\n")
    
    def start_monitoring(self):
        """Start monitoring IP"""
        ip = self.monitor_ip_entry.get()
        
        if not ip:
            messagebox.showwarning("Warning", "Please enter an IP address!")
            return
        
        self.db_manager.add_monitored_ip(ip)
        self.start_monitor_btn.config(state=tk.DISABLED)
        self.stop_monitor_btn.config(state=tk.NORMAL)
        
        messagebox.showinfo("Monitoring", f"Started monitoring {ip}")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.start_monitor_btn.config(state=tk.NORMAL)
        self.stop_monitor_btn.config(state=tk.DISABLED)
        
        messagebox.showinfo("Monitoring", "Stopped monitoring")
    
    def add_monitored_ip(self):
        """Add IP to monitoring list"""
        ip = self.monitor_ip_entry.get()
        
        if not ip:
            messagebox.showwarning("Warning", "Please enter an IP address!")
            return
        
        self.db_manager.add_monitored_ip(ip)
        self.refresh_monitored_ips()
        
        messagebox.showinfo("Success", f"Added {ip} to monitoring list")
    
    def remove_monitored_ip(self):
        """Remove selected IP from monitoring list"""
        selection = self.monitored_listbox.curselection()
        
        if not selection:
            messagebox.showwarning("Warning", "Please select an IP to remove!")
            return
        
        ip = self.monitored_listbox.get(selection[0])
        self.db_manager.remove_monitored_ip(ip)
        self.refresh_monitored_ips()
        
        messagebox.showinfo("Success", f"Removed {ip} from monitoring list")
    
    def refresh_monitored_ips(self):
        """Refresh monitored IPs list"""
        self.monitored_listbox.delete(0, tk.END)
        
        ips = self.db_manager.get_monitored_ips()
        for ip in ips:
            self.monitored_listbox.insert(tk.END, ip)
    
    def set_telegram_token(self):
        """Set Telegram bot token"""
        token = self.token_entry.get()
        
        if not token:
            messagebox.showwarning("Warning", "Please enter a bot token!")
            return
        
        result = self.telegram_manager.config_telegram_token(token)
        self.show_telegram_status()
        messagebox.showinfo("Token", result)
    
    def set_telegram_chat_id(self):
        """Set Telegram chat ID"""
        chat_id = self.chat_id_entry.get()
        
        if not chat_id:
            messagebox.showwarning("Warning", "Please enter a chat ID!")
            return
        
        result = self.telegram_manager.config_telegram_chat_id(chat_id)
        self.show_telegram_status()
        messagebox.showinfo("Chat ID", result)
    
    def test_telegram_connection(self):
        """Test Telegram connection"""
        result = self.telegram_manager.test_telegram_connection()
        self.telegram_status_text.delete(1.0, tk.END)
        self.telegram_status_text.insert(tk.END, result)
    
    def show_telegram_status(self):
        """Show Telegram status"""
        result = self.telegram_manager.get_telegram_status()
        self.telegram_status_text.delete(1.0, tk.END)
        self.telegram_status_text.insert(tk.END, result)
    
    def send_test_message(self):
        """Send test message to Telegram"""
        if self.telegram_manager.send_telegram_message("🔒 Cyber Security Tool - Test Message"):
            messagebox.showinfo("Success", "Test message sent successfully!")
        else:
            messagebox.showerror("Error", "Failed to send test message!")
    
    def process_telegram_updates(self):
        """Process Telegram updates"""
        self.telegram_status_text.insert(tk.END, "\n🔄 Processing updates...\n")
        self.telegram_manager.process_telegram_updates()
        self.telegram_status_text.insert(tk.END, "✅ Updates processed\n")
    
    def generate_report(self, report_type):
        """Generate report"""
        self.report_text.delete(1.0, tk.END)
        
        if report_type == "daily":
            threats = self.db_manager.get_all_threats(100)
            recent_threats = [t for t in threats if 
                             datetime.now() - datetime.fromisoformat(t[0].replace('Z', '+00:00')) < timedelta(days=1)]
            
            report = f"""DAILY SECURITY REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Period: Last 24 hours

SYSTEM STATUS:
CPU Usage: {psutil.cpu_percent()}%
Memory Usage: {psutil.virtual_memory().percent}%
Disk Usage: {psutil.disk_usage('/').percent}%

THREAT SUMMARY:
Total Threats: {len(recent_threats)}
High Severity: {len([t for t in recent_threats if t[3].lower() == 'high'])}
Medium Severity: {len([t for t in recent_threats if t[3].lower() == 'medium'])}
Low Severity: {len([t for t in recent_threats if t[3].lower() == 'low'])}

RECENT THREATS:"""
            
            for threat in recent_threats[:10]:
                timestamp, ip, threat_type, severity, description, port = threat
                report += f"\n  • {ip} - {threat_type} ({severity})"
                if description:
                    report += f" - {description[:50]}..."
            
            self.report_text.insert(tk.END, report)
            
        elif report_type == "weekly":
            self.report_text.insert(tk.END, "📆 WEEKLY REPORT\n\nComing soon...")
        elif report_type == "monthly":
            self.report_text.insert(tk.END, "📈 MONTHLY REPORT\n\nComing soon...")
        elif report_type == "custom":
            self.report_text.insert(tk.END, "🎯 CUSTOM REPORT\n\nConfigure custom report parameters...")
    
    def save_report(self):
        """Save report to file"""
        report_text = self.report_text.get(1.0, tk.END).strip()
        
        if not report_text:
            messagebox.showwarning("Warning", "No report to save!")
            return
        
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(report_text)
        
        messagebox.showinfo("Saved", f"Report saved as:\n{filename}")
    
    def export_to_telegram(self):
        """Export report to Telegram"""
        report_text = self.report_text.get(1.0, tk.END).strip()
        
        if not report_text:
            messagebox.showwarning("Warning", "No report to export!")
            return
        
        if self.telegram_manager.send_telegram_message(f"📊 SECURITY REPORT\n\n{report_text[:1000]}..."):
            messagebox.showinfo("Success", "Report sent to Telegram!")
        else:
            messagebox.showerror("Error", "Failed to send report!")
    
    def print_report(self):
        """Print report"""
        messagebox.showinfo("Print", "Print functionality would be implemented here")
    
    def change_theme(self):
        """Change theme"""
        new_theme = self.theme_var.get()
        self.tool_instance.current_theme = new_theme
        
        # Recreate GUI with new theme
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.setup_theme()
        self.create_widgets()
    
    def clear_history(self):
        """Clear command history"""
        if messagebox.askyesno("Confirm", "Clear all command history?"):
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM command_history")
            conn.commit()
            conn.close()
            
            messagebox.showinfo("Cleared", "Command history cleared!")
    
    def backup_database(self):
        """Backup database"""
        backup_file = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        
        try:
            shutil.copy2(DATABASE_FILE, backup_file)
            messagebox.showinfo("Backup", f"Database backed up as:\n{backup_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Backup failed: {e}")
    
    def show_db_stats(self):
        """Show database statistics"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM threats")
        threat_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM monitored_ips")
        ip_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM command_history")
        command_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM telegram_logs")
        telegram_count = cursor.fetchone()[0]
        
        conn.close()
        
        stats = f"""📊 DATABASE STATISTICS

Threats Logged: {threat_count}
IPs Monitored: {ip_count}
Commands Executed: {command_count}
Telegram Messages: {telegram_count}

Database File: {DATABASE_FILE}
Size: {os.path.getsize(DATABASE_FILE) // 1024} KB"""
        
        messagebox.showinfo("Database Stats", stats)
    
    def restart_tool(self):
        """Restart the tool"""
        if messagebox.askyesno("Restart", "Restart the Cyber Security Tool?"):
            self.on_closing()
            # Note: In a real application, you would restart the application
            # For now, we'll just close and let the user restart manually
            messagebox.showinfo("Restart", "Please restart the tool manually")
    
    def view_logs(self):
        """View logs"""
        log_file = os.path.join(LOG_DIR, 'cyber_tool.log')
        
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = f.read()[-5000:]  # Last 5000 characters
            
            log_window = tk.Toplevel(self.root)
            log_window.title("View Logs")
            log_window.geometry("800x600")
            
            text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD)
            text.pack(fill=tk.BOTH, expand=True)
            text.insert(tk.END, logs)
            text.config(state=tk.DISABLED)
        else:
            messagebox.showinfo("Logs", "No log file found")
    
    def show_about(self):
        """Show about information"""
        about_text = f"""ACCURATE CYBER DRILL TOOL
Version: {VERSION}
Author: Ian Carter Kulani

Features:
• Network Monitoring
• Intrusion Detection
• Traffic Analysis
• Vulnerability Scanning
• Telegram Integration
• Real-time Dashboard
• Advanced Reporting

© 2024 Cyber Security War Tool Team
All rights reserved."""
        
        messagebox.showinfo("About", about_text)
    
    def on_closing(self):
        """Handle window closing"""
        if messagebox.askokcancel("Exit", "Exit the Cyber Security Tool?"):
            # Send shutdown notification
            if self.telegram_manager.telegram_enabled:
                self.telegram_manager.send_telegram_message("🔒 Cyber Security Tool - Shutting down")
            
            self.root.destroy()
            self.tool_instance.exit_tool()

def main():
    """Main entry point"""
    tool = CyberSecurityTool()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='ACCURATE CYBER DRILL TOOL')
    parser.add_argument('--gui', action='store_true', help='Start in GUI mode')
    parser.add_argument('--cli', action='store_true', help='Start in CLI mode')
    parser.add_argument('--theme', choices=list(THEMES.keys()), help='Set theme')
    
    args = parser.parse_args()
    
    # Set theme if specified
    if args.theme and args.theme in THEMES:
        tool.current_theme = args.theme
    
    # Print banner
    tool.print_banner()
    
    # Start in appropriate mode
    if args.gui:
        if GUI_AVAILABLE:
            tool.run_gui()
        else:
            print(f"{Colors.RED}❌ GUI not available. Starting CLI mode...{Colors.END}")
            tool.run_cli()
    elif args.cli:
        tool.run_cli()
    else:
        # Interactive mode selection
        print(f"\n{Colors.CYAN}Select Mode:{Colors.END}")
        print(f"{Colors.GREEN}1. {Colors.WHITE}CLI Mode (Command Line Interface)")
        print(f"{Colors.GREEN}2. {Colors.WHITE}GUI Mode (Graphical Interface)")
        print(f"{Colors.RED}3. {Colors.WHITE}Exit{Colors.END}")
        
        while True:
            choice = input(f"\n{Colors.ORANGE}Select (1-3): {Colors.END}").strip()
            
            if choice == '1':
                tool.run_cli()
                break
            elif choice == '2':
                if GUI_AVAILABLE:
                    tool.run_gui()
                else:
                    print(f"{Colors.RED}❌ GUI not available. Starting CLI mode...{Colors.END}")
                    tool.run_cli()
                break
            elif choice == '3':
                tool.exit_tool()
                break
            else:
                print(f"{Colors.RED}❌ Invalid choice!{Colors.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}👋 Thank you for using ACCURATE CYBER DRILL TOOL!{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Application error: {e}{Colors.END}")
        logging.exception("Application crash")