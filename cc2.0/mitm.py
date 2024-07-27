import sys
import os
import json
import requests
import schedule
import time
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QPushButton, QTextEdit, QLabel, QTabWidget, 
                             QFormLayout, QLineEdit, QCheckBox, QFileDialog)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QIcon
import scapy.all as scapy
import netifaces
import logging
import ssl
import socket
import OpenSSL
from plyer import notification


class MITMDetector(QThread):
    detection_signal = pyqtSignal(str)
    alert_signal = pyqtSignal(str, str)
    
    def __init__(self, interface, config):
        super().__init__()
        self.interface = interface
        self.config = config
        self.running = False
        self.logger = self.setup_logger()

    def setup_logger(self):
        logger = logging.getLogger('MITMDetector')
        logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler('mitm_detector.log')
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)
        return logger

    def run(self):
        self.running = True
        while self.running:
            try:
                self.detect_mitm()
                self.verify_ssl_certificates()
                self.analyze_network_traffic()
            except Exception as e:
                self.log_and_emit(f"Error: {str(e)}", logging.ERROR)
            time.sleep(self.config['scan_interval'])

    def stop(self):
        self.running = False

    def log_and_emit(self, message, level=logging.INFO):
        self.logger.log(level, message)
        self.detection_signal.emit(message)
        if level >= logging.WARNING:
            self.alert_signal.emit("MITM Alert", message)

    def detect_mitm(self):
     arp_packets = scapy.sniff(iface=self.interface, filter="arp", timeout=5)
    ip_mac_mapping = {}

    for packet in arp_packets:
        if packet[scapy.ARP].op == 2:  # ARP reply
            ip = packet[scapy.ARP].psrc
            mac = packet[scapy.ARP].hwsrc

            if ip in ip_mac_mapping:
                if ip_mac_mapping[ip] != mac:
                    self.detection_signal.emit(f"Potential MITM attack detected! IP: {ip}")
                    self.detection_signal.emit(f"Original MAC: {ip_mac_mapping[ip]}")
                    self.detection_signal.emit(f"New MAC: {mac}")
            else:
                ip_mac_mapping[ip] = mac

    # default gateway ch
    gateways = netifaces.gateways()
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        gateway_ip = gateways['default'][netifaces.AF_INET][0]
        if gateway_ip in ip_mac_mapping:
            gateway_mac = ip_mac_mapping[gateway_ip]
            self.detection_signal.emit(f"Default Gateway: {gateway_ip} - MAC: {gateway_mac}")
        else:
            self.detection_signal.emit("Warning: Default gateway not found in ARP table")

    # DNS spoofing 
    dns_packets = scapy.sniff(iface=self.interface, filter="udp port 53", timeout=5)
    dns_servers = set()
    for packet in dns_packets:
        if scapy.DNS in packet and packet[scapy.DNS].qr == 1:  # DNS response
            dns_servers.add(packet[scapy.IP].src)
    
    if len(dns_servers) > 1:
        self.detection_signal.emit("Warning: Multiple DNS servers detected:")
        for server in dns_servers:
            self.detection_signal.emit(f"  - {server}")

    def verify_ssl_certificates(self):
        for domain in self.config['monitored_domains']:
            try:
                cert = ssl.get_server_certificate((domain, 443))
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                
                # cert
                expiration_date = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                if expiration_date < datetime.now():
                    self.log_and_emit(f"SSL certificate for {domain} has expired!", logging.WARNING)
                
                #cert? self signed?
                if x509.get_issuer() == x509.get_subject():
                    self.log_and_emit(f"Self-signed certificate detected for {domain}", logging.WARNING)
                
            except Exception as e:
                self.log_and_emit(f"Error verifying SSL for {domain}: {str(e)}", logging.ERROR)

    def analyze_network_traffic(self):
        packets = scapy.sniff(iface=self.interface, count=1000, timeout=60)
        ip_count = {}
        for packet in packets:
            if scapy.IP in packet:
                src_ip = packet[scapy.IP].src
                ip_count[src_ip] = ip_count.get(src_ip, 0) + 1
        
        # traffic ?
        for ip, count in ip_count.items():
            if count > self.config['traffic_threshold']:
                self.log_and_emit(f"Unusual traffic detected from {ip}: {count} packets", logging.WARNING)
                
                
                
                
                
                
                
                
                class Config:
                   def __init__(self):
                         self.config_file = 'config.json'
                         self.default_config = {
            'scan_interval': 300,
            'monitored_domains': ['example.com', 'google.com'],
            'traffic_threshold': 500,
            'enable_notifications': True
        }
        self.load_config()

    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = self.default_config
            self.save_config()

    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

    def get(self, key):
        return self.config.get(key, self.default_config.get(key))

    def set(self, key, value):
        self.config[key] = value
        self.save_config()
        
        class MainWindow(QMainWindow):
            def __init__(self):
                super().__init__()
                self.setWindowTitle("MITM Attack Detector")
                self.setGeometry(100, 100, 800, 600)
                self.setWindowIcon(QIcon('icon.png'))  # Add an icon file

                self.config = Config()
                self.setup_ui()
                self.detector = None

    def setup_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        # Create
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)

        # Main
        self.main_tab = QWidget()
        self.main_layout = QVBoxLayout(self.main_tab)
        self.tabs.addTab(self.main_tab, "Main")

        self.start_button = QPushButton("Start Detection")
        self.start_button.clicked.connect(self.start_detection)
        self.main_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Detection")
        self.stop_button.clicked.connect(self.stop_detection)
        self.stop_button.setEnabled(False)
        self.main_layout.addWidget(self.stop_button)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.main_layout.addWidget(self.log_area)

        self.status_label = QLabel("Status: Idle")
        self.main_layout.addWidget(self.status_label)

        # Settings
        self.settings_tab = QWidget()
        self.settings_layout = QFormLayout(self.settings_tab)
        self.tabs.addTab(self.settings_tab, "Settings")

        self.scan_interval = QLineEdit(str(self.config.get('scan_interval')))
        self.settings_layout.addRow("Scan Interval (seconds):", self.scan_interval)

        self.traffic_threshold = QLineEdit(str(self.config.get('traffic_threshold')))
        self.settings_layout.addRow("Traffic Threshold:", self.traffic_threshold)

        self.enable_notifications = QCheckBox()
        self.enable_notifications.setChecked(self.config.get('enable_notifications'))
        self.settings_layout.addRow("Enable Notifications:", self.enable_notifications)

        self.save_settings_button = QPushButton("Save Settings")
        self.save_settings_button.clicked.connect(self.save_settings)
        self.settings_layout.addWidget(self.save_settings_button)

        # Reports tab
        self.reports_tab = QWidget()
        self.reports_layout = QVBoxLayout(self.reports_tab)
        self.tabs.addTab(self.reports_tab, "Reports")

        self.generate_report_button = QPushButton("Generate Report")
        self.generate_report_button.clicked.connect(self.generate_report)
        self.reports_layout.addWidget(self.generate_report_button)

    def start_detection(self):
        interface = self.get_default_interface()
        self.detector = MITMDetector(interface, self.config.config)
        self.detector.detection_signal.connect(self.update_log)
        self.detector.alert_signal.connect(self.show_alert)
        self.detector.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_label.setText(f"Status: Detecting on {interface}")

    def stop_detection(self):
        if self.detector:
            self.detector.stop()
            self.detector.wait()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Status: Idle")

    def update_log(self, message):
        self.log_area.append(message)

    def show_alert(self, title, message):
        if self.config.get('enable_notifications'):
            notification.notify(
                title=title,
                message=message,
                app_name="MITM Detector",
                timeout=10
            )

    def save_settings(self):
        self.config.set('scan_interval', int(self.scan_interval.text()))
        self.config.set('traffic_threshold', int(self.traffic_threshold.text()))
        self.config.set('enable_notifications', self.enable_notifications.isChecked())
        self.update_log("Settings saved successfully.")

    def generate_report(self):
        report = "MITM Detection Report\n"
        report += "=" * 25 + "\n"
        report += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        with open('mitm_detector.log', 'r') as log_file:
            report += log_file.read()
        
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Report", "", "Text Files (*.txt)")
        if file_name:
            with open(file_name, 'w') as f:
                f.write(report)
            self.update_log(f"Report saved to {file_name}")

    def get_default_interface(self):
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            if interface != 'lo' and netifaces.AF_INET in netifaces.ifaddresses(interface):
                return interface
        return None

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()

    # Setup automatic updates
    def check_for_updates():
        try:
            response = requests.get("https://api.github.com/repos/your_repo/mitm_detector/releases/latest")
            latest_version = response.json()["tag_name"]
            current_version = "v1.0.0"  # Replace with actual version tracking
            if latest_version > current_version:
                window.update_log(f"New version available: {latest_version}")
        except Exception as e:
            window.update_log(f"Failed to check for updates: {str(e)}")

    schedule.every().day.do(check_for_updates)

    # scheduler
    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(1)

    import threading
    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.start()

    sys.exit(app.exec_())

if __name__ == "__main__":
    main()