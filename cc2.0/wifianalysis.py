import tkinter as tk
from tkinter import ttk
import subprocess
import re
import threading
import time
import platform
from scapy.all import sniff, ARP, Dot11, rdpcap, TCP
from collections import defaultdict
from datetime import datetime

class WiFiAnalyzer:
    def __init__(self, master):
        self.master = master
        master.title("Advanced WiFi Analyzer")
        master.geometry("800x600")
        
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.frames = {
            "current": ttk.Frame(self.notebook),
            "nearby": ttk.Frame(self.notebook),
            "users": ttk.Frame(self.notebook),
            "security": ttk.Frame(self.notebook),
            "attacks": ttk.Frame(self.notebook)
        }
        
        for name, frame in self.frames.items():
            self.notebook.add(frame, text=name.capitalize())
        
        self.create_widgets()
        self.attack_detection_running = False
        
    def create_widgets(self):
        self.create_current_network_widgets()
        self.create_nearby_networks_widgets()
        self.create_connected_users_widgets()
        self.create_security_analysis_widgets()
        self.create_attack_detection_widgets()
        
    def create_current_network_widgets(self):
        frame = self.frames["current"]
        ttk.Button(frame, text="Analyze Current Network", command=self.analyze_current_network).pack(pady=10)
        self.current_network_info = tk.Text(frame, height=20, width=80)
        self.current_network_info.pack(pady=10)
        
    def create_nearby_networks_widgets(self):
        frame = self.frames["nearby"]
        ttk.Button(frame, text="Scan Nearby Networks", command=self.scan_nearby_networks).pack(pady=10)
        self.nearby_networks_info = tk.Text(frame, height=20, width=80)
        self.nearby_networks_info.pack(pady=10)
        
    def create_connected_users_widgets(self):
        frame = self.frames["users"]
        ttk.Button(frame, text="List Connected Users", command=self.list_connected_users).pack(pady=10)
        self.connected_users_info = tk.Text(frame, height=20, width=80)
        self.connected_users_info.pack(pady=10)
        
    def create_security_analysis_widgets(self):
        frame = self.frames["security"]
        ttk.Button(frame, text="Perform Security Analysis", command=self.perform_security_analysis).pack(pady=10)
        self.security_analysis_info = tk.Text(frame, height=20, width=80)
        self.security_analysis_info.pack(pady=10)
        
    def create_attack_detection_widgets(self):
        frame = self.frames["attacks"]
        self.attack_button = ttk.Button(frame, text="Start Attack Detection", command=self.toggle_attack_detection)
        self.attack_button.pack(pady=10)
        self.attack_detection_info = tk.Text(frame, height=20, width=80)
        self.attack_detection_info.pack(pady=10)
        
    def analyze_current_network(self):
        self.current_network_info.delete('1.0', tk.END)
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(["netsh", "wlan", "show", "interfaces"]).decode("utf-8")
                ssid = re.search(r"SSID\s*:\s*(.*)", result)
                signal = re.search(r"Signal\s*:\s*(.*)", result)

            elif platform.system() == "Linux":
                result = subprocess.check_output(["iwgetid"]).decode("utf-8")
                ssid = re.search(r"ESSID:\"(.*)\"", result)
                signal = subprocess.check_output(["iwconfig", "wlan0"]).decode("utf-8")
                signal = re.search(r"Signal level=(.*) dBm", signal)

            if ssid and signal:
                self.current_network_info.insert(tk.END, f"SSID: {ssid.group(1).strip()}\n")
                self.current_network_info.insert(tk.END, f"Signal Strength: {signal.group(1).strip()}\n")
            else:
                self.current_network_info.insert(tk.END, "Could not retrieve network information.\n")
            
            gateway_ip = self.get_router_admin_ip()
            self.current_network_info.insert(tk.END, f"Router Admin IP: {gateway_ip}\n")
        except Exception as e:
            self.current_network_info.insert(tk.END, f"Error: {str(e)}\n")
        
    def scan_nearby_networks(self):
        self.nearby_networks_info.delete('1.0', tk.END)
        networks = self.get_nearby_networks()
        if networks:
            for network in networks:
                self.nearby_networks_info.insert(tk.END, f"SSID: {network['ssid']}, Channel: {network['channel']}, Encryption: {network['encryption']}\n")
        else:
            self.nearby_networks_info.insert(tk.END, "Could not retrieve nearby networks.\n")
        
    def list_connected_users(self):
        self.connected_users_info.delete('1.0', tk.END)
        users = self.get_connected_users()
        if users:
            for user in users:
                self.connected_users_info.insert(tk.END, f"IP: {user['ip']}, MAC: {user['mac']}\n")
        else:
            self.connected_users_info.insert(tk.END, "Could not retrieve connected users.\n")
        
    def perform_security_analysis(self):
        self.security_analysis_info.delete('1.0', tk.END)
        security_info = self.analyze_security()
        self.security_analysis_info.insert(tk.END, security_info)
        
    def toggle_attack_detection(self):
        if not self.attack_detection_running:
            self.attack_detection_running = True
            self.attack_button.config(text="Stop Attack Detection")
            self.attack_detection_thread = threading.Thread(target=self.detect_attacks)
            self.attack_detection_thread.start()
        else:
            self.attack_detection_running = False
            self.attack_button.config(text="Start Attack Detection")
        
    def detect_attacks(self):
        self.attack_detection_info.delete('1.0', tk.END)
        packet_count = defaultdict(int)
        arp_table = {}
        recent_packets = []

        def analyze_packet(packet):
            nonlocal recent_packets
            if ARP in packet:
                # Check for suspicious ARP packets
                if packet[ARP].op == 2:  # ARP is-at (response)
                    sender_ip = packet[ARP].psrc
                    sender_mac = packet[ARP].hwsrc
                    if sender_ip in arp_table and arp_table[sender_ip] != sender_mac:
                        self.attack_detection_info.insert(tk.END, f"ARP Spoofing detected: {sender_ip} is at {sender_mac} but previously at {arp_table[sender_ip]}\n")
                    arp_table[sender_ip] = sender_mac

            if Dot11 in packet:
                # Check for deauthentication packets
                if packet.type == 0 and packet.subtype == 12:  # Deauth frame
                    self.attack_detection_info.insert(tk.END, f"Deauthentication attack detected from {packet.addr2}\n")

            if TCP in packet:
                # Count TCP packets from each source IP
                src_ip = packet[1].src
                packet_count[src_ip] += 1
                recent_packets.append((src_ip, datetime.now()))

            # Remove old packets from recent_packets
            threshold_time = datetime.now() - time.timedelta(seconds=10)
            recent_packets = [pkt for pkt in recent_packets if pkt[1] > threshold_time]

            # Detect DDoS-like behavior
            for ip, count in packet_count.items():
                if count > 100:  # Threshold for suspecting DDoS
                    self.attack_detection_info.insert(tk.END, f"Potential DDoS attack from {ip}\n")
                    packet_count[ip] = 0  # Reset counter for this IP

        try:
            sniff(prn=analyze_packet, store=0, stop_filter=lambda x: not self.attack_detection_running)
        except Exception as e:
            self.attack_detection_info.insert(tk.END, f"Error: {str(e)}\n")
        
    def get_router_admin_ip(self):
        if platform.system() == "Windows":
            result = subprocess.check_output("ipconfig").decode("utf-8")
            gateway = re.search(r"Default Gateway . . . . . . . . . . . : (\d+\.\d+\.\d+\.\d+)", result)
        elif platform.system() == "Linux":
            result = subprocess.check_output(["ip", "route"]).decode("utf-8")
            gateway = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result)
        return gateway.group(1) if gateway else "Unknown"
    
    def get_nearby_networks(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"]).decode("utf-8")
                networks = re.findall(r"SSID \d+ : (.+?)\n.*?Signal\s*:\s*(.+?)%\n.*?Authentication\s*:\s*(.+?)\n", result, re.DOTALL)
                return [{"ssid": ssid.strip(), "signal": signal.strip(), "encryption": encryption.strip()} for ssid, signal, encryption in networks]
            elif platform.system() == "Linux":
                result = subprocess.check_output(["nmcli", "-f", "SSID,SECURITY,SIGNAL", "dev", "wifi"]).decode("utf-8")
                lines = result.strip().split("\n")[1:]
                networks = [line.split() for line in lines if line]
                return [{"ssid": n[0], "encryption": n[1], "signal": n[2]} for n in networks if len(n) >= 3]
        except Exception as e:
            print(f"Error: {e}")
            return []
    
    def get_connected_users(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(["arp", "-a"]).decode("utf-8")
                users = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F:-]+)", result)
                return [{"ip": ip, "mac": mac} for ip, mac in users]
            elif platform.system() == "Linux":
                result = subprocess.check_output(["arp-scan", "--localnet"]).decode("utf-8")
                users = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F:-]+)", result)
                return [{"ip": ip, "mac": mac} for ip, mac in users]
        except Exception as e:
            print(f"Error: {e}")
            return []
    
    def analyze_security(self):
        # Simulated security analysis
        return """
        Security Analysis:
        1. WiFi encryption: WPA2 (Good)
        2. Password strength: Moderate (Could be improved)
        3. Hidden SSID: No
        4. MAC filtering: Disabled
        
        Recommendations:
        1. Enable MAC address filtering
        2. Use a stronger WiFi password
        3. Regularly update router firmware
        4. Use a guest network for visitors
        5. Enable firewall on the router
        """

root = tk.Tk()
wifi_analyzer = WiFiAnalyzer(root)
root.mainloop()
