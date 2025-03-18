import os
import hashlib
import threading
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

try:
    import scapy.all as scapy
except ImportError:
    print("Please install scapy: pip install scapy")

# Logging configuration
LOG_DIRECTORY = "firewall_logs"
DATA_LOG_FILE = os.path.join(LOG_DIRECTORY, "data_scan_log.txt")
NETWORK_LOG_FILE = os.path.join(LOG_DIRECTORY, "network_scan_log.txt")

class FirewallLogger:
    """Handles logging operations for the firewall system."""

    @staticmethod
    def create_log_directory():
        """Creates the log directory if it doesn't exist."""
        if not os.path.exists(LOG_DIRECTORY):
            os.makedirs(LOG_DIRECTORY)

    @staticmethod
    def create_log_file(file_path):
        """Creates a log file with header if it doesn't exist."""
        if not os.path.exists(file_path):
            with open(file_path, 'w') as log_file:
                log_file.write(f"Firewall Log - {os.path.basename(file_path)}\n")
                log_file.write(f"Created on {datetime.now()}\n\n")

    @staticmethod
    def log_threat(log_file, threat_type, message):
        """Logs detected threats to specified log file with timestamp."""
        try:
            with open(log_file, "a") as f:
                f.write(f"[{datetime.now()}] {threat_type} - {message}\n")
            print(f"[ALERT] {threat_type}: {message}")
        except Exception as e:
            print(f"Error writing to log file {log_file}: {e}")

    @classmethod
    def log_data_threat(cls, threat_type, message):
        """Logs data-related threats."""
        cls.log_threat(DATA_LOG_FILE, threat_type, message)

    @classmethod
    def log_network_threat(cls, threat_type, message):
        """Logs network-related threats."""
        cls.log_threat(NETWORK_LOG_FILE, threat_type, message)

# Existing threat signatures remain the same
THREAT_SIGNATURES = {
    "blocked_extensions": [".exe", ".bat", ".js", ".vbs", ".scr", ".ps1"],
    "malware_hashes": [
        "44d88612fea8a8f36de82e1278abb02f",  # WannaCry
        "e2fc714c4727ee9395f324cd2e7f331f",  # Example malicious .exe
        "5d41402abc4b2a76b9719d911017c592",  # Another malware sample
        "99017f6eebbac24f351415dd410d522d",  # EICAR test file
    ],
    "malware_patterns": [
        b'Powershell -enc',
        b'MSOffice exploit',
        b'TrojanDownloader',
    ],
}

def get_file_hash(file_path, hash_func=hashlib.md5):
    """Computes the hash of a file using the specified hash function (default: MD5)."""
    hash_obj = hash_func()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hash_obj.update(chunk)
    except OSError:
        FirewallLogger.log_data_threat("File Error", f"Unable to access file: {file_path}")
        return None
    return hash_obj.hexdigest()

def scan_file_for_signature(file_path, output_widget):
    """Scans a file for known malware signatures."""
    file_hash = get_file_hash(file_path)
    if file_hash in THREAT_SIGNATURES["malware_hashes"]:
        message = f"Malware Detected: {file_path} matches known malware hash: {file_hash}"
        output_widget.insert(tk.END, message + '\n')
        FirewallLogger.log_data_threat("Malware Detected", message)

    try:
        with open(file_path, "rb") as f:
            content = f.read()
            for pattern in THREAT_SIGNATURES["malware_patterns"]:
                if pattern in content:
                    message = f"Malware Detected: {file_path} contains suspicious pattern."
                    output_widget.insert(tk.END, message + '\n')
                    FirewallLogger.log_data_threat("Malware Detected", message)
                    break
    except OSError:
        FirewallLogger.log_data_threat("File Error", f"Unable to access file: {file_path}")

def scan_network(output_widget):
    """Scans the network for suspicious activity."""
    try:
        ip_range = "192.168 .1.0/24"  # Adjust this to your network range
        output_widget.insert(tk.END, f"Scanning network: {ip_range}\n")
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        for element in answered_list:
            output_widget.insert(tk.END, f"IP: {element[1].psrc}, MAC: {element[1].hwsrc}\n")

    except Exception as e:
        FirewallLogger.log_network_threat("Network Scan Error", str(e))
        output_widget.insert(tk.END, f"Network Scan Error: {str(e)}\n")

def start_file_scan(output_widget):
    """Starts the file scan based on user-selected files."""
    file_paths = filedialog.askopenfilenames(title="Select Files to Scan")
    for file_path in file_paths:
        scan_file_for_signature(file_path, output_widget)
        if any(file_path.endswith(ext) for ext in THREAT_SIGNATURES["blocked_extensions"]):
            message = f"Blocked File Type: {file_path}"
            output_widget.insert(tk.END, message + '\n')
            FirewallLogger.log_data_threat("Blocked File Type", message)

def start_network_scan(output_widget):
    """Starts the network scan in a separate thread."""
    network_scan_thread = threading.Thread(target=scan_network, args=(output_widget,))
    network_scan_thread.start()

def create_gui():
    """Creates the main GUI for the firewall scanner."""
    root = tk.Tk()
    root.title("Firewall Scanner")

    frame = tk.Frame(root)
    frame.pack(pady=10)

    output_widget = scrolledtext.ScrolledText(frame, width=80, height=20)
    output_widget.pack()

    scan_button = tk.Button(root, text="Scan Files", command=lambda: start_file_scan(output_widget))
    scan_button.pack(pady=5)

    network_scan_button = tk.Button(root, text="Scan Network", command=lambda: start_network_scan(output_widget))
    network_scan_button.pack(pady=5)

    FirewallLogger.create_log_directory()
    FirewallLogger.create_log_file(DATA_LOG_FILE)
    FirewallLogger.create_log_file(NETWORK_LOG_FILE)

    root.mainloop()

if __name__ == "__main__":
 create_gui()
