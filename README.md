# NetCut (Web-based LAN Control Tool)

A Flask web application that scans your local network and can cut off a device's
internet access using ARP spoofing. It auto-detects your gateway and subnet, lists
connected hosts, and lets you selectively "cut" or restore devices from a browser UI.

> ⚠️ **Authorized use only.** This tool performs ARP spoofing, which disrupts network
> connectivity. Use it **only on networks you own or have explicit written permission
> to test**. Unauthorized use against networks or devices you do not control is illegal
> in most jurisdictions. You are solely responsible for how you use it.

## Features

- 🔍 **Auto network detection** — finds your active adapter, gateway, and subnet from `ipconfig`.
- 📡 **Host scan** — ARP/ping sweep of the subnet with hostname and MAC vendor hints.
- ✂️ **Cut / Restore** — ARP-spoof a single target (`/attack`, `/stop`).
- 🌐 **Cut all / Restore all** — act on every discovered host (`/attack_all`, `/stop_all`).
- 🖥️ **Web UI** — simple browser dashboard served by Flask.

## Requirements

- Python 3.8+
- [Npcap](https://npcap.com/) installed (required by Scapy on Windows)
- Administrator / root privileges (raw packet sending)

Python packages:

```
flask
scapy
```

## Installation

```bash
git clone https://github.com/anugrahhhhh/NEtcut.git
cd NEtcut
pip install -r requirements.txt
```

## Usage

Run with administrator privileges (needed for raw packets):

```bash
python app.py
```

Then open the UI in your browser:

```
http://127.0.0.1:5000
```

### Finding your network interface

If auto-detection picks the wrong adapter, run the helper to list active interfaces:

```bash
python cek.py
```

Match the IP it prints against your `ipconfig` output, then set `conf.iface` manually
near the top of `app.py` if needed.

## HTTP endpoints

| Method | Route         | Description                          |
|--------|---------------|--------------------------------------|
| GET    | `/`           | Web UI                               |
| GET    | `/info`       | Detected local network info          |
| GET    | `/scan`       | Scan the subnet for live hosts       |
| POST   | `/attack`     | Cut a single target                  |
| POST   | `/stop`       | Restore a single target              |
| POST   | `/attack_all` | Cut all discovered hosts             |
| POST   | `/stop_all`   | Restore all hosts                    |
| GET    | `/status`     | Current attack status                |

## Project structure

```
.
├── app.py              # Flask app: network detection, scanning, ARP spoofing
├── cek.py              # Helper to list active network interfaces
├── requirements.txt    # Python dependencies
└── templates/
    └── index.html      # Web UI
```

## Disclaimer

This project is provided for **educational purposes and authorized network
administration/testing only**. The authors accept no liability for misuse or any
damage caused by this software.
