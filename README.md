# 🔥 WiFi Handshake Toolkit  

![Version](https://img.shields.io/badge/version-1.0-blue)  
![License](https://img.shields.io/badge/license-MIT-green)  
![Status](https://img.shields.io/badge/status-In_Progress-yellow)  
![Python](https://img.shields.io/badge/Python-3.x-orange)  
![Aircrack-ng](https://img.shields.io/badge/Dependencies-Aircrack--ng-red)  
![Scapy](https://img.shields.io/badge/Scapy-Network_Tools-purple)  

---

## 📋 Project Description  
An **automated WiFi handshake capture, cracking, and conversion toolkit** built with Python.  
Designed for **educational & lab use only**, it provides a simple interactive terminal GUI with colorful menus, target selection, and built-in cracking support.  

---

## 🖼️ Banner  
![WiFi Toolkit Banner](banner)  


# Wi-Fi Handshake Capture & Cracking Tool

This tool automates Wi-Fi penetration testing tasks such as scanning networks, capturing handshakes, converting them, and cracking WPA/WPA2 handshakes using `aircrack-ng` and `hashcat`.

## Features
- Scan available Wi-Fi networks
- Select target network
- Capture WPA/WPA2 handshakes
- Convert handshakes to `.hc22000` format for Hashcat
- Crack captured handshakes with `aircrack-ng`
- Retry deauthentication to capture full EAPOL handshakes
- Save cracked credentials (ESSID, BSSID, password) into a file
- Interactive menu system
- Re-select target without rescanning

## Requirements
Ensure you have the following installed:

```bash
sudo apt update && sudo apt install -y aircrack-ng hashcat python3 python3-pip
pip3 install -r requirements.txt
```

## Usage
Run the script with:

```bash
sudo python3 main.py
```

### Menu Options
```
=== Next Step ===
1. Crack captured handshakes
2. Convert handshakes to .hc22000
3. Retry deauth to capture full EAPOL handshake
4. Settings
5. Rescan
6. Exit
7. Re-select target
```

## Output
Cracked results are saved automatically in:
```
cracked_wifi.txt
```

## Notes
- You must run this script with **root privileges** (`sudo`).
- Use this tool **only on networks you own or have permission to test**. Unauthorized use is illegal.

---

### Disclaimer
This project is for **educational purposes only**. The author is not responsible for misuse.
