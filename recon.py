import socket
import sys
import json
import xml.etree.ElementTree as ET
import logging
import ssl
import os

# Suppress Scapy IPv6/runtime warnings on startup
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, UDP, sr1, send, ICMP

# Configuration Constants
FTP_PORT = 21
SSH_PORT = 22
DNS_PORT = 53
HTTP_PORT = 80
SMTP_PORTS = [25, 465, 587]
IMAP_PORTS = [143, 993]
TIMEOUT = 2.0

# Dynamic State Tracker & Core Priority Engine
port_votes = {}  # Format: { port: {"open": X, "closed": Y, "filtered": Z} }
detected_as_windows = False  
port_authoritative_states = {}  

# Added "status" key to track port state separate from version
scan_results = {
    "target_ip": "",
    "zombie_ip": "Skipped",
    "network_discovery": {},
    "port_scans": {
        "21": {"service": "FTP", "version": "Not Evaluated", "status": "Unknown", "scans": {}, "enumeration": {}},
        "22": {"service": "SSH", "version": "Not Evaluated", "status": "Unknown", "scans": {}, "enumeration": {}},
        "53": {"service": "DNS", "version": "Not Evaluated", "status": "Unknown", "scans": {}, "enumeration": {}},
        "80": {"service": "HTTP", "version": "Not Evaluated", "status": "Unknown", "scans": {}, "enumeration": {}},
        "25": {"service": "SMTP", "version": "Not Evaluated", "status": "Unknown", "scans": {}, "enumeration": {}},
        "465": {"service": "SMTP-SSL", "version": "Not Evaluated", "status": "Unknown", "scans": {}, "enumeration": {}},
        "587": {"service": "SMTP-Submission", "version": "Not Evaluated", "status": "Unknown", "scans": {}, "enumeration": {}},
        "143": {"service": "IMAP", "version": "Not Evaluated", "status": "Unknown", "scans": {}, "enumeration": {}},
        "993": {"service": "IMAP-SSL", "version": "Not Evaluated", "status": "Unknown", "scans": {}, "enumeration": {}}
    },
    "os_fingerprint": "Unknown"
}

def log_silent(section, key, message, port=None):
    """Saves raw metrics strictly into background telemetry WITHOUT screen spam."""
    clean_msg = message.replace("[+]", "").replace("[-]", "").replace("[*]", "").replace("[HEURISTIC]", "").replace("[WARNING]", "").replace("[VULN]", "").strip()
    
    if port:
        port_str = str(port)
        if port_str in scan_results["port_scans"]:
            if section == "scans":
                scan_results["port_scans"][port_str]["scans"][key] = clean_msg
            elif section == "enumeration":
                scan_results["port_scans"][port_str]["enumeration"][key] = clean_msg
    else:
        if section == "discovery":
            scan_results["network_discovery"][key] = clean_msg
        elif section == "os":
            scan_results["os_fingerprint"] = clean_msg

def log_and_print(section, key, message, port=None):
    """Prints output explicitly during application layer auditing."""
    print(message)
    log_silent(section, key, message, port)

def cast_vote(port, state, weight=1):
    """Registers weighted votes into the consensus pool."""
    if port not in port_votes:
        port_votes[port] = {"open": 0, "closed": 0, "filtered": 0}
    port_votes[port][state] += weight

def final_consensus_decision(port):
    """
    Computes cumulative totals instead of breaking out early on a single 
    high-weight result. This heavily mitigates false-positive state lock-ins.
    """
    votes = port_votes.get(port, {"open": 0, "closed": 0, "filtered": 0})
    
    # If no scans scored anything, it's filtered
    if votes["open"] == 0 and votes["closed"] == 0 and votes["filtered"] == 0:
        return "FILTERED"
        
    max_state = max(votes, key=votes.get)
    return max_state.upper()

# ==============================================================================
# 1. NETWORK PROTOCOL PROBE ENGINE
# ==============================================================================

def ping_scan(target):
    print(f"[*] [Ping Scan] Verifying link layer context for {target}...")
    ans = sr1(IP(dst=target)/ICMP(), timeout=TIMEOUT, verbose=0)
    if ans:
        log_silent("discovery", "host_status", "Host is up via ICMP Echo Reply.")
        print(f"  [+] Host {target} is up via ICMP Echo Reply.")
    else:
        log_silent("discovery", "host_status", "No ICMP response from target.")
        print(f"  [-] No ICMP response from {target}. Proceeding cautiously.")

def basic_port_scan(target, port):
    """TCP Connect Scan (High Trust Verification)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        result = s.connect_ex((target, port))
        if result == 0:
            log_silent("scans", "tcp_connect", "OPEN", port=port)
            cast_vote(port, "open", weight=10) 
        else:
            log_silent("scans", "tcp_connect", "CLOSED", port=port)
            cast_vote(port, "closed", weight=10) 
            fallback_version = service_and_os_detection(target, port, fallback_mode=True)
            if str(port) in scan_results["port_scans"]:
                # Clean Separation: Version shows profile, Status shows "CLOSED"
                scan_results["port_scans"][str(port)]["version"] = fallback_version
                scan_results["port_scans"][str(port)]["status"] = "CLOSED"
        s.close()
    except Exception as e:
        log_silent("scans", "tcp_connect", f"Exception: {e}", port=port)

def syn_scan(target, port):
    """TCP SYN Stealth Scan"""
    packet = IP(dst=target)/TCP(dport=port, flags="S")
    response = sr1(packet, timeout=TIMEOUT, verbose=0)
    if response and response.haslayer(TCP):
        if response[TCP].flags == 0x12: # SYN-ACK
            log_silent("scans", "syn_scan", "OPEN", port=port)
            cast_vote(port, "open", weight=10)
            send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0) 
        elif response[TCP].flags == 0x14: # RST
            log_silent("scans", "syn_scan", "CLOSED", port=port)
            cast_vote(port, "closed", weight=10)
    else:
        log_silent("scans", "syn_scan", "FILTERED", port=port)
        cast_vote(port, "filtered", weight=2)

def tcp_scan(target, port):
    """Full TCP Handshake Verification"""
    syn_packet = IP(dst=target)/TCP(dport=port, flags="S", seq=1000)
    syn_ack = sr1(syn_packet, timeout=TIMEOUT, verbose=0)
    if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
        ack_packet = IP(dst=target)/TCP(dport=port, flags="A", seq=1001, ack=syn_ack[TCP].seq + 1)
        send(ack_packet, verbose=0)
        log_silent("scans", "full_tcp", "OPEN", port=port)
        cast_vote(port, "open", weight=5)
        send(IP(dst=target)/TCP(dport=port, flags="R", seq=1002), verbose=0)
    else:
        log_silent("scans", "full_tcp", "Handshake Fail", port=port)

def udp_scan(target, port):
    """UDP Scans properly tied back into the voting framework"""
    packet = IP(dst=target)/UDP(dport=port)
    response = sr1(packet, timeout=TIMEOUT, verbose=0)
    if response is None:
        log_silent("scans", "udp_scan", "OPEN|FILTERED", port=port)
        cast_vote(port, "filtered", weight=1)
    elif response.haslayer(UDP):
        log_silent("scans", "udp_scan", "UDP_OPEN", port=port)
        cast_vote(port, "open", weight=8)
    elif response.haslayer(ICMP):
        if int(response[ICMP].type) == 3 and int(response[ICMP].code) == 3:
            log_silent("scans", "udp_scan", "UDP_CLOSED", port=port)
            cast_vote(port, "closed", weight=10)

def process_inverse_response(response, port, scan_type):
    """Inverse responses logged internally to isolate ambient scan noise."""
    global detected_as_windows
    if response is None:
        log_silent("scans", scan_type, "OPEN|FILTERED", port=port)
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:
        if detected_as_windows:
            log_silent("scans", scan_type, "OPEN_RFC793_ANOMALY", port=port)
        else:
            log_silent("scans", scan_type, "CLOSED", port=port)

def fin_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="F")
    process_inverse_response(sr1(packet, timeout=TIMEOUT, verbose=0), port, "fin_scan")

def null_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="")
    process_inverse_response(sr1(packet, timeout=TIMEOUT, verbose=0), port, "null_scan")

def xmas_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="FPU")
    process_inverse_response(sr1(packet, timeout=TIMEOUT, verbose=0), port, "xmas_scan")

def ack_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="A")
    response = sr1(packet, timeout=TIMEOUT, verbose=0)
    if response is None:
        log_silent("scans", "ack_scan", "FILTERED", port=port)
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:
        log_silent("scans", "ack_scan", "UNFILTERED", port=port)

def window_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="A")
    response = sr1(packet, timeout=TIMEOUT, verbose=0)
    if response and response.haslayer(TCP) and response[TCP].flags == 0x14:
        if response[TCP].window > 0:
            log_silent("scans", "window_scan", "OPEN_INDICATION", port=port)
        else:
            log_silent("scans", "window_scan", "CLOSED_INDICATION", port=port)
    else:
        log_silent("scans", "window_scan", "FILTERED", port=port)

def maimon_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="FA")
    response = sr1(packet, timeout=TIMEOUT, verbose=0)
    if response is None:
        log_silent("scans", "maimon_scan", "OPEN|FILTERED", port=port)
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:
        log_silent("scans", "maimon_scan", "CLOSED", port=port)

def zombie_scan(target, zombie_ip, port):
    if not zombie_ip: return
    try:
        p1 = sr1(IP(dst=zombie_ip)/TCP(flags="SA"), timeout=TIMEOUT, verbose=0)
        if not p1: return
        id1 = p1.id
        send(IP(src=zombie_ip, dst=target)/TCP(dport=port, flags="S"), verbose=0)
        p2 = sr1(IP(dst=zombie_ip)/TCP(flags="SA"), timeout=TIMEOUT, verbose=0)
        if not p2: return
        id2 = p2.id
        if id2 == id1 + 2:
            log_silent("scans", "zombie_scan", "OPEN_ZOMBIE", port=port)
        else:
            log_silent("scans", "zombie_scan", "CLOSED_ZOMBIE", port=port)
    except:
        pass

# ==============================================================================
# 2. FIXED ADVANCED HEURISTIC OS ESTIMATION ENGINE
# ==============================================================================

def service_and_os_detection(target, port, fallback_mode=False):
    """
    Predicts remote operating systems cleanly by using steady-state network variables
    (Initial TTL) combined with RFC-compliance checks to mitigate false matches.
    """
    global detected_as_windows
    linux_points = 0
    windows_points = 0
    
    # Core Test 1: Handle Initial TTL boundaries (The most resilient baseline metric)
    pkt = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=TIMEOUT, verbose=0)
    if pkt and pkt.haslayer(IP):
        ttl = pkt.ttl
        if ttl <= 64:
            linux_points += 4
        elif 64 < ttl <= 128:
            windows_points += 4
            
    # Core Test 2: RFC 793 Flag Validation (Null packet handling)
    null_pkt = sr1(IP(dst=target)/TCP(dport=port, flags=""), timeout=TIMEOUT, verbose=0)
    if null_pkt and null_pkt.haslayer(TCP):
        if null_pkt[TCP].flags == 0x14: # RST
            windows_points += 2
    else:
        linux_points += 2

    # Consolidating confidence intervals
    if windows_points > linux_points and windows_points >= 4:
        detected_as_windows = True
        os_guess = f"Windows OS Stack Profile (Heuristical Match Confidence: {windows_points}/6)"
    elif linux_points > windows_points and linux_points >= 4:
        os_guess = f"Linux/Unix Stack Profile (Heuristical Match Confidence: {linux_points}/6)"
    else:
        os_guess = "Generic Network Framework or Hardened Firewall Environment"
 
    if not fallback_mode:
        print(f"  [HEURISTIC] Operating System Identified: {os_guess}")
        log_silent("os", "fingerprint", os_guess)
    
    return os_guess

# ==============================================================================
# 3. APPLICATION LAYER MODULES
# ==============================================================================

def run_ssh_advanced_audit(target):
    log_and_print("enumeration", "ssh_init", f"[*] Running SSH Banner Discovery at {target}:22", port=SSH_PORT)
    banner = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((target, SSH_PORT))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        scan_results["port_scans"]["22"]["version"] = banner
        log_and_print("enumeration", "ssh_banner", f"  [+] SSH Software Banner Stack: {banner}", port=SSH_PORT)
        s.close()
    except Exception as e:
        log_and_print("enumeration", "ssh_fault", f"  [-] SSH Connection lost or timed out: {e}", port=SSH_PORT)

    if banner:
        vulns = {"OpenSSH_7.2p2": "Known Username Enumeration behavior documented (CVE-2018-15473)"}
        for release, descriptor in vulns.items():
            if release in banner:
                log_and_print("enumeration", "ssh_vuln_script", f"    [INFO] Signature Hit -> {release}: {descriptor}", port=SSH_PORT)

def ftp_banner_grab(target):
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        s.connect((target, FTP_PORT))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner
    except: 
        return None

def ftp_anonymous_check(target):
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        s.connect((target, FTP_PORT))
        s.recv(1024)
        s.send(b"USER anonymous\r\n")
        s.recv(1024)
        s.send(b"PASS anonymous@target.com\r\n")
        res2 = s.recv(1024).decode('utf-8')
        s.close()
        if "230" in res2 or "successful" in res2.lower():
            log_and_print("enumeration", "ftp_anonymous", "  [VULN] FTP Anonymous access allowed with default settings", port=FTP_PORT)
            return True
    except: 
        pass
    log_and_print("enumeration", "ftp_anonymous", "  [-] Anonymous login rejected by daemon.", port=FTP_PORT)
    return False

def ftp_bounce_check(target):
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        s.connect((target, FTP_PORT))
        s.recv(1024)
        s.send(b"USER anonymous\r\n")
        s.recv(1024)
        s.send(b"PASS anonymous@target.com\r\n")
        s.recv(1024)
        s.send(b"PORT 127,0,0,1,0,80\r\n")
        res = s.recv(1024).decode('utf-8')
        s.close()
        if res.startswith("200"):
            log_and_print("enumeration", "ftp_bounce", "  [INFO] Daemon accepted PORT payload formatting syntax", port=FTP_PORT)
        else:
            log_and_print("enumeration", "ftp_bounce", f"  [-] Target daemon blocked internal tracking instruction: {res.strip()}", port=FTP_PORT)
    except: 
        pass

def ftp_brute_force(target):
    users = ["admin", "root", "ftp"]
    passwords = ["password", "12345"]
    for u in users:
        for p in passwords:
            try:
                s = socket.socket()
                s.settimeout(1.0)
                s.connect((target, FTP_PORT))
                s.recv(1024)
                s.send(f"USER {u}\r\n".encode())
                s.recv(1024)
                s.send(f"PASS {p}\r\n".encode())
                res = s.recv(1024).decode('utf-8')
                s.close()
                if "230" in res:
                    log_and_print("enumeration", "ftp_brute", f"    [VULN] Basic fallback credentials active -> {u}:{p}", port=FTP_PORT)
                    return
            except: 
                pass
    log_and_print("enumeration", "ftp_brute", "  [-] No micro-dictionary authentication patterns matched.", port=FTP_PORT)

def run_ftp_vulnerability_scripts(banner):
    if not banner: return
    vulns = {"vsFTPd 2.3.4": "Legacy reference distribution backdoor vulnerability checks recommended"}
    for app, vuln in vulns.items():
        if app in banner: 
            log_and_print("enumeration", "ftp_vuln_match", f"    [INFO] App Banner Match -> {app}: {vuln}", port=FTP_PORT)

def http_get_details(target):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((target, HTTP_PORT))
        s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\nUser-Agent: SecurityAuditorEngine\r\n\r\n")
        response = s.recv(4096).decode('utf-8', errors='ignore')
        s.close()
        server = "Unknown Headers"
        for line in response.split("\n"):
            if line.lower().strip().startswith("server:"): 
                server = line.split(":", 1)[1].strip()
        scan_results["port_scans"]["80"]["version"] = server
        log_and_print("enumeration", "http_server", f"  [+] HTTP Server Header Information field: {server}", port=HTTP_PORT)
    except Exception as e:
        log_and_print("enumeration", "http_details", f"  [-] Exception mapping web server: {e}", port=HTTP_PORT)

def http_methods_check(target):
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(TIMEOUT)
        conn.connect((target, HTTP_PORT))
        conn.send(b"OPTIONS / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        res = conn.recv(2048).decode('utf-8', errors='ignore')
        conn.close()
        for line in res.split("\n"):
            if line.lower().strip().startswith("allow:") or line.lower().strip().startswith("public:"):
                log_and_print("enumeration", "http_methods", f"    [+] Exposed Server Options Directives: {line.strip()}", port=HTTP_PORT)
    except: 
        pass

def http_directory_enumeration(target):
    wordlist = ["admin", "login", "robots.txt"]
    for path in wordlist:
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(1.0)
            conn.connect((target, HTTP_PORT))
            conn.send(f"GET /{path} HTTP/1.1\r\nHost: {target}\r\nCache-Control: no-cache\r\n\r\n".encode())
            response = conn.recv(512).decode('utf-8', errors='ignore')
            conn.close()
            if "HTTP/1.1 200" in response: 
                log_and_print("enumeration", f"path_{path}", f"    [+] Resolved Active endpoint found: /{path} (Status Code: 200)", port=HTTP_PORT)
        except: 
            pass

def run_smtp_advanced_audit(target, port):
    log_and_print("enumeration", "smtp_init", f"[*] Launching Structured SMTP Verification on target {target}:{port}", port=port)
    try:
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        plain_socket.settimeout(TIMEOUT)
        s = ssl.create_default_context().wrap_socket(plain_socket, server_hostname=target) if port == 465 else plain_socket
        s.connect((target, port))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        scan_results["port_scans"][str(port)]["version"] = banner
        log_and_print("enumeration", "smtp_banner", f"  [+] SMTP Core Service Banner: {banner}", port=port)
        s.close()
    except Exception as e:
        log_and_print("enumeration", "smtp_connect_error", f"  [-] SMTP Verification anomaly: {e}", port=port)

def run_dns_advanced_audit(target):
    log_and_print("enumeration", "dns_init", f"[*] Running DNS Boundary verification on {target}:{DNS_PORT}", port=DNS_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((target, DNS_PORT))
        scan_results["port_scans"]["53"]["version"] = "Active Responding DNS Structure"
        log_and_print("enumeration", "dns_status", "  [+] Active connection mapping successful on TCP Port 53.", port=DNS_PORT)
        s.close()
    except:
        log_and_print("enumeration", "dns_fault", f"  [-] DNS connection refused/filtered", port=DNS_PORT)

def run_imap_advanced_audit(target, port):
    log_and_print("enumeration", "imap_init", f"[*] Launching Target Verification on IMAP Endpoint {target}:{port}", port=port)
    try:
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        plain_socket.settimeout(TIMEOUT)
        s = ssl.create_default_context().wrap_socket(plain_socket, server_hostname=target) if port == 993 else plain_socket
        s.connect((target, port))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        scan_results["port_scans"][str(port)]["version"] = banner
        log_and_print("enumeration", "imap_banner", f"  [+] IMAP Clean Service Banner: {banner}", port=port)
        s.close()
    except: 
        pass

# ==============================================================================
# 4. UNIFIED SUMMARY REPORT GENERATOR (MODIFIED FOR SEPARATION)
# ==============================================================================

def generate_reports():
    print("\n[*] Exporting structured session summaries to operational storage...")
    base_filename = "report_data"
    
    # 1. Text Report Generation (Separated into Version and Port Status Points)
    with open(f"{base_filename}.txt", "w") as f:
        f.write("============================================================\n")
        f.write("            CONSOLIDATED AUTHORITATIVE PORT REPORT           \n")
        f.write("============================================================\n")
        f.write(f"Target host IP address: {scan_results['target_ip']}\n")
        f.write(f"OS Fingerprint Baseline: {scan_results['os_fingerprint']}\n\n")
        for port, data in scan_results["port_scans"].items():
            f.write(f"\n[Port Element {port} - Service: {data['service']}]\n")
            f.write(f"  -> Service Software Version: {data['version']}\n")
            f.write(f"  -> Port Status: {data.get('status', 'Unknown')}\n") # Next line point
            f.write("  -> Layer Scans Executed:\n")
            for sk, sv in data["scans"].items(): f.write(f"    {sk}: {sv}\n")
            f.write("  -> Enumeration Script Output:\n")
            for ek, ev in data["enumeration"].items(): f.write(f"    {ek}: {ev}\n")
    print(f"  [+] Saved Text Report to: {base_filename}.txt")

    # 2. JSON Report Generation (Now includes independent 'status' key per port)
    with open(f"{base_filename}.json", "w") as f:
        json.dump(scan_results, f, indent=4)
    print(f"  [+] Saved JSON Report to: {base_filename}.json")

    # 3. XML Report Generation (Added PortStatus attribute to XML nodes)
    root = ET.Element("ComprehensiveAuditReport", target=scan_results["target_ip"])
    ET.SubElement(root, "OperatingSystemEstimation").text = scan_results["os_fingerprint"]
    ports_node = ET.SubElement(root, "TargetInfrastructurePorts")
    for port, data in scan_results["port_scans"].items():
        p_node = ET.SubElement(
            ports_node, 
            "PortRecord", 
            ID=port, 
            Profile=data["service"], 
            SoftwareVersion=data["version"],
            PortStatus=data.get("status", "Unknown") # Explicitly separated attribute
        )
        s_node = ET.SubElement(p_node, "ProbingMatrices")
        for sk, sv in data["scans"].items(): ET.SubElement(s_node, sk).text = sv
        e_node = ET.SubElement(p_node, "EnumerationScripts")
        for ek, ev in data["enumeration"].items(): ET.SubElement(e_node, ek).text = ev
    ET.ElementTree(root).write(f"{base_filename}.xml", encoding="utf-8", xml_declaration=True)
    print(f"  [+] Saved XML Report to: {base_filename}.xml")

# ==============================================================================
# 5. THE MASTER AUTHORITATIVE EXECUTION GATEWAY
# ==============================================================================

if __name__ == "__main__":
    if sys.platform != "win32":
        if os.geteuid() != 0:
            sys.exit("[!] CRITICAL: Script requires root privileges.")

    target_ip = input("[?] Enter Target IP Address to scan: ").strip()
    if not target_ip: sys.exit("[!] Input error: Target IP context null.")
    scan_results["target_ip"] = target_ip
        
    zombie_input = input("[?] Enter Zombie Host IP for Idle Scan (Press Enter to Skip): ").strip()
    if zombie_input:
        scan_results["zombie_ip"] = zombie_input

    all_ports = [FTP_PORT, SSH_PORT, DNS_PORT, HTTP_PORT] + SMTP_PORTS + IMAP_PORTS

    # Step 1: Initial Discovery Verification
    ping_scan(target_ip)
    
    print("\n" + "="*15 + " Initializing Multi-Vector OS Profiling Engine " + "="*15)
    fallback_os = service_and_os_detection(target_ip, SSH_PORT)
    
    # Step 2: Multi-Vector Silent Scanning Loop
    print("\n[*] Probing all infrastructure targets via multiple raw matrices silently...")
    for p in all_ports:
        basic_port_scan(target_ip, p)
        syn_scan(target_ip, p)
        tcp_scan(target_ip, p)
        udp_scan(target_ip, p)
        fin_scan(target_ip, p)
        null_scan(target_ip, p)
        xmas_scan(target_ip, p)
        ack_scan(target_ip, p)
        window_scan(target_ip, p)
        maimon_scan(target_ip, p)
        if zombie_input:
            zombie_scan(target_ip, zombie_input, p)
            
    # Step 3: Compute Authority Decisions & Update State Maps
    for p in all_ports:
        port_authoritative_states[p] = final_consensus_decision(p)
        port_str = str(p)
        if port_str in scan_results["port_scans"]:
            # Set unified Port Status dynamically
            scan_results["port_scans"][port_str]["status"] = port_authoritative_states[p]
            
            # If the port is open, version is initialized as placeholder and overwritten during deep scans.
            # If the port is closed/filtered, version field is cleanly populated with the dynamic OS fallback match.
            if port_authoritative_states[p] != "OPEN":
                scan_results["port_scans"][port_str]["version"] = fallback_os

    # Step 4: Consolidated Table Output View
    print("\n" + "="*35)
    print(f" PORT     STATE      SERVICE")
    print("="*35)
    for p in all_ports:
        f_state = port_authoritative_states[p]
        s_name = scan_results["port_scans"][str(p)]["service"]
        print(f" {str(p):<8} {f_state:<11} {s_name}")
    print("="*35)
            
    # Step 5: Application Layer Scans on Verified OPEN ports
    print("\n" + "="*15 + " Executing Safe Open-Port Application Layer Enumeration " + "="*15)
    
    if port_authoritative_states[FTP_PORT] == "OPEN":
        ftp_banner = ftp_banner_grab(target_ip)
        if ftp_banner: 
            scan_results["port_scans"]["21"]["version"] = ftp_banner
        ftp_anonymous_check(target_ip)
        ftp_bounce_check(target_ip)
        ftp_brute_force(target_ip)
        run_ftp_vulnerability_scripts(ftp_banner)
    else:
        print(f"  [-] Skipping FTP Enumeration: Port {FTP_PORT} is strictly {port_authoritative_states[FTP_PORT]}.")
    
    if port_authoritative_states[SSH_PORT] == "OPEN":
        run_ssh_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping SSH Enumeration: Port {SSH_PORT} is strictly {port_authoritative_states[SSH_PORT]}.")

    if port_authoritative_states[DNS_PORT] == "OPEN":
        run_dns_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping DNS Enumeration: Port {DNS_PORT} is strictly {port_authoritative_states[DNS_PORT]}.")
    
    if port_authoritative_states[HTTP_PORT] == "OPEN":
        http_get_details(target_ip)
        http_methods_check(target_ip)
        http_directory_enumeration(target_ip)
    else:
        print(f"  [-] Skipping HTTP Enumeration: Port {HTTP_PORT} is strictly {port_authoritative_states[HTTP_PORT]}.")
    
    for s_port in SMTP_PORTS:
        if port_authoritative_states[s_port] == "OPEN":
            run_smtp_advanced_audit(target_ip, s_port)
        else:
            print(f"  [-] Skipping SMTP Enumeration: Port {s_port} is strictly {port_authoritative_states[s_port]}.")

    for i_port in IMAP_PORTS:
        if port_authoritative_states[i_port] == "OPEN":
            run_imap_advanced_audit(target_ip, i_port)
        else:
            print(f"  [-] Skipping IMAP Enumeration: Port {i_port} is strictly {port_authoritative_states[i_port]}.")
            
    # Step 6: Compile and Dump Report Artifacts
    generate_reports()
