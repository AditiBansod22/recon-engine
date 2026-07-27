import socket
import sys
import json
import xml.etree.ElementTree as ET
import logging
import ssl
import re
import time
from urllib.parse import urlparse

# Suppress Scapy IPv6/runtime warnings on startup
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, UDP, sr1, send, ICMP, DNS, DNSQR, RandShort, Raw

# Configuration Constants & Baseline Dynamic RTT Tracking
FTP_PORT = 21
SSH_PORT = 22
DNS_PORT = 53
HTTP_PORT = 80
HTTPS_PORT = 443
SMTP_PORTS = [25, 465, 587]
IMAP_PORTS = [143, 993]

DEFAULT_TIMEOUT = 2.0
MIN_TIMEOUT = 0.8
MAX_TIMEOUT = 6.0
MEASURED_RTT = None  # Calculated dynamically during network ping discovery

# Dynamic State Tracker & Core Priority Engine
port_votes = {}  # Format: { port: {"open": X, "closed": Y, "filtered": Z} }
detected_as_windows = False  # Track platform characteristics dynamically
port_authoritative_states = {}  # Definitive single state tracker

scan_results = {
    "target_ip": "",
    "zombie_ip": "Skipped",
    "network_discovery": {},
    "port_scans": {
        "21": {"service": "FTP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "22": {"service": "SSH", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "53": {"service": "DNS", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "80": {"service": "HTTP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "443": {"service": "HTTPS", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "25": {"service": "SMTP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "465": {"service": "SMTP-SSL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "587": {"service": "SMTP-Submission", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "143": {"service": "IMAP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "993": {"service": "IMAP-SSL", "version": "Not Evaluated", "scans": {}, "enumeration": {}}
    },
    "os_fingerprint": "Unknown"
}

def get_dynamic_timeout():
    """Calculates active operational timeout based on dynamic network baseline RTT."""
    if MEASURED_RTT is not None:
        calculated = MEASURED_RTT * 2.5
        return max(MIN_TIMEOUT, min(calculated, MAX_TIMEOUT))
    return DEFAULT_TIMEOUT

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
    """Explicitly allowed to print ONLY during targeted application layer auditing."""
    print(message)
    log_silent(section, key, message, port)

def cast_vote(port, state, weight=1):
    """Registers weighted votes. High-trust scans get massive absolute veto weights."""
    if port not in port_votes:
        port_votes[port] = {"open": 0, "closed": 0, "filtered": 0}
    port_votes[port][state] += weight

def final_consensus_decision(port):
    """Strict Priority Decision Engine."""
    votes = port_votes.get(port, {"open": 0, "closed": 0, "filtered": 0})
    
    if votes["open"] >= 10:   return "OPEN"
    if votes["closed"] >= 10: return "CLOSED"
    
    max_state = max(votes, key=votes.get)
    if votes[max_state] == 0:
        return "FILTERED"
    return max_state.upper()

# ==============================================================================
# 1. NETWORK PROTOCOL PROBE ENGINE WITH ADAPTIVE RTT CALCULATOR
# ==============================================================================

def ping_scan(target):
    global MEASURED_RTT
    print(f"[*] [Ping Scan] Verifying link layer context and calculating baseline RTT for {target}...")
    
    t_start = time.time()
    ans = sr1(IP(dst=target)/ICMP(), timeout=DEFAULT_TIMEOUT, verbose=0)
    t_end = time.time()
    
    if ans:
        MEASURED_RTT = t_end - t_start
        adaptive_t = get_dynamic_timeout()
        log_silent("discovery", "host_status", f"Host is up via ICMP Echo Reply. Measured RTT: {MEASURED_RTT*1000:.2f}ms. Adaptive Timeout: {adaptive_t:.2f}s")
        print(f"  [+] Host {target} is up via ICMP. Measured RTT: {MEASURED_RTT*1000:.2f}ms -> Dynamic Scan Timeout set to: {adaptive_t:.2f}s")
    else:
        log_silent("discovery", "host_status", f"No ICMP response. Reverting to default dynamic threshold {DEFAULT_TIMEOUT}s.")
        print(f"  [-] No ICMP response from {target}. Using default timeout threshold ({DEFAULT_TIMEOUT}s).")

def basic_port_scan(target, port):
    """HIGH TRUST CRITICAL SCAN (TCP CONNECT)"""
    timeout = get_dynamic_timeout()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        if result == 0:
            log_silent("scans", "tcp_connect", "OPEN", port=port)
            cast_vote(port, "open", weight=10)
        else:
            log_silent("scans", "tcp_connect", "CLOSED", port=port)
            cast_vote(port, "closed", weight=10)
            if str(port) in scan_results["port_scans"]:
                scan_results["port_scans"][str(port)]["version"] = "Port Closed"
        s.close()
    except Exception as e:
        log_silent("scans", "tcp_connect", f"Exception: {e}", port=port)

def syn_scan(target, port):
    """HIGH TRUST CRITICAL SCAN (SYN STEALTH)"""
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="S")
    response = sr1(packet, timeout=timeout, verbose=0)
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
    timeout = get_dynamic_timeout()
    syn_packet = IP(dst=target)/TCP(dport=port, flags="S", seq=1000)
    syn_ack = sr1(syn_packet, timeout=timeout, verbose=0)
    if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
        ack_packet = IP(dst=target)/TCP(dport=port, flags="A", seq=1001, ack=syn_ack[TCP].seq + 1)
        send(ack_packet, verbose=0)
        log_silent("scans", "full_tcp", "OPEN", port=port)
        cast_vote(port, "open", weight=5)
        send(IP(dst=target)/TCP(dport=port, flags="R", seq=1002), verbose=0)
    else:
        log_silent("scans", "full_tcp", "Handshake Fail", port=port)

def get_udp_service_probe(port):
    """
    Returns specific UDP payload probes according to target port context.
    """
    probes = {
        53:  DNS(rd=1, qd=DNSQR(qname="version.bind", qclass=3, qtype=16)), # DNS Chaos Query
        67:  Raw(b'\x01\x01\x06\x00' + b'\x00' * 232),                     # DHCP Discover
        69:  Raw(b'\x00\x01\x74\x65\x73\x74\x00\x6f\x63\x74\x65\x74\x00'),   # TFTP Read Request
        123: Raw(b'\x1b' + b'\x00' * 47),                                  # NTP Client Request (v3/v4)
        137: Raw(b'\x80\x90\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41'
                 b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'
                 b'\x41\x41\x41\x00\x00\x21\x00\x01'),                      # NetBIOS Name Query
        161: Raw(b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02'
                 b'\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06'
                 b'\x05\x2b\x06\x01\x02\x01\x05\x00'),                     # SNMP v2c Get-Next Query
        500: Raw(b'\x00' * 28)                                             # ISAKMP / VPN Security Association
    }
    return probes.get(port, Raw(b'')) # Default to standard empty UDP probe if no specific mapping exists

def udp_scan(target, port):
    """
    UPDATED UDP SCAN:
    Uses service-specific payloads for targeted UDP services rather than relying 
    solely on empty packets and ICMP Port Unreachable responses.
    """
    timeout = get_dynamic_timeout()
    probe_payload = get_udp_service_probe(port)
    
    packet = IP(dst=target)/UDP(sport=RandShort(), dport=port)/probe_payload
    response = sr1(packet, timeout=timeout, verbose=0)
    
    if response is None:
        log_silent("scans", "udp_scan", "OPEN|FILTERED", port=port)
        cast_vote(port, "filtered", weight=1)
    elif response.haslayer(UDP):
        log_silent("scans", "udp_scan", "UDP_OPEN", port=port)
        cast_vote(port, "open", weight=10) # High trust when daemon actively replies via UDP
    elif response.haslayer(ICMP):
        icmp_type = int(response[ICMP].type)
        icmp_code = int(response[ICMP].code)
        
        if icmp_type == 3:
            if icmp_code == 3: # Destination Port Unreachable
                log_silent("scans", "udp_scan", "UDP_CLOSED", port=port)
                cast_vote(port, "closed", weight=10)
            elif icmp_code in [1, 2, 9, 10, 13]: # Administratively prohibited / Filtered
                log_silent("scans", "udp_scan", f"UDP_FILTERED (ICMP Code {icmp_code})", port=port)
                cast_vote(port, "filtered", weight=5)

def process_inverse_response(response, port, scan_type):
    """NOISE ISOLATION: Inverse responses are recorded silently for info only; NO VOTES cast"""
    global detected_as_windows
    if response is None:
        log_silent("scans", scan_type, "OPEN|FILTERED", port=port)
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:
        if detected_as_windows:
            log_silent("scans", scan_type, "OPEN_RFC793_ANOMALY", port=port)
        else:
            log_silent("scans", scan_type, "CLOSED", port=port)

def fin_scan(target, port):
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="F")
    process_inverse_response(sr1(packet, timeout=timeout, verbose=0), port, "fin_scan")

def null_scan(target, port):
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="")
    process_inverse_response(sr1(packet, timeout=timeout, verbose=0), port, "null_scan")

def xmas_scan(target, port):
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="FPU")
    process_inverse_response(sr1(packet, timeout=timeout, verbose=0), port, "xmas_scan")

def ack_scan(target, port):
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="A")
    response = sr1(packet, timeout=timeout, verbose=0)
    if response is None:
        log_silent("scans", "ack_scan", "FILTERED", port=port)
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:
        log_silent("scans", "ack_scan", "UNFILTERED", port=port)

def window_scan(target, port):
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="A")
    response = sr1(packet, timeout=timeout, verbose=0)
    if response and response.haslayer(TCP) and response[TCP].flags == 0x14:
        if response[TCP].window > 0:
            log_silent("scans", "window_scan", "OPEN_INDICATION", port=port)
        else:
            log_silent("scans", "window_scan", "CLOSED_INDICATION", port=port)
    else:
        log_silent("scans", "window_scan", "FILTERED", port=port)

def maimon_scan(target, port):
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="FA")
    response = sr1(packet, timeout=timeout, verbose=0)
    if response is None:
        log_silent("scans", "maimon_scan", "OPEN|FILTERED", port=port)
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:
        log_silent("scans", "maimon_scan", "CLOSED", port=port)

def zombie_scan(target, zombie_ip, port):
    if not zombie_ip: return
    timeout = get_dynamic_timeout()
    try:
        p1 = sr1(IP(dst=zombie_ip)/TCP(flags="SA"), timeout=timeout, verbose=0)
        if not p1: return
        id1 = p1.id
        send(IP(src=zombie_ip, dst=target)/TCP(dport=port, flags="S"), verbose=0)
        p2 = sr1(IP(dst=zombie_ip)/TCP(flags="SA"), timeout=timeout, verbose=0)
        if not p2: return
        id2 = p2.id
        if id2 == id1 + 2:
            log_silent("scans", "zombie_scan", "OPEN_ZOMBIE", port=port)
        else:
            log_silent("scans", "zombie_scan", "CLOSED_ZOMBIE", port=port)
    except:
        pass

# ==============================================================================
# 2. HEURISTIC OS ESTIMATION ENGINE
# ==============================================================================

def service_and_os_detection(target, port=SSH_PORT):
    """REFINED KERNEL ESTIMATION & OS FINGERPRINTING MATRIX"""
    global detected_as_windows
    linux_score = 0
    windows_score = 0
    evidence = []

    pkt = sr1(
        IP(dst=target)/TCP(dport=port, flags="S"),
        timeout=DEFAULT_TIMEOUT,
        verbose=0
    )

    if pkt and pkt.haslayer(TCP):
        ttl = pkt.ttl
        window = pkt[TCP].window
        df_bit = int(pkt.flags) & 0x2 if hasattr(pkt.flags, 'DF') else 0
        
        # 1. TTL Analysis
        if 50 <= ttl <= 70:
            linux_score += 3
            evidence.append(f"TTL = {ttl} (Standard Linux range ~64)")
        elif 100 <= ttl <= 130:
            windows_score += 3
            evidence.append(f"TTL = {ttl} (Standard Windows range ~128)")
            
        # 2. TCP Window Size Correlation
        if window in [5840, 29200, 64240]:
            linux_score += 2
            evidence.append(f"TCP Window Size = {window} (Linux Match)")
        elif window in [8192, 65535]:
            windows_score += 2
            evidence.append(f"TCP Window Size = {window} (Windows Match)")
            
        # 3. Don't Fragment (DF) Bit
        if df_bit:
            linux_score += 1
            evidence.append("DF Flag set (Linux standard)")

        # 4. Application Banner Correlation
        for port_key, pdata in scan_results["port_scans"].items():
            banner = pdata.get("version", "")
            service = pdata.get("service", "")

            text = f"{banner} {service}".lower()

            if any(x in text for x in ["ubuntu", "debian", "linux", "openssh"]):
                linux_score += 4
                evidence.append(f"Banner Match: {banner}")
                break

            elif any(x in text for x in ["windows", "microsoft", "iis"]):
                windows_score += 4
                evidence.append(f"Banner Match: {banner}")
                break

        if windows_score > linux_score and windows_score >= 3:
            detected_as_windows = True
            total_score = min(windows_score, 10)
            os_name = "Microsoft Windows Server / Desktop"
        elif linux_score > windows_score and linux_score >= 3:
            total_score = min(linux_score, 10)
            os_name = "Linux 2.6.x (Kernel Range 2.6.9 - 2.6.33)"
        else:
            total_score = 4
            os_name = "Embedded System / Network Appliance"

        conf_pct = f"{total_score * 10}%"
    
        scan_results["os_fingerprint"] = {
            "detected_os": os_name,
            "confidence_score": total_score,
            "confidence_percentage": conf_pct,
            "evidence": evidence
        }
        return os_name

# ==============================================================================
# 3. APPLICATION LAYER MODULES
# ==============================================================================

def run_ssh_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "ssh_init", f"[*] Running SSH Banner Discovery at {target}:22", port=SSH_PORT)
    banner = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, SSH_PORT))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        scan_results["port_scans"]["22"]["version"] = banner
        log_and_print("enumeration", "ssh_banner", f"  [+] SSH Software Banner Stack: {banner}", port=SSH_PORT)
        s.close()
    except Exception as e:
        log_and_print("enumeration", "ssh_fault", f"  [-] SSH Connection lost or timed out: {e}", port=SSH_PORT)

def ftp_banner_grab(target):
    timeout = get_dynamic_timeout()
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((target, FTP_PORT))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner
    except: return None

def ftp_anonymous_check(target):
    timeout = get_dynamic_timeout()
    try:
        s = socket.socket()
        s.settimeout(timeout)
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
    except: pass
    log_and_print("enumeration", "ftp_anonymous", "  [-] Anonymous login rejected by daemon.", port=FTP_PORT)
    return False

def ftp_bounce_check(target):
    timeout = get_dynamic_timeout()
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((target, FTP_PORT)); s.recv(1024)
        s.send(b"USER anonymous\r\n"); s.recv(1024); s.send(b"PASS anonymous@target.com\r\n"); s.recv(1024)
        s.send(b"PORT 127,0,0,1,0,80\r\n")
        res = s.recv(1024).decode('utf-8')
        s.close()
        if res.startswith("200"):
            log_and_print("enumeration", "ftp_bounce", "  [INFO] Daemon accepted PORT payload formatting syntax", port=FTP_PORT)
        else:
            log_and_print("enumeration", "ftp_bounce", f"  [-] Target daemon blocked internal tracking instruction: {res.strip()}", port=FTP_PORT)
    except: pass

def send_http_raw_request(target, port, path="/", method="GET", extra_headers=None, use_ssl=False):
    if extra_headers is None:
        extra_headers = {}
    timeout = get_dynamic_timeout()
    
    req_lines = [f"{method} {path} HTTP/1.1", f"Host: {target}", "User-Agent: SecurityAuditorEngine/2.0", "Connection: close"]
    for k, v in extra_headers.items():
        req_lines.append(f"{k}: {v}")
    req_bytes = ("\r\n".join(req_lines) + "\r\n\r\n").encode("utf-8")
    
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            s = context.wrap_socket(raw_sock, server_hostname=target)
        else:
            s = raw_sock
            
        s.connect((target, port))
        s.sendall(req_bytes)
        
        response_bytes = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            response_bytes += chunk
        s.close()
        
        response_str = response_bytes.decode('utf-8', errors='ignore')
        parts = response_str.split("\r\n\r\n", 1)
        header_part = parts[0]
        body_part = parts[1] if len(parts) > 1 else ""
        
        headers_dict = {}
        status_line = ""
        lines = header_part.split("\r\n")
        if lines:
            status_line = lines[0]
            for l in lines[1:]:
                if ":" in l:
                    hk, hv = l.split(":", 1)
                    headers_dict[hk.strip().lower()] = hv.strip()
                    
        return status_line, headers_dict, body_part
    except Exception:
        return "", {}, ""

def http_get_details(target, port=HTTP_PORT, use_ssl=False):
    status_line, headers, body = send_http_raw_request(target, port, "/", use_ssl=use_ssl)
    server = headers.get("server", "Unknown Headers")
    scan_results["port_scans"][str(port)]["version"] = server
    log_and_print("enumeration", "http_server", f"  [+] HTTP Server Header Information field: {server}", port=port)
    
    title = "No Title Found"
    title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
    if title_match:
        title = title_match.group(1).strip()
    log_and_print("enumeration", "http_title", f"    [+] HTTP Webpage Title: {title}", port=port)

def http_methods_check(target, port=HTTP_PORT, use_ssl=False):
    status_line, headers, _ = send_http_raw_request(target, port, "/", method="OPTIONS", use_ssl=use_ssl)
    allow_methods = headers.get("allow") or headers.get("public")
    if allow_methods:
        log_and_print("enumeration", "http_methods", f"    [+] Exposed Server Options Directives: {allow_methods}", port=port)

def http_security_headers_audit(target, port=HTTP_PORT, use_ssl=False):
    status_line, headers, _ = send_http_raw_request(target, port, "/", use_ssl=use_ssl)
    sec_headers = {
        "strict-transport-security": "HSTS (Strict-Transport-Security)",
        "content-security-policy": "Content-Security-Policy (CSP)",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "x-xss-protection": "X-XSS-Protection",
        "referrer-policy": "Referrer-Policy"
    }
    
    log_and_print("enumeration", "sec_headers_init", f"    [*] Auditing HTTP Security Headers for Port {port}...", port=port)
    found_count = 0
    for h_key, h_desc in sec_headers.items():
        if h_key in headers:
            log_and_print("enumeration", f"sec_hdr_{h_key.replace('-', '_')}", f"      [+] [HEADER PRESENT] {h_desc}: {headers[h_key]}", port=port)
            found_count += 1
        else:
            log_silent("enumeration", f"sec_hdr_missing_{h_key.replace('-', '_')}", f"MISSING: {h_desc}", port=port)
    
    if found_count == 0:
        log_and_print("enumeration", "sec_headers_summary", f"      [-] Warning: No standard HTTP security headers detected on port {port}.", port=port)

def run_smtp_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "smtp_init", f"[*] Launching Structured SMTP Verification on target {target}:{port}", port=port)
    try:
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM); plain_socket.settimeout(timeout)
        s = ssl.create_default_context().wrap_socket(plain_socket, server_hostname=target) if port == 465 else plain_socket
        s.connect((target, port)); banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        scan_results["port_scans"][str(port)]["version"] = banner
        log_and_print("enumeration", "smtp_banner", f"  [+] SMTP Core Service Banner: {banner}", port=port)
        
        s.send(b"EHLO metasploitable.localdomain\r\n")
        ehlo_response = s.recv(2048).decode('utf-8', errors='ignore').strip()
        capabilities = []
        for line in ehlo_response.split("\n"):
            if line.startswith("250-") or line.startswith("250 "):
                capabilities.append(line[4:].strip())
        if capabilities:
            caps_str = ", ".join(capabilities)
            log_and_print("enumeration", "smtp_ehlo", f"    [+] SMTP Supported Capabilities (EHLO): {caps_str}", port=port)
            
        s.close()
    except Exception as e: log_and_print("enumeration", "smtp_connect_error", f"  [-] SMTP Validation anomaly: {e}", port=port)

def run_dns_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "dns_init", f"[*] Running DNS Boundary verification on {target}:{DNS_PORT}", port=DNS_PORT)
    version_detected = "Active Responding DNS Structure"
    try:
        dns_req = IP(dst=target)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname="version.bind", qclass=3, qtype=16))
        dns_resp = sr1(dns_req, timeout=timeout, verbose=0)
        
        if dns_resp and dns_resp.haslayer(DNS) and dns_resp[DNS].ancount > 0:
            rdata = dns_resp[DNS].an[0].rdata
            if rdata:
                if isinstance(rdata, list):
                    version_detected = b" ".join(rdata).decode('utf-8', errors='ignore')
                else:
                    version_detected = rdata.decode('utf-8', errors='ignore')
                
        scan_results["port_scans"]["53"]["version"] = version_detected
        log_and_print("enumeration", "dns_status", f"  [+] DNS Software Version (Chaos Query): {version_detected}", port=DNS_PORT)
    except Exception: 
        scan_results["port_scans"]["53"]["version"] = version_detected
        log_and_print("enumeration", "dns_fault", f"  [-] DNS query fallback active. Port 53 open but Chaos Query rejected.", port=DNS_PORT)

def run_imap_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "imap_init", f"[*] Launching Target Verification on IMAP Endpoint {target}:{port}", port=port)
    try:
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM); plain_socket.settimeout(timeout)
        s = ssl.create_default_context().wrap_socket(plain_socket, server_hostname=target) if port == 993 else plain_socket
        s.connect((target, port)); banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        scan_results["port_scans"][str(port)]["version"] = banner
        log_and_print("enumeration", "imap_banner", f"  [+] IMAP Clean Service Banner: {banner}", port=port); s.close()
    except: pass

# ==============================================================================
# 4. UNIFIED SUMMARY REPORT GENERATOR
# ==============================================================================

def generate_reports():
    print("\n[*] Exporting structured session summaries to operational storage...")
    base_filename = "report_data"
    
    with open(f"{base_filename}.txt", "w") as f:
        f.write("============================================================\n")
        f.write("            CONSOLIDATED AUTHORITATIVE PORT REPORT            \n")
        f.write("============================================================\n")
        f.write(f"Target host IP address: {scan_results['target_ip']}\n")
        f.write(f"OS Fingerprint Baseline: {scan_results['os_fingerprint']}\n\n")
        for port, data in scan_results["port_scans"].items():
            f.write(f"\n[Port Element {port} - Service: {data['service']}]\n")
            f.write(f"  -> Service Software Version: {data['version']}\n")
            f.write("  -> Layer Scans Executed:\n")
            for sk, sv in data["scans"].items(): f.write(f"    {sk}: {sv}\n")
            f.write("  -> Enumeration Script Output:\n")
            for ek, ev in data["enumeration"].items(): f.write(f"    {ek}: {ev}\n")
    print(f"  [+] Saved Text Report to: {base_filename}.txt")

    with open(f"{base_filename}.json", "w") as f: json.dump(scan_results, f, indent=4)
    print(f"  [+] Saved JSON Report to: {base_filename}.json")

    root = ET.Element("ComprehensiveAuditReport", target=scan_results["target_ip"])
    ET.SubElement(root, "OperatingSystemEstimation").text = str(scan_results["os_fingerprint"])
    ports_node = ET.SubElement(root, "TargetInfrastructurePorts")
    for port, data in scan_results["port_scans"].items():
        p_node = ET.SubElement(ports_node, "PortRecord", ID=port, Profile=data["service"], SoftwareVersion=data["version"])
        s_node = ET.SubElement(p_node, "ProbingMatrices")
        for sk, sv in data["scans"].items(): ET.SubElement(s_node, sk).text = sv
        e_node = ET.SubElement(p_node, "EnumerationScripts")
        for ek, ev in data["enumeration"].items(): ET.SubElement(e_node, ek).text = ev
    ET.ElementTree(root).write(f"{base_filename}.xml", encoding="utf-8", xml_declaration=True)
    print(f"  [+] Saved XML Report to: {base_filename}.xml")

# ==============================================================================
# MASTER EXECUTION GATEWAY
# ==============================================================================

if __name__ == "__main__":
    if sys.platform != "win32":
        import os
        if os.geteuid() != 0: sys.exit("[!] CRITICAL: Script requires root privileges.")

    target_ip = input("[?] Enter Target IP Address to scan: ").strip()
    if not target_ip: sys.exit("[!] Input error: Target IP context null.")
    scan_results["target_ip"] = target_ip
        
    zombie_input = input("[?] Enter Zombie Host IP for Idle Scan (Press Enter to Skip): ").strip()
    if zombie_input: scan_results["zombie_ip"] = zombie_input

    all_ports = [FTP_PORT, SSH_PORT, DNS_PORT, HTTP_PORT, HTTPS_PORT] + SMTP_PORTS + IMAP_PORTS

    # Step 1: Initial Discovery Verification & RTT Calculation
    ping_scan(target_ip)
    
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
            
    # Step 3: Compute Authority Decisions
    for p in all_ports:
        port_authoritative_states[p] = final_consensus_decision(p)

    # Step 4: Consolidated Table Output View
    print("\n" + "="*35)
    print(f" PORT      STATE       SERVICE")
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
        if ftp_banner: scan_results["port_scans"]["21"]["version"] = ftp_banner
        ftp_anonymous_check(target_ip)
        ftp_bounce_check(target_ip)
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
        log_and_print("enumeration", "http_init", f"[*] Executing Deep HTTP Fingerprinting on {target_ip}:{HTTP_PORT}", port=HTTP_PORT)
        http_get_details(target_ip, port=HTTP_PORT, use_ssl=False)
        http_methods_check(target_ip, port=HTTP_PORT, use_ssl=False)
        http_security_headers_audit(target_ip, port=HTTP_PORT, use_ssl=False)
    else:
        print(f"  [-] Skipping HTTP Enumeration: Port {HTTP_PORT} is strictly {port_authoritative_states[HTTP_PORT]}.")

    if port_authoritative_states[HTTPS_PORT] == "OPEN":
        log_and_print("enumeration", "https_init", f"[*] Executing Deep HTTPS Fingerprinting on {target_ip}:{HTTPS_PORT}", port=HTTPS_PORT)
        http_get_details(target_ip, port=HTTPS_PORT, use_ssl=True)
        http_methods_check(target_ip, port=HTTPS_PORT, use_ssl=True)
        http_security_headers_audit(target_ip, port=HTTPS_PORT, use_ssl=True)
    else:
        print(f"  [-] Skipping HTTPS Enumeration: Port {HTTPS_PORT} is strictly {port_authoritative_states[HTTPS_PORT]}.")
    
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
            
    # Step 6: OS Fingerprinting
    service_and_os_detection(target_ip, SSH_PORT)

    # Step 7: Export Reports
    generate_reports()
