import socket
import sys
import json
import xml.etree.ElementTree as ET
import logging
import ssl
import re
import time
import struct
from urllib.parse import urlparse

# Suppress Scapy IPv6/runtime warnings on startup
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, UDP, sr1, send, ICMP, DNS, DNSQR, RandShort, Raw

# Configuration Constants & Baseline Dynamic RTT Tracking
FTP_PORT = 21
TELNET_PORT = 23
SSH_PORT = 22
DNS_PORT = 53
KERBEROS_PORT = 88
HTTP_PORT = 80
HTTPS_PORT = 443
SMB_PORT = 445
RDP_PORT = 3389
ORACLE_PORT = 1521
MYSQL_PORT = 3306
POSTGRES_PORT = 5432
REDIS_PORT = 6379
MONGODB_PORT = 27017
SMTP_PORTS = [25, 465, 587]
IMAP_PORTS = [143, 993]
POP3_PORTS = [110, 995]                # NEW: POP3 & POP3S
LDAP_PORTS = [389, 636]                # NEW: LDAP & LDAPS
DHCP_PORTS = [67, 68]                  # NEW: DHCP Server/Client
HTTPS_ALT_PORTS = [8443, 9443]          # Common alternate HTTPS management/app ports
FTPS_IMPLICIT_DATA_PORT = 989           # Implicit FTPS - Data channel
FTPS_IMPLICIT_CTRL_PORT = 990           # Implicit FTPS - Control channel (TLS from connect)
FTPS_PORTS = [FTPS_IMPLICIT_DATA_PORT, FTPS_IMPLICIT_CTRL_PORT]

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
        "21": {"service": "FTP/FTPS", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "22": {"service": "SSH", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "53": {"service": "DNS", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "88": {"service": "Kerberos", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "80": {"service": "HTTP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "443": {"service": "HTTPS", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "445": {"service": "SMB", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "3389": {"service": "RDP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "1521": {"service": "Oracle TNS Listener", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "3306": {"service": "MySQL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5432": {"service": "PostgreSQL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "6379": {"service": "Redis", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "27017": {"service": "MongoDB", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "25": {"service": "SMTP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "465": {"service": "SMTP-SSL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "587": {"service": "SMTP-Submission", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "143": {"service": "IMAP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "993": {"service": "IMAP-SSL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "110": {"service": "POP3", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "995": {"service": "POP3-SSL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "389": {"service": "LDAP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "636": {"service": "LDAP-SSL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "67": {"service": "DHCP-Server", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "68": {"service": "DHCP-Client", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "23": {"service": "Telnet", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "989": {"service": "FTPS (Implicit-Data)", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "990": {"service": "FTPS (Implicit-Control)", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "8443": {"service": "HTTPS-Alt", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "9443": {"service": "HTTPS-Alt", "version": "Not Evaluated", "scans": {}, "enumeration": {}}
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
    """Returns specific UDP payload probes according to target port context."""
    probes = {
        53:  DNS(rd=1, qd=DNSQR(qname="version.bind", qclass=3, qtype=16)), # DNS Chaos Query
        67:  Raw(b'\x01\x01\x06\x00' + b'\x00' * 232),                     # DHCP Discover
        68:  Raw(b'\x01\x01\x06\x00' + b'\x00' * 232),                     # DHCP Response Probe
        69:  Raw(b'\x00\x01\x74\x65\x73\x74\x00\x6f\x63\x74\x65\x74\x00'),   # TFTP Read Request
        88:  Raw(b'\x6e\x81\x00\x00'),                                     # Kerberos UDP Probe
        123: Raw(b'\x1b' + b'\x00' * 47),                                  # NTP Client Request (v3/v4)
        137: Raw(b'\x80\x90\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41'
                 b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'
                 b'\x41\x41\x41\x00\x00\x21\x00\x01'),                      # NetBIOS Name Query
        161: Raw(b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02'
                 b'\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06'
                 b'\x05\x2b\x06\x01\x02\x01\x05\x00'),                     # SNMP v2c Get-Next Query
        500: Raw(b'\x00' * 28)                                             # ISAKMP / VPN Security Association
    }
    return probes.get(port, Raw(b''))

def udp_scan(target, port):
    timeout = get_dynamic_timeout()
    probe_payload = get_udp_service_probe(port)
    
    packet = IP(dst=target)/UDP(sport=RandShort(), dport=port)/probe_payload
    response = sr1(packet, timeout=timeout, verbose=0)
    
    if response is None:
        log_silent("scans", "udp_scan", "OPEN|FILTERED", port=port)
        cast_vote(port, "filtered", weight=1)
    elif response.haslayer(UDP):
        log_silent("scans", "udp_scan", "UDP_OPEN", port=port)
        cast_vote(port, "open", weight=10)
    elif response.haslayer(ICMP):
        icmp_type = int(response[ICMP].type)
        icmp_code = int(response[ICMP].code)
        
        if icmp_type == 3:
            if icmp_code == 3:
                log_silent("scans", "udp_scan", "UDP_CLOSED", port=port)
                cast_vote(port, "closed", weight=10)
            elif icmp_code in [1, 2, 9, 10, 13]:
                log_silent("scans", "udp_scan", f"UDP_FILTERED (ICMP Code {icmp_code})", port=port)
                cast_vote(port, "filtered", weight=5)

def process_inverse_response(response, port, scan_type):
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
        
        if 50 <= ttl <= 70:
            linux_score += 3
            evidence.append(f"TTL = {ttl} (Standard Linux range ~64)")
        elif 100 <= ttl <= 130:
            windows_score += 3
            evidence.append(f"TTL = {ttl} (Standard Windows range ~128)")
            
        if window in [5840, 29200, 64240]:
            linux_score += 2
            evidence.append(f"TCP Window Size = {window} (Linux Match)")
        elif window in [8192, 65535]:
            windows_score += 2
            evidence.append(f"TCP Window Size = {window} (Windows Match)")
            
        if df_bit:
            linux_score += 1
            evidence.append("DF Flag set (Linux standard)")

        for port_key, pdata in scan_results["port_scans"].items():
            banner = pdata.get("version", "")
            service = pdata.get("service", "")
            text = f"{banner} {service}".lower()

            if any(x in text for x in ["ubuntu", "debian", "linux", "openssh"]):
                linux_score += 4
                evidence.append(f"Banner Match: {banner}")
                break
            elif any(x in text for x in ["windows", "microsoft", "iis", "smb", "kerberos"]):
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

# NEW: POP3 Audit Module
def run_pop3_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "pop3_init", f"[*] Launching POP3 Verification on {target}:{port}", port=port)
    try:
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        plain_socket.settimeout(timeout)
        s = ssl.create_default_context().wrap_socket(plain_socket, server_hostname=target) if port == 995 else plain_socket
        s.connect((target, port))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        scan_results["port_scans"][str(port)]["version"] = banner
        log_and_print("enumeration", "pop3_banner", f"  [+] POP3 Banner: {banner}", port=port)
        s.close()
    except Exception as e:
        log_and_print("enumeration", "pop3_fault", f"  [-] POP3 Connection error: {e}", port=port)

# NEW: LDAP Audit Module
def run_ldap_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "ldap_init", f"[*] Auditing LDAP Service on {target}:{port}", port=port)
    try:
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        plain_socket.settimeout(timeout)
        s = ssl.create_default_context().wrap_socket(plain_socket, server_hostname=target) if port == 636 else plain_socket
        s.connect((target, port))
        
        # LDAP Anonymous Bind Request (BER Encoded)
        ldap_bind_req = b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
        s.sendall(ldap_bind_req)
        resp = s.recv(1024)
        s.close()

        if resp and len(resp) > 5 and resp[0] == 0x30:
            scan_results["port_scans"][str(port)]["version"] = "Active LDAP Service (BER Response)"
            log_and_print("enumeration", "ldap_status", "  [+] LDAP Service active and responded to bind query", port=port)
        else:
            scan_results["port_scans"][str(port)]["version"] = "LDAP Service Open"
            log_and_print("enumeration", "ldap_status", "  [+] Port open (non-standard LDAP probe result)", port=port)
    except Exception as e:
        log_and_print("enumeration", "ldap_fault", f"  [-] LDAP Handshake Error: {e}", port=port)

# NEW: DHCP Audit Module
def run_dhcp_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "dhcp_init", f"[*] Auditing DHCP Endpoint on {target}:{port}", port=port)
    try:
        dhcp_discover = (
            IP(dst=target)/UDP(sport=68, dport=port)/
            Raw(b'\x01\x01\x06\x00' + b'\x00' * 232)
        )
        resp = sr1(dhcp_discover, timeout=timeout, verbose=0)
        if resp:
            scan_results["port_scans"][str(port)]["version"] = "Active DHCP Server/Relay"
            log_and_print("enumeration", "dhcp_status", "  [+] DHCP Service replied to Discovery probe", port=port)
        else:
            scan_results["port_scans"][str(port)]["version"] = "DHCP Port Active (No reply)"
            log_and_print("enumeration", "dhcp_status", "  [+] DHCP Port active (no direct response to unicast discover)", port=port)
    except Exception as e:
        log_and_print("enumeration", "dhcp_fault", f"  [-] DHCP Probe Anomaly: {e}", port=port)

def run_ssh_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "ssh_init", f"[*] Running SSH Banner Discovery at {target}:22", port=SSH_PORT)
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

def run_ftps_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "ftps_init", f"[*] Auditing FTPS / FTP Explicit TLS capabilities on {target}:{FTP_PORT}", port=FTP_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, FTP_PORT))
        s.recv(1024)
        s.sendall(b"AUTH TLS\r\n")
        resp = s.recv(1024).decode('utf-8', errors='ignore')
        if "234" in resp:
            log_and_print("enumeration", "ftps_auth_tls", "  [+] FTPS Explicit TLS supported (AUTH TLS Response 234)", port=FTP_PORT)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(s, server_hostname=target) as tls_sock:
                cipher = tls_sock.cipher()
                ver = tls_sock.version()
                log_and_print("enumeration", "ftps_tls_info", f"    [+] TLS Version: {ver} | Cipher: {cipher[0]}", port=FTP_PORT)
                scan_results["port_scans"]["21"]["version"] += f" (FTPS Enabled - {ver})"
        else:
            log_and_print("enumeration", "ftps_auth_tls", "  [-] Explicit FTPS (AUTH TLS) not supported.", port=FTP_PORT)
            s.close()
    except Exception as e:
        log_and_print("enumeration", "ftps_fault", f"  [-] FTPS Audit Exception: {e}", port=FTP_PORT)

def run_ftps_implicit_audit(target, port):
    """Audits Implicit FTPS (TLS is negotiated immediately on connect, no AUTH TLS handshake)."""
    timeout = get_dynamic_timeout()
    channel_label = "Control Channel" if port == FTPS_IMPLICIT_CTRL_PORT else "Data Channel"
    log_and_print("enumeration", "ftps_implicit_init", f"[*] Auditing Implicit FTPS {channel_label} on {target}:{port}", port=port)
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(raw_sock, server_hostname=target) as tls_sock:
            tls_sock.connect((target, port))
            ver = tls_sock.version()
            cipher = tls_sock.cipher()
            log_and_print("enumeration", "ftps_implicit_tls_info", f"  [+] Implicit TLS negotiated immediately on connect | Version: {ver} | Cipher: {cipher[0] if cipher else 'Unknown'}", port=port)
            scan_results["port_scans"][str(port)]["version"] = f"FTPS Implicit {channel_label} ({ver})"

            if port == FTPS_IMPLICIT_CTRL_PORT:
                try:
                    banner = tls_sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        log_and_print("enumeration", "ftps_implicit_banner", f"    [+] Post-TLS Control Banner: {banner}", port=port)
                except Exception:
                    pass
    except ssl.SSLError as e:
        log_and_print("enumeration", "ftps_implicit_fault", f"  [-] TLS handshake failed on implicit FTPS {channel_label}: {e}", port=port)
        scan_results["port_scans"][str(port)]["version"] = "TLS Handshake Failed (Not True Implicit FTPS)"
    except Exception as e:
        log_and_print("enumeration", "ftps_implicit_fault", f"  [-] Implicit FTPS Audit Exception ({channel_label}): {e}", port=port)

def run_telnet_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "telnet_init", f"[*] Auditing Telnet Service & IAC Option Negotiation on {target}:{TELNET_PORT}", port=TELNET_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, TELNET_PORT))
        data = s.recv(1024)

        iac_opts = []
        IAC, WILL, WONT, DO, DONT = 255, 251, 252, 253, 254
        OPTION_NAMES = {1: "ECHO", 3: "SUPPRESS-GO-AHEAD", 24: "TERMINAL-TYPE", 31: "WINDOW-SIZE", 32: "TERMINAL-SPEED", 39: "NEW-ENVIRON"}
        cmd_names = {WILL: "WILL", WONT: "WONT", DO: "DO", DONT: "DONT"}
        i = 0
        while i < len(data) - 2:
            if data[i] == IAC and data[i + 1] in cmd_names:
                opt_id = data[i + 2]
                opt_name = OPTION_NAMES.get(opt_id, f"OPT-{opt_id}")
                iac_opts.append(f"{cmd_names[data[i + 1]]} {opt_name}")
                i += 3
            else:
                i += 1

        if iac_opts:
            log_and_print("enumeration", "telnet_iac_negotiation", f"  [+] IAC Option Negotiation observed: {', '.join(iac_opts)}", port=TELNET_PORT)

        printable = re.sub(rb'\xff[\xfb-\xfe].', b'', data).decode('utf-8', errors='ignore').strip()
        banner = printable if printable else "Banner not printable / IAC-only response"
        scan_results["port_scans"]["23"]["version"] = banner
        log_and_print("enumeration", "telnet_banner", f"  [+] Telnet Login Banner/Prompt: {banner}", port=TELNET_PORT)
        log_and_print("enumeration", "telnet_cleartext_warning", "  [VULN] Telnet transmits all credentials and session data in cleartext (unencrypted)", port=TELNET_PORT)
        s.close()
    except Exception as e:
        log_and_print("enumeration", "telnet_fault", f"  [-] Telnet Connection lost or timed out: {e}", port=TELNET_PORT)

def run_smb_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "smb_init", f"[*] Auditing SMB Service & Dialect Negotiations on {target}:{SMB_PORT}", port=SMB_PORT)
    
    smb_header = (
        b"\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    dialects = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
    word_count = b"\x00"
    byte_count = struct.pack("<H", len(dialects))
    payload = smb_header + word_count + byte_count + dialects
    netbios_header = struct.pack("!xL", len(payload))
    packet = netbios_header + payload

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, SMB_PORT))
        s.sendall(packet)
        response = s.recv(1024)
        s.close()

        if response and len(response) > 4:
            if b"\xffSMB" in response:
                log_and_print("enumeration", "smb_dialect", "  [VULN] SMBv1 Protocol Dialect Accepted (Legacy/Vulnerable)", port=SMB_PORT)
                scan_results["port_scans"]["445"]["version"] = "SMBv1 Active (Potentially Legacy)"
            elif b"\xfeSMB" in response:
                log_and_print("enumeration", "smb_dialect", "  [+] SMBv2/v3 Protocol Dialect Negotiated", port=SMB_PORT)
                scan_results["port_scans"]["445"]["version"] = "SMBv2/v3 Active"
            else:
                log_and_print("enumeration", "smb_response", "  [+] SMB Port open and responding", port=SMB_PORT)
                scan_results["port_scans"]["445"]["version"] = "SMB Active"
    except Exception as e:
        log_and_print("enumeration", "smb_fault", f"  [-] SMB Connection Error: {e}", port=SMB_PORT)

def run_mysql_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "mysql_init", f"[*] Auditing MySQL Database Protocol Handshake on {target}:{MYSQL_PORT}", port=MYSQL_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, MYSQL_PORT))
        data = s.recv(1024)
        s.close()

        if len(data) >= 5:
            proto_ver = data[4]
            if proto_ver == 10:
                null_idx = data.find(b'\x00', 5)
                server_ver = data[5:null_idx].decode('utf-8', errors='ignore')
                scan_results["port_scans"]["3306"]["version"] = f"MySQL/MariaDB v{server_ver}"
                log_and_print("enumeration", "mysql_version", f"  [+] MySQL Protocol v10 Detected | Version: {server_ver}", port=MYSQL_PORT)
            else:
                log_and_print("enumeration", "mysql_proto", f"  [+] Non-standard MySQL Protocol Version: {proto_ver}", port=MYSQL_PORT)
    except Exception as e:
        log_and_print("enumeration", "mysql_fault", f"  [-] MySQL Handshake Error: {e}", port=MYSQL_PORT)

def run_postgres_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "postgres_init", f"[*] Auditing PostgreSQL Service SSL/Handshake on {target}:{POSTGRES_PORT}", port=POSTGRES_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, POSTGRES_PORT))
        
        ssl_request = struct.pack("!II", 8, 80877103)
        s.sendall(ssl_request)
        response = s.recv(1)
        s.close()

        if response == b'S':
            log_and_print("enumeration", "postgres_ssl", "  [+] PostgreSQL SSL Encryption Supported", port=POSTGRES_PORT)
            scan_results["port_scans"]["5432"]["version"] = "PostgreSQL Server (SSL Enabled)"
        elif response == b'N':
            log_and_print("enumeration", "postgres_ssl", "  [-] PostgreSQL SSL Encryption Disabled", port=POSTGRES_PORT)
            scan_results["port_scans"]["5432"]["version"] = "PostgreSQL Server (SSL Disabled)"
        else:
            scan_results["port_scans"]["5432"]["version"] = "PostgreSQL Server Active"
    except Exception as e:
        log_and_print("enumeration", "postgres_fault", f"  [-] PostgreSQL Handshake Error: {e}", port=POSTGRES_PORT)

def run_redis_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "redis_init", f"[*] Auditing Redis Key-Value Store on {target}:{REDIS_PORT}", port=REDIS_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, REDIS_PORT))
        s.sendall(b"INFO\r\n")
        data = s.recv(4096).decode('utf-8', errors='ignore')
        s.close()

        if "redis_version" in data:
            ver_match = re.search(r"redis_version:(.*?\r\n)", data)
            version = ver_match.group(1).strip() if ver_match else "Unknown"
            scan_results["port_scans"]["6379"]["version"] = f"Redis Server v{version} (Unauthenticated)"
            log_and_print("enumeration", "redis_info", f"  [VULN] Redis Server Responded without Authentication | Version: {version}", port=REDIS_PORT)
        elif "NOAUTH" in data or "WRONGPASS" in data:
            scan_results["port_scans"]["6379"]["version"] = "Redis Server (Auth Required)"
            log_and_print("enumeration", "redis_auth", "  [+] Redis Server Active (Password Protected)", port=REDIS_PORT)
        else:
            scan_results["port_scans"]["6379"]["version"] = "Redis Server Active"
            log_and_print("enumeration", "redis_status", "  [+] Redis Service Responding", port=REDIS_PORT)
    except Exception as e:
        log_and_print("enumeration", "redis_fault", f"  [-] Redis Handshake Error: {e}", port=REDIS_PORT)

def run_kerberos_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "kerberos_init", f"[*] Auditing Kerberos Key Distribution Center (KDC) on {target}:{KERBEROS_PORT}", port=KERBEROS_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, KERBEROS_PORT))
        dummy_req = b"\x00\x00\x00\x04\x6e\x81\x00\x00"
        s.sendall(dummy_req)
        resp = s.recv(1024)
        s.close()

        if resp:
            scan_results["port_scans"]["88"]["version"] = "Kerberos KDC (v5)"
            log_and_print("enumeration", "kerberos_status", "  [+] Kerberos v5 KDC Active and responding to probes", port=KERBEROS_PORT)
        else:
            scan_results["port_scans"]["88"]["version"] = "Kerberos Service Active"
    except Exception as e:
        log_and_print("enumeration", "kerberos_fault", f"  [-] Kerberos Connection Anomaly: {e}", port=KERBEROS_PORT)

def run_oracle_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "oracle_init", f"[*] Auditing Oracle TNS Listener on {target}:{ORACLE_PORT}", port=ORACLE_PORT)
    
    tns_connect = (
        b"\x00\x3a\x00\x00\x01\x00\x00\x00\x01\x36\x01\x2c\x00\x00\x08\x00"
        b"\x7f\xff\x01\x00\x00\x00\x00\x20\x00\x3a\x00\x01\x20\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"(CONNECT_DATA=(COMMAND=version))"
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, ORACLE_PORT))
        s.sendall(tns_connect)
        data = s.recv(2048).decode('utf-8', errors='ignore')
        s.close()

        if "VSNNUM" in data or "TNSLSNR" in data:
            scan_results["port_scans"]["1521"]["version"] = "Oracle TNS Listener Active"
            log_and_print("enumeration", "oracle_tns", "  [+] Oracle TNS Listener Active (Version Data Extracted)", port=ORACLE_PORT)
        else:
            scan_results["port_scans"]["1521"]["version"] = "Oracle Database Service"
            log_and_print("enumeration", "oracle_status", "  [+] Oracle Service Port responding", port=ORACLE_PORT)
    except Exception as e:
        log_and_print("enumeration", "oracle_fault", f"  [-] Oracle TNS Probe Error: {e}", port=ORACLE_PORT)

def run_mongodb_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "mongodb_init", f"[*] Auditing MongoDB Instance on {target}:{MONGODB_PORT}", port=MONGODB_PORT)
    
    is_master_msg = (
        b"\x3d\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\xd4\x07\x00\x00"
        b"\x00\x00\x00\x00"
        b"admin.$cmd\x00"
        b"\x00\x00\x00\x00"
        b"\xff\xff\xff\xff"
        b"\x13\x00\x00\x00"
        b"\x10ismaster\x00\x01\x00\x00\x00\x00"
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, MONGODB_PORT))
        s.sendall(is_master_msg)
        resp = s.recv(1024)
        s.close()

        if len(resp) > 20 and b"ismaster" in resp or b"ok" in resp:
            scan_results["port_scans"]["27017"]["version"] = "MongoDB Engine (Unauthenticated Wire Protocol)"
            log_and_print("enumeration", "mongodb_info", "  [VULN] MongoDB responding to raw IsMaster wire commands", port=MONGODB_PORT)
        else:
            scan_results["port_scans"]["27017"]["version"] = "MongoDB Service Active"
            log_and_print("enumeration", "mongodb_status", "  [+] MongoDB Database Listener Active", port=MONGODB_PORT)
    except Exception as e:
        log_and_print("enumeration", "mongodb_fault", f"  [-] MongoDB Protocol Handshake Error: {e}", port=MONGODB_PORT)

def send_http_raw_request(target, port, path="/", method="GET", extra_headers=None, use_ssl=False):
    if extra_headers is None: extra_headers = {}
    timeout = get_dynamic_timeout()
    req_lines = [f"{method} {path} HTTP/1.1", f"Host: {target}", "User-Agent: SecurityAuditorEngine/2.0", "Connection: close"]
    for k, v in extra_headers.items(): req_lines.append(f"{k}: {v}")
    req_bytes = ("\r\n".join(req_lines) + "\r\n\r\n").encode("utf-8")
    
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            s = context.wrap_socket(raw_sock, server_hostname=target)
        else: s = raw_sock
            
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
        lines = header_part.split("\r\n")
        if lines:
            status_line = lines[0]
            for l in lines[1:]:
                if ":" in l:
                    hk, hv = l.split(":", 1)
                    headers_dict[hk.strip().lower()] = hv.strip()
        return status_line, headers_dict, body_part
    except Exception: return "", {}, ""

def http_get_details(target, port=HTTP_PORT, use_ssl=False):
    status_line, headers, body = send_http_raw_request(target, port, "/", use_ssl=use_ssl)
    server = headers.get("server", "Unknown Headers")
    scan_results["port_scans"][str(port)]["version"] = server
    log_and_print("enumeration", "http_server", f"  [+] HTTP Server Header Information field: {server}", port=port)
    
    title = "No Title Found"
    title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
    if title_match: title = title_match.group(1).strip()
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
                version_detected = rdata.decode('utf-8', errors='ignore') if not isinstance(rdata, list) else b" ".join(rdata).decode('utf-8', errors='ignore')
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
# 3B. RDP (REMOTE DESKTOP PROTOCOL) DEEP ENUMERATION MODULE
# ==============================================================================

RDP_NEG_REQ     = 0x01
RDP_NEG_RSP     = 0x02
RDP_NEG_FAILURE = 0x03

PROTOCOL_RDP       = 0x00000000
PROTOCOL_SSL       = 0x00000001
PROTOCOL_HYBRID    = 0x00000002
PROTOCOL_HYBRID_EX = 0x00000008

RDP_FAILURE_CODES = {
    1: "SSL_REQUIRED_BY_SERVER",
    2: "SSL_NOT_ALLOWED_BY_SERVER",
    3: "SSL_CERT_NOT_ON_SERVER",
    4: "INCONSISTENT_FLAGS",
    5: "HYBRID_REQUIRED_BY_SERVER",
    6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"
}

RDP_ENCRYPTION_METHODS = {0: "None", 1: "40-bit RC4", 2: "128-bit RC4", 8: "56-bit RC4", 0x10: "FIPS 140-1"}
RDP_ENCRYPTION_LEVELS  = {0: "None", 1: "Low", 2: "Client Compatible", 3: "High", 4: "FIPS Compliant"}

NTLM_BUILD_MAP = {
    2600: "Windows XP", 3790: "Windows Server 2003", 6000: "Windows Vista",
    6001: "Windows Vista SP1 / Server 2008", 7600: "Windows 7 / Server 2008 R2",
    7601: "Windows 7 SP1 / Server 2008 R2 SP1", 9200: "Windows 8 / Server 2012",
    9600: "Windows 8.1 / Server 2012 R2", 14393: "Windows 10 1607 / Server 2016",
    15063: "Windows 10 1703", 16299: "Windows 10 1709", 17134: "Windows 10 1803",
    17763: "Windows 10 1809 / Server 2019", 18362: "Windows 10 1903", 18363: "Windows 10 1909",
    19041: "Windows 10 2004", 19042: "Windows 10 20H2", 19043: "Windows 10 21H1",
    19044: "Windows 10 21H2", 19045: "Windows 10 22H2", 20348: "Windows Server 2022",
    22000: "Windows 11 21H2", 22621: "Windows 11 22H2", 22631: "Windows 11 23H2",
    26100: "Windows Server 2025 / Windows 11 24H2"
}

def build_x224_negotiation_request(requested_protocols):
    neg_req = struct.pack('<BBHI', RDP_NEG_REQ, 0x00, 0x0008, requested_protocols)
    x224_body = b'\xe0\x00\x00\x00\x00\x00' + neg_req
    x224 = struct.pack('B', len(x224_body)) + x224_body
    tpkt = struct.pack('>BBH', 3, 0, 4 + len(x224)) + x224
    return tpkt

def parse_x224_negotiation_response(data):
    result = {"selected_protocol": None, "failure_code": None, "negotiation_present": False}
    if not data or len(data) < 6:
        return result
    length_indicator = data[4]
    if length_indicator <= 6:
        return result
    nego_offset = 11
    if len(data) < nego_offset + 8:
        return result
    nego_type = data[nego_offset]
    value = struct.unpack('<I', data[nego_offset + 4:nego_offset + 8])[0]
    result["negotiation_present"] = True
    if nego_type == RDP_NEG_RSP:
        result["selected_protocol"] = value
    elif nego_type == RDP_NEG_FAILURE:
        result["failure_code"] = value
    return result

def extract_certificate_info(der_bytes):
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        return cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()
    except ImportError:
        msg = "cryptography library not installed"
        return msg, msg
    except Exception as e:
        msg = f"Parse error: {e}"
        return msg, msg

def der_len(n):
    if n < 0x80:
        return struct.pack('B', n)
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return struct.pack('B', 0x80 | len(b)) + b

def der_tlv(tag, value):
    return struct.pack('B', tag) + der_len(len(value)) + value

def build_ntlm_negotiate_message():
    flags = (0x00000001 | 0x00000004 | 0x00000200 | 0x00008000 |
             0x00080000 | 0x02000000 | 0x20000000 | 0x40000000 | 0x80000000)
    msg = b'NTLMSSP\x00'
    msg += struct.pack('<I', 1)
    msg += struct.pack('<I', flags)
    msg += struct.pack('<HHI', 0, 0, 0)
    msg += struct.pack('<HHI', 0, 0, 0)
    msg += struct.pack('<BBHI', 10, 0, 0, 15)
    return msg

def build_ts_request(ntlm_token):
    version_field = der_tlv(0xA0, der_tlv(0x02, b'\x02'))
    nego_token = der_tlv(0x04, ntlm_token)
    nego_item = der_tlv(0x30, der_tlv(0xA0, nego_token))
    nego_seq = der_tlv(0x30, nego_item)
    nego_field = der_tlv(0xA1, nego_seq)
    return der_tlv(0x30, version_field + nego_field)

def probe_ntlm_os_version(tls_sock):
    ts_req = build_ts_request(build_ntlm_negotiate_message())
    tls_sock.send(ts_req)
    data = tls_sock.recv(8192)

    idx = data.find(b'NTLMSSP\x00')
    if idx == -1 or len(data) < idx + 56:
        return None
    challenge = data[idx:]
    neg_flags = struct.unpack('<I', challenge[20:24])[0]
    if not (neg_flags & 0x02000000):
        return None
    ver = challenge[48:56]
    major, minor, build = ver[0], ver[1], struct.unpack('<H', ver[2:4])[0]
    label = NTLM_BUILD_MAP.get(build)
    return f"{label} (NT {major}.{minor}, Build {build})" if label else f"Windows NT {major}.{minor}, Build {build}"

def build_client_mcs_connect_initial(encryption_methods=0x1F):
    core_body = struct.pack('<I', 0x00080004)
    core_body += struct.pack('<HH', 1024, 768)
    core_body += struct.pack('<HH', 0xCA01, 1)
    core_body += struct.pack('<I', 0x00000409)
    core_body += struct.pack('<I', 2600)
    core_body += "reconcli".encode('utf-16-le').ljust(32, b'\x00')[:32]
    core_body += struct.pack('<I', 4)
    core_body += struct.pack('<I', 0)
    core_body += struct.pack('<I', 12)
    core_body += b'\x00' * 64
    client_core = struct.pack('<HH', 0xC001, 4 + len(core_body)) + core_body

    client_security = struct.pack('<HH', 0xC002, 12) + struct.pack('<II', encryption_methods, 0)
    client_network = struct.pack('<HH', 0xC003, 8) + struct.pack('<HH', 0, 0)
    user_data = client_core + client_security + client_network

    gcc_header = b'\x00\x05\x00\x14\x7c\x00\x01\x2a\x14\x76\x0a\x01\x01\x00\x01\xc0'
    gcc_pdu = gcc_header + struct.pack('>H', 0x8000 | len(user_data)) + user_data

    domain_selector = der_tlv(0x04, b'\x01')
    upward_flag = der_tlv(0x01, b'\xff')
    domain_params = der_tlv(0x30,
        b'\x02\x01\x22\x02\x01\x02\x02\x01\x00\x02\x01\x01'
        b'\x02\x01\x00\x02\x01\x01\x02\x03\x00\xff\xff\x02\x01\x02')

    mcs_body = (domain_selector + domain_selector + upward_flag +
                domain_params + domain_params + domain_params +
                der_tlv(0x04, gcc_pdu))
    mcs_ci = b'\x7f\x65' + der_len(len(mcs_body)) + mcs_body

    x224_data = b'\x02\xf0\x80' + mcs_ci
    return struct.pack('>BBH', 3, 0, 4 + len(x224_data)) + x224_data

def probe_rdp_encryption_level(sock, timeout):
    try:
        sock.settimeout(timeout)
        sock.send(build_client_mcs_connect_initial())
        data = sock.recv(8192)
    except Exception:
        return None, None

    idx = data.find(b'\x02\x0c')
    if idx == -1 or len(data) < idx + 12:
        return None, None
    try:
        return struct.unpack('<II', data[idx + 4:idx + 12])
    except Exception:
        return None, None

def run_rdp_advanced_audit(target, port=RDP_PORT):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "rdp_init", f"[*] Launching RDP Deep Protocol Audit on {target}:{port}", port=port)

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        log_and_print("enumeration", "rdp_x224_cr", "  [+] X.224 Connection Request (CR) sent", port=port)

        requested = PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX
        sock.send(build_x224_negotiation_request(requested))
        log_and_print("enumeration", "rdp_neg_req", f"  [+] RDP Negotiation Request sent", port=port)

        resp = sock.recv(4096)
        if not resp:
            log_and_print("enumeration", "rdp_neg_fault", "  [-] No response to RDP Negotiation Request.", port=port)
            return
        parsed = parse_x224_negotiation_response(resp)

        if parsed["failure_code"] is not None:
            fcode = parsed["failure_code"]
            reason = RDP_FAILURE_CODES.get(fcode, f"Unknown code {fcode}")
            log_and_print("enumeration", "rdp_neg_response", f"  [+] Protocol Negotiation Response: FAILURE ({reason})", port=port)
            if fcode == 5:
                log_and_print("enumeration", "rdp_nla_hint", "  [+] Network Level Authentication (NLA) is ENFORCED", port=port)
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            sock.send(build_x224_negotiation_request(PROTOCOL_RDP))
            resp = sock.recv(4096)
            parsed = parse_x224_negotiation_response(resp)

        selected = parsed["selected_protocol"]
        proto_names = {0: "Standard RDP Security", 1: "TLS/SSL", 2: "CredSSP (Hybrid/NLA)", 8: "CredSSP + Early User Auth"}
        if selected is None and not parsed["negotiation_present"]:
            selected = PROTOCOL_RDP
            log_and_print("enumeration", "rdp_neg_response", "  [+] Protocol Negotiation Response: Standard RDP Security assumed", port=port)
        elif selected is not None:
            log_and_print("enumeration", "rdp_neg_response", f"  [+] Protocol Negotiation Response: SUCCESS -> selectedProtocol={selected} ({proto_names.get(selected, 'Unknown')})", port=port)

        if selected == PROTOCOL_RDP:
            sec_layer, nla, credssp, tls_support = "RDP Security (Standard)", False, False, False
        elif selected == PROTOCOL_SSL:
            sec_layer, nla, credssp, tls_support = "SSL/TLS", False, False, True
        elif selected in (PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX):
            sec_layer, nla, credssp, tls_support = "CredSSP (Hybrid/NLA)", True, True, True
        else:
            sec_layer, nla, credssp, tls_support = "Undetermined", False, False, False

        log_and_print("enumeration", "rdp_security_layer", f"  [+] Security Layer: {sec_layer}", port=port)
        log_and_print("enumeration", "rdp_nla_status", f"  [+] Network Level Authentication (NLA): {'Enabled' if nla else 'Disabled'}", port=port)
        scan_results["port_scans"][str(port)]["version"] = f"RDP - Security Layer: {sec_layer}"

        active_sock = sock
        if tls_support:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
                except ssl.SSLError:
                    pass
                tls_sock = ctx.wrap_socket(sock, server_hostname=target)
                active_sock = tls_sock

                cipher_info = tls_sock.cipher()
                if cipher_info:
                    cname, tls_ver, bits = cipher_info
                    log_and_print("enumeration", "rdp_tls_version", f"  [+] TLS Protocol Version negotiated: {tls_ver}", port=port)

                der_cert = tls_sock.getpeercert(binary_form=True)
                if der_cert:
                    subject, issuer = extract_certificate_info(der_cert)
                    log_and_print("enumeration", "rdp_cert_subject", f"  [+] Certificate Subject: {subject}", port=port)
            except Exception as e:
                log_and_print("enumeration", "rdp_tls_fault", f"  [-] TLS handshake anomaly: {e}", port=port)
                active_sock = sock

        if selected in (PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX) and active_sock is not sock:
            try:
                win_ver = probe_ntlm_os_version(active_sock)
                if win_ver:
                    log_and_print("enumeration", "rdp_windows_version", f"  [+] Windows Version: {win_ver}", port=port)
            except Exception as e:
                log_and_print("enumeration", "rdp_ntlm_fault", f"  [-] NTLM probe anomaly: {e}", port=port)

    except Exception as e:
        log_and_print("enumeration", "rdp_fault", f"  [-] RDP Connection error: {e}", port=port)
    finally:
        try:
            sock.close()
        except Exception:
            pass

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

    # Target Ports Array (Included NEW: POP3, LDAP, DHCP)
    all_ports = [FTP_PORT, TELNET_PORT, SSH_PORT, DNS_PORT, KERBEROS_PORT, HTTP_PORT, HTTPS_PORT, SMB_PORT, RDP_PORT, ORACLE_PORT, MYSQL_PORT, POSTGRES_PORT, REDIS_PORT, MONGODB_PORT] + SMTP_PORTS + IMAP_PORTS + POP3_PORTS + LDAP_PORTS + DHCP_PORTS + HTTPS_ALT_PORTS + FTPS_PORTS

    # Step 1: Initial Discovery
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
        run_ftps_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping FTP Enumeration: Port {FTP_PORT} is strictly {port_authoritative_states[FTP_PORT]}.")

    if port_authoritative_states[TELNET_PORT] == "OPEN":
        run_telnet_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping Telnet Enumeration: Port {TELNET_PORT} is strictly {port_authoritative_states[TELNET_PORT]}.")

    if port_authoritative_states[SSH_PORT] == "OPEN":
        run_ssh_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping SSH Enumeration: Port {SSH_PORT} is strictly {port_authoritative_states[SSH_PORT]}.")

    if port_authoritative_states[DNS_PORT] == "OPEN":
        run_dns_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping DNS Enumeration: Port {DNS_PORT} is strictly {port_authoritative_states[DNS_PORT]}.")

    if port_authoritative_states[KERBEROS_PORT] == "OPEN":
        run_kerberos_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping Kerberos Enumeration: Port {KERBEROS_PORT} is strictly {port_authoritative_states[KERBEROS_PORT]}.")
    
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

    for alt_port in HTTPS_ALT_PORTS:
        if port_authoritative_states[alt_port] == "OPEN":
            log_and_print("enumeration", "https_alt_init", f"[*] Executing Deep HTTPS Fingerprinting on {target_ip}:{alt_port} (Alternate/Management Port)", port=alt_port)
            http_get_details(target_ip, port=alt_port, use_ssl=True)
            http_methods_check(target_ip, port=alt_port, use_ssl=True)
            http_security_headers_audit(target_ip, port=alt_port, use_ssl=True)
        else:
            print(f"  [-] Skipping HTTPS-Alt Enumeration: Port {alt_port} is strictly {port_authoritative_states[alt_port]}.")

    if port_authoritative_states[SMB_PORT] == "OPEN":
        run_smb_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping SMB Enumeration: Port {SMB_PORT} is strictly {port_authoritative_states[SMB_PORT]}.")

    if port_authoritative_states[RDP_PORT] == "OPEN":
        run_rdp_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping RDP Enumeration: Port {RDP_PORT} is strictly {port_authoritative_states[RDP_PORT]}.")

    if port_authoritative_states[ORACLE_PORT] == "OPEN":
        run_oracle_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping Oracle Enumeration: Port {ORACLE_PORT} is strictly {port_authoritative_states[ORACLE_PORT]}.")

    if port_authoritative_states[MYSQL_PORT] == "OPEN":
        run_mysql_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping MySQL Enumeration: Port {MYSQL_PORT} is strictly {port_authoritative_states[MYSQL_PORT]}.")

    if port_authoritative_states[POSTGRES_PORT] == "OPEN":
        run_postgres_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping PostgreSQL Enumeration: Port {POSTGRES_PORT} is strictly {port_authoritative_states[POSTGRES_PORT]}.")

    if port_authoritative_states[REDIS_PORT] == "OPEN":
        run_redis_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping Redis Enumeration: Port {REDIS_PORT} is strictly {port_authoritative_states[REDIS_PORT]}.")

    if port_authoritative_states[MONGODB_PORT] == "OPEN":
        run_mongodb_advanced_audit(target_ip)
    else:
        print(f"  [-] Skipping MongoDB Enumeration: Port {MONGODB_PORT} is strictly {port_authoritative_states[MONGODB_PORT]}.")
    
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

    # NEW: POP3 Loop
    for pop_port in POP3_PORTS:
        if port_authoritative_states[pop_port] == "OPEN":
            run_pop3_advanced_audit(target_ip, pop_port)
        else:
            print(f"  [-] Skipping POP3 Enumeration: Port {pop_port} is strictly {port_authoritative_states[pop_port]}.")

    # NEW: LDAP Loop
    for ldap_port in LDAP_PORTS:
        if port_authoritative_states[ldap_port] == "OPEN":
            run_ldap_advanced_audit(target_ip, ldap_port)
        else:
            print(f"  [-] Skipping LDAP Enumeration: Port {ldap_port} is strictly {port_authoritative_states[ldap_port]}.")

    # NEW: DHCP Loop
    for dhcp_port in DHCP_PORTS:
        if port_authoritative_states[dhcp_port] == "OPEN":
            run_dhcp_advanced_audit(target_ip, dhcp_port)
        else:
            print(f"  [-] Skipping DHCP Enumeration: Port {dhcp_port} is strictly {port_authoritative_states[dhcp_port]}.")

    for f_port in FTPS_PORTS:
        if port_authoritative_states[f_port] == "OPEN":
            run_ftps_implicit_audit(target_ip, f_port)
        else:
            print(f"  [-] Skipping Implicit FTPS Enumeration: Port {f_port} is strictly {port_authoritative_states[f_port]}.")

    # Step 6: OS Fingerprinting
    service_and_os_detection(target_ip, SSH_PORT)

    # Step 7: Export Reports
    generate_reports()
