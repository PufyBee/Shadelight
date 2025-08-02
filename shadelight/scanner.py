# shadelight/scanner.py

import ipaddress
import platform
import subprocess
import socket
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Basic risk flagging based on well-known ports
COMMON_RISKS = {
    21: "FTP - Unencrypted file transfer",
    23: "Telnet - Unencrypted remote access",
    80: "HTTP - Consider using HTTPS",
    139: "NetBIOS - Legacy file sharing",
    445: "SMB - Windows file sharing",
    3389: "RDP - Remote Desktop"
}

def ping_host(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", str(ip)]
    try:
        subprocess.check_output(command, stderr=subprocess.DEVNULL)
        return str(ip)
    except subprocess.CalledProcessError:
        return None

def scan_subnet(subnet):
    net = ipaddress.ip_network(subnet, strict=False)
    print(f"[INFO] Scanning subnet: {subnet}")

    live_hosts = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping_host, net.hosts())

    for ip in results:
        if ip:
            live_hosts.append(ip)

    print(f"[INFO] {len(live_hosts)} host(s) found alive:")
    for host in live_hosts:
        print(f"       {host}")

    return live_hosts

def scan_port(ip, port, timeout=1):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        return port if result == 0 else None
    
def grab_banner(ip, port, timeout=1):
    try:
        with socket.socket() as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")  # generic banner probe
            return s.recv(1024).decode(errors="ignore").strip()
    except Exception:
        return ""


def scan_ports(ip, ports, timeout=1, max_threads=50):
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                result = future.result()
                if result is not None:
                    open_ports.append(result)
            except Exception:
                pass
    return open_ports

def flag_risks(open_ports):
    flags = []
    for port in open_ports:
        if port in COMMON_RISKS:
            flags.append(f"Port {port}: {COMMON_RISKS[port]}")
    return flags

def save_results_csv(results, filename="scan_results.csv"):
    with open(filename, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Open Ports", "Risks", "Banners"])
        for r in results:
            banner_str = "; ".join(f"{p}: {b}" for p, b in r.get("banners", {}).items())
            writer.writerow([
                r["host"],
                ", ".join(map(str, r["open_ports"])),
                "; ".join(r["risks"]),
                banner_str
            ])


def save_results_html(results, filename="scan_results.html"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Scan Report</title></head><body>")
        f.write("<h1>Shadelight Scan Report</h1>")
        f.write(f"<p>Generated: {datetime.now()}</p>")
        f.write("<table border='1'><tr><th>Host</th><th>Open Ports</th><th>Risks</th><th>Banners</th></tr>")
        for r in results:
            f.write(f"<tr><td>{r['host']}</td>")
            f.write(f"<td>{', '.join(map(str, r['open_ports']))}</td>")
            f.write(f"<td>{'<br>'.join(r['risks'])}</td>")
            banner_html = "<br>".join(f"{p}: {b}" for p, b in r.get("banners", {}).items())
            f.write(f"<td>{banner_html}</td></tr>")
        f.write("</table></body></html>")


def run_scan(subnet, ports):
    live_hosts = scan_subnet(subnet)
    results = []

    for host in live_hosts:
        print(f"\n[INFO] Scanning host: {host}")
        open_ports = scan_ports(host, ports)
        port_banners = {p: grab_banner(host, p) for p in open_ports}


        if open_ports:
            print(f"[RESULT] Open ports on {host}: {', '.join(map(str, open_ports))}")
            risk_flags = flag_risks(open_ports)
            for flag in risk_flags:
                print(f"         {flag}")
        else:
            print(f"[RESULT] No open ports found on {host}")
            risk_flags = []

        results.append({
            "host": host,
            "open_ports": open_ports,
            "risks": risk_flags,
            "banners":port_banners
        })

    save_results_csv(results)
    save_results_html(results)
