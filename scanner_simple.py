import socket
import sys
import json
import requests

# Get user input for multiple targets (IP or domain)
targets_input = input("Enter IP addresses or website domains (comma or new line separated): ")
targets = [t.strip() for t in targets_input.replace('\n', ',').split(',') if t.strip()]

# Get user input for ports (comma separated)
ports_input = input("Enter ports to scan (comma separated, e.g. 80,443,22) or press Enter for default: ")
if ports_input.strip():
    ports = [int(p.strip()) for p in ports_input.split(',') if p.strip().isdigit()]
else:
    # Expanded default common ports
    ports = [21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 2483, 2484, 3306, 3389, 3690, 4000, 4045, 5060, 5432, 5900, 5984, 6379, 6667, 8000, 8080, 8443, 8888, 9200, 11211, 27017]

all_results = []

VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"  # Replace with your VirusTotal API key

def get_virustotal_report(ip_or_domain):
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_API_KEY_HERE":
        return "(VirusTotal check skipped: No API key set)"
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_or_domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            malicious = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            suspicious = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('suspicious', 0)
            return f"Malicious: {malicious}, Suspicious: {suspicious} (VirusTotal)"
        else:
            return f"VirusTotal API error: {response.status_code}"
    except Exception as e:
        return f"VirusTotal check error: {e}"

for target in targets:
    try:
        ip = socket.gethostbyname(target)
        # Try to get domain name if input is IP
        try:
            domain_name = socket.gethostbyaddr(ip)[0]
        except Exception:
            domain_name = None
    except Exception as e:
        ip = f"Error: {e}"
        domain_name = None
        open_ports = []
        api_info = None
        all_results.append({
            'target': target,
            'ip': ip,
            'domain_name': domain_name,
            'open_ports': [],
            'api_info': None
        })
        continue

    open_ports = []
    for port in ports:
        try:
            service = socket.getservbyport(port, 'tcp')
        except Exception:
            service = 'Unknown'
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)  # Reduced timeout for faster scan
        try:
            result = sock.connect_ex((ip, port))
            status = 'Open' if result == 0 else 'Closed'
        except Exception as e:
            status = f"Error: {e}"
        finally:
            sock.close()
        if status == 'Open':
            open_ports.append({
                'port': port,
                'service': service,
                'status': status
            })

    api_info = None
    if not ip.replace('.', '').isdigit():
        try:
            import requests
            api_url = f"http://{target}/api"
            r = requests.get(api_url, timeout=2)
            if r.status_code == 200:
                api_info = r.text
            else:
                api_info = f"API endpoint returned status {r.status_code}"
        except Exception as e:
            api_info = f"API check error: {e}"

    all_results.append({
        'target': target,
        'ip': ip,
        'domain_name': domain_name,
        'open_ports': open_ports,
        'api_info': api_info
    })

with open('scan_results_simple.txt', 'a') as f:
    for result in all_results:
        f.write(f"Target: {result['target']}\nIP: {result['ip']}\n")
        if result.get('domain_name'):
            f.write(f"Domain Name: {result['domain_name']}\n")
        f.write("\nOpen Ports:\n")
        f.write("No | Port | Service | Status\n")
        f.write("---|------|---------|-------\n")
        for idx, res in enumerate(result['open_ports'], 1):
            f.write(f"{idx}  | {res['port']}   | {res['service']}    | {res['status']}\n")
        f.write("\n")
        if result['api_info']:
            f.write(f"API Info: {result['api_info']}\n")
        # ...existing code for threat info...
        if 'get_virustotal_report' in globals():
            vt_info = get_virustotal_report(result['target'])
            if vt_info and "skipped" not in vt_info:
                f.write(f"Threat Info: {vt_info}\n")
        f.write("\n==============================\n\n")

print("Scan complete. Results saved to scan_results_simple.txt")
