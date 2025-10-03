# Scanner
CONTENT — Quick hook: “Give an IP or domain — find open TCP ports and the likely services running on them.”
🚀 Project overview

Scanner is a small, easy-to-use Python-based network utility that scans a single IP address or domain, probes TCP ports, and attempts to identify services (HTTP, SSH, SMTP, etc.) running on open ports. The project is intended for authorized security testing, inventory, and troubleshooting only.

⚠️ Legal & safety notice

Network scanning can be intrusive and may be illegal when performed without permission. Only scan hosts you own or have explicit permission to test. The author/contributors are not liable for misuse.

🛠 Tech stack

Python 3.8+

Standard library modules: socket, argparse, concurrent.futures, datetime

Optional (if used): python-nmap, scapy (listed in requirements.txt if needed
