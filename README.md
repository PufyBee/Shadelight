# Shadelight

_"Open the blinds to your safety"_

## Overview
Shadelight is a lightweight Python‑based network and threat scanner for students, home users, and cybersecurity learners. It helps uncover live hosts and open ports in your local subnet and identifies potential security risks.

## Features
- **Subnet‑wide host discovery** via `ping`/`ARP`
- **TCP port scanning** 
- **Simple risk flagging** 
-  **Signature based malware scanning** 
- **CSV + HTML reporting** 
- **Streamlit GUI** *(planned)*

## Installation
```bash
git clone https://github.com/YOUR_USERNAME/shadelight.git
cd shadelight
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage
```bash
python -m shadelight 192.168.1.0/24 --ports 22,80,443
```
Replace `192.168.1.0/24` with your own subnet and adjust the port list as needed.

## Signature-Based Malware Scan
- **Scan a folder**
python -m shadelight 0.0.0.0/32 -- ports 0 --signature-scan "C:\\Users\\YourName\\Downloads"
- **Scan a single file**
python -m shadelight 0.0.0.0/32 --ports 0 --signature-scan "C:\\path\\to\\suspect_file.exe"

## Project Structure
```text
shadelight/
├── shadelight/       ← main scanner code
│   ├── __init__.py
│   ├── __main__.py
│   └── scanner.py
|   └── signature_scan.py
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

## Ethical Use Notice
Use **Shadelight** only on networks you own **or** have explicit permission to scan. Unauthorized scanning is illegal and unethical. This tool is built for academic and educational purposes.

## License
[MIT License](LICENSE)