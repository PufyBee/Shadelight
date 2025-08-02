# Shadelight

_"Open the blinds to your safety"_

## Overview
Shadelight is a lightweight Python‑based network and threat scanner for students, home users, and cybersecurity learners. It helps uncover live hosts and open ports in your local subnet and identifies potential security risks.

## Features
- **Subnet‑wide host discovery** via `ping`/`ARP`
- **TCP port scanning** (multi‑host, multi‑port)
- **Simple risk flagging** *(coming soon)*
- **CSV + HTML reporting** *(coming soon)*
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

## Project Structure
```text
shadelight/
├── shadelight/       ← main scanner code
│   ├── __init__.py
│   ├── __main__.py
│   └── scanner.py
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

## Ethical Use Notice
Use **Shadelight** only on networks you own **or** have explicit permission to scan. Unauthorized scanning is illegal and unethical. This tool is built for academic and educational purposes.

## License
[MIT License](LICENSE)