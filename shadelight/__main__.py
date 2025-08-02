from .scanner import run_scan
from .signature_scan import scan_folder_for_signatures, save_signature_scan_csv, save_signature_scan_html
import argparse

def main():
    parser = argparse.ArgumentParser(description="Shadelight - Lightweight Security Scanner")
    parser.add_argument("subnet", help="Subnet to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("--ports", help="Comma-separated list of ports to scan", default="22,80,443,445")
    parser.add_argument("--signature-scan", help="Optional folder to scan for known malware signatures")
    args = parser.parse_args()

    ports = list(map(int, args.ports.split(",")))
    run_scan(args.subnet, ports)

    if args.signature_scan:
        print(f"\n[INFO] Scanning folder for known malware signatures: {args.signature_scan}")
        signature_hits = scan_folder_for_signatures(args.signature_scan)

        if signature_hits:
            print(f"[ALERT] {len(signature_hits)} suspicious file(s) found!")
            for hit in signature_hits:
                print(f"        {hit['path']} — {hit['label']}")
        else:
            print("[INFO] No known malware signatures detected.")

        save_signature_scan_csv(signature_hits)
        save_signature_scan_html(signature_hits)

if __name__ == "__main__":
    main()
