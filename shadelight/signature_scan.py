import os
import hashlib
from colorama import Fore, Style, init
init(autoreset=True)

# Fake known-bad hashes for demo purposes
# In a real tool, you'd pull these from VirusTotal, MalShare, etc.
KNOWN_BAD_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty file (demo)",
    "90497dccc1d87d52aa25d50e3f623359d1b82c691c14dc1215df42b60bc7e10a":"Demo Malware ",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR test file (AV test string)"
}

def hash_file(filepath, algorithm="sha256"):
    """Calculate file hash"""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        if algorithm == "sha256":
            return hashlib.sha256(data).hexdigest()
        elif algorithm == "md5":
            return hashlib.md5(data).hexdigest()
    except Exception:
        return None

def scan_folder_for_signatures(path):
    matches = []

    print(f"{Fore.CYAN}[INFO] Scanning for known malware signatures: {path}{Style.RESET_ALL}")

    if os.path.isfile(path):
        paths = [path]
    else:
        paths = []
        for root, _, files in os.walk(path):
            for name in files:
                paths.append(os.path.join(root, name))

    for file_path in paths:
        print(f"{Fore.BLUE}    [SCAN] {file_path}")
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                if file_hash in KNOWN_BAD_HASHES:
                    label = KNOWN_BAD_HASHES[file_hash]
                    print(f"{Fore.RED}    [ALERT] Match found: {label}")
                    matches.append({
                        "path": file_path,
                        "hash": file_hash,
                        "label": label
                    })
                else:
                    print(f"{Fore.GREEN}    [CLEAN] {file_path}")
        except Exception as e:
            print(f"{Fore.YELLOW}    [SKIP] Could not read {file_path} — {e}")

    print(f"\n{Fore.MAGENTA}[SUMMARY] Total matches: {len(matches)}{Style.RESET_ALL}\n")
    return matches



def save_signature_scan_csv(results, filename="signature_scan_results.csv"):
    import csv
    with open(filename, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["File Path", "Hash", "Detected Threat"])
        for r in results:
            writer.writerow([r["path"], r["hash"], r["label"]])

def save_signature_scan_html(results, filename="signature_scan_results.html"):
    from datetime import datetime
    with open(filename, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Signature Scan Report</title></head><body>")
        f.write("<h1>Shadelight Signature Scan</h1>")
        f.write(f"<p>Generated: {datetime.now()}</p>")
        f.write("<table border='1'><tr><th>File Path</th><th>Hash</th><th>Threat</th></tr>")
        for r in results:
            f.write(f"<tr><td>{r['path']}</td><td>{r['hash']}</td><td>{r['label']}</td></tr>")
        f.write("</table></body></html>")
