import os
import hashlib
import json
from colorama import Fore, Style, init
# Try to import yara, otherwise disable that layer
try:
    import yara
except ImportError:
    yara = None
from datetime import datetime


init(autoreset=True)

BASE_DIR = os.path.dirname(__file__)
SIGNATURE_MANIFEST = os.path.join(BASE_DIR, "signatures.json")
YARA_RULES_FILE = os.path.join(BASE_DIR, "rules.yar")

def load_manifest():
    if not os.path.exists(SIGNATURE_MANIFEST):
        return {"hashes": [], "fuzzy": [], "yara_revision": None}
    with open(SIGNATURE_MANIFEST, "r", encoding="utf-8") as f:
        return json.load(f)

def compile_yara():
    # If yara-python isn't installed or failed to import, skip this layer
    if yara is None:
        return None

    # Only attempt to compile if the rules file exists
    if os.path.exists(YARA_RULES_FILE):
        try:
            return yara.compile(filepath=YARA_RULES_FILE)
        except Exception as e:
            print(f"{Fore.YELLOW}[WARN] Failed to compile YARA rules: {e}")
    return None

def compute_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def check_exact_hash(file_hash, manifest):
    for entry in manifest.get("hashes", []):
        if entry.get("type") == "sha256" and entry.get("value", "").lower() == file_hash.lower():
            return {
                "matched": True,
                "name": entry.get("name"),
                "source": entry.get("source"),
                "date_added": entry.get("date_added"),
            }
    return {"matched": False}

def check_yara(filepath, compiled_rules):
    if not compiled_rules:
        return []
    try:
        matches = compiled_rules.match(filepath=filepath)
        return [m.rule for m in matches]
    except Exception:
        return []

def aggregate_risk(exact, yara_matches):
    score = 0
    reasons = []

    if exact.get("matched"):
        score += 100
        reasons.append(f"Exact hash match: {exact.get('name')}")
    if yara_matches:
        yara_score = 40 * len(yara_matches)
        score += yara_score
        reasons.append(f"YARA rules triggered: {', '.join(yara_matches)}")

    if score > 150:
        score = 150

    if score >= 100:
        level = "High"
    elif score >= 50:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
    }

def scan_path_for_signatures(path):
    matches = []
    manifest = load_manifest()
    compiled_yara = compile_yara()

    def scan_file(file_path):
        try:
            sha256 = compute_sha256(file_path)
            exact = check_exact_hash(sha256, manifest)
            yara_matches = check_yara(file_path, compiled_yara)
            risk = aggregate_risk(exact, yara_matches)

            entry = {
                "path": file_path,
                "sha256": sha256,
                "exact_match": exact,
                "yara_matches": yara_matches,
                "risk": risk,
            }

            if exact.get("matched") or yara_matches:
                matches.append(entry)

            print(f"{Fore.BLUE}    [SCAN] {file_path}")
            if exact.get("matched"):
                print(f"{Fore.RED}    [ALERT] Exact hash match: {exact.get('name')}")
            if yara_matches:
                print(f"{Fore.YELLOW}    [NOTICE] YARA rule(s): {', '.join(yara_matches)}")
            if not exact.get("matched") and not yara_matches:
                print(f"{Fore.GREEN}    [CLEAN] {file_path}")

            print(f"         Risk level: {risk['level']} (score {risk['score']})")
            for reason in risk["reasons"]:
                print(f"           - {reason}")

        except Exception as e:
            print(f"{Fore.YELLOW}    [SKIP] Could not scan {file_path} — {e}")

    print(f"{Fore.CYAN}[INFO] Running layered signature scan (hash + YARA): {path}{Style.RESET_ALL}")

    if os.path.isfile(path):
        scan_file(path)
    else:
        for root, _, files in os.walk(path):
            for name in files:
                scan_file(os.path.join(root, name))

    print(f"\n{Fore.MAGENTA}[SUMMARY] Total suspicious/positive hits: {len(matches)}{Style.RESET_ALL}\n")
    return matches

def save_signature_scan_csv(results, filename="signature_scan_results.csv"):
    import csv
    with open(filename, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["File Path", "SHA256", "Risk Level", "Reasons"])
        for r in results:
            reasons = "; ".join(r["risk"]["reasons"])
            writer.writerow([r["path"], r["sha256"], r["risk"]["level"], reasons])

def save_signature_scan_html(results, filename="signature_scan_results.html"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Signature Scan Report</title></head><body>")
        f.write("<h1>Shadelight Signature Scan</h1>")
        f.write(f"<p>Generated: {datetime.now()}</p>")
        f.write("<table border='1'><tr><th>File Path</th><th>SHA256</th><th>Risk</th><th>Reasons</th></tr>")
        for r in results:
            reasons = "<br>".join(r["risk"]["reasons"])
            f.write(f"<tr><td>{r['path']}</td><td>{r['sha256']}</td><td>{r['risk']['level']}</td><td>{reasons}</td></tr>")
        f.write("</table></body></html>")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python signature_scan.py <file-or-folder>")
        sys.exit(1)
    target = sys.argv[1]
    results = scan_path_for_signatures(target)
    save_signature_scan_csv(results)
    save_signature_scan_html(results)
