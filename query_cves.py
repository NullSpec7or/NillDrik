# query_cves.py

import sqlite3
from packaging.version import parse as parse_version
import json
from datetime import datetime
import csv
import os
from pathlib import Path
import re


REPORT_DIR = "Drishti-Report"
os.makedirs(REPORT_DIR, exist_ok=True)

BANNER = r"""
#        ▄▄        ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄            ▄            ▄▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄    ▄ 
#       ▐░░▌      ▐░▌▐░░░░░░░░░░░▌▐░▌          ▐░▌          ▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌  ▐░▌
#       ▐░▌░▌     ▐░▌ ▀▀▀▀█░█▀▀▀▀ ▐░▌          ▐░▌          ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ ▐░▌ ▐░▌ 
#       ▐░▌▐░▌    ▐░▌     ▐░▌     ▐░▌          ▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌     ▐░▌     ▐░▌▐░▌  
#       ▐░▌ ▐░▌   ▐░▌     ▐░▌     ▐░▌          ▐░▌          ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░▌░▌   
#       ▐░▌  ▐░▌  ▐░▌     ▐░▌     ▐░▌          ▐░▌          ▐░▌       ▐░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░░▌    
#       ▐░▌   ▐░▌ ▐░▌     ▐░▌     ▐░▌          ▐░▌          ▐░▌       ▐░▌▐░█▀▀▀▀█░█▀▀      ▐░▌     ▐░▌░▌   
#       ▐░▌    ▐░▌▐░▌     ▐░▌     ▐░▌          ▐░▌          ▐░▌       ▐░▌▐░▌     ▐░▌       ▐░▌     ▐░▌▐░▌  
#       ▐░▌     ▐░▐░▌ ▄▄▄▄█░█▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░▌      ▐░▌  ▄▄▄▄█░█▄▄▄▄ ▐░▌ ▐░▌ 
#       ▐░▌      ▐░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░▌  ▐░▌
#        ▀        ▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀   ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀    ▀ 
#
#    Project: NillDrik – The Seer from Niladri
#    Where the sacred eye rests, shadows in code unravel.
#    Code Author: Rupesh Kumar (@Null Spec7or)
#    GitHub: Null Spec7or | Twitter: @nullspec7or
"""


def extract_year_from_cve(cve_id):
    if cve_id.startswith("CVE-"):
        parts = cve_id.split("-")
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
    return 1999

def sanitize_expression(expr):
    if not expr:
        return ""
    expr = expr.replace("Fixed in", "")
    expr = expr.replace("Affected", "")
    expr = expr.replace("OpenSSL", "")
    expr = expr.strip()
    expr = expr.replace(" and ", ",").replace("&", ",")
    expr = expr.replace("to", ",").replace("upto", ",")
    expr = re.sub(r'[^\d<>=., ]+', '', expr)
    expr = re.sub(r'\s+', '', expr)
    return expr.strip()

def normalize_debian_version(version):
    return version.split('-')[0] if '-' in version else version

def ver_in_range(installed_str, expr_str, debug=False):
    if not installed_str or not expr_str:
        return False

    try:
        inst_v = parse_version(normalize_debian_version(installed_str))
        expr_str = sanitize_expression(expr_str)

        if not re.search(r'\d+\.\d+', expr_str):
            raise ValueError("No version-like pattern in expression")

        conditions = expr_str.split(",")
        for cond in conditions:
            cond = cond.strip()
            if not cond:
                continue

            match = re.match(r'(<=|>=|==|<|>)\s*([\d\.\+a-zA-Z\-]+)', cond)
            if not match:
                raise ValueError(f"Invalid version condition: {cond}")

            op, val = match.groups()
            val_v = parse_version(normalize_debian_version(val))

            if debug:
                print(f"[DEBUG] Comparing {inst_v} {op} {val_v}")

            if op == "<" and not (inst_v < val_v): return False
            if op == ">" and not (inst_v > val_v): return False
            if op == "<=" and not (inst_v <= val_v): return False
            if op == ">=" and not (inst_v >= val_v): return False
            if op == "==" and not (inst_v == val_v): return False

        return True

    except Exception as e:
        raise ValueError(f"Version comparison failed: {e}")


def scan_sqlite_for_cves(normalized_packages, version_map, debug=False, min_cve_year=None):
    print("[*] Matching packages against CVEs...")
    conn = sqlite3.connect("cve.db")
    cur = conn.cursor()

    results = []
    matched_cves = 0
    invalid_conditions = []

    for orig_pkg, norm_pkg in normalized_packages.items():
        clean_version = version_map.get(orig_pkg, "")
        if not clean_version:
            continue

        cur.execute("SELECT * FROM cves WHERE package LIKE ?", (f"%{norm_pkg}%",))
        rows = cur.fetchall()

        for row in rows:
            if len(row) < 6:
                continue

            try:
                cve_id = row[1]
                ver_expr = row[4]
                status = row[5]
                desc = row[6]
            except IndexError:
                continue

            if status != "affected":
                continue

            cve_year = extract_year_from_cve(cve_id)
            if min_cve_year and int(cve_year) < min_cve_year:
                continue

            try:
                if ver_in_range(clean_version, ver_expr, debug=debug):
                    exploit_links = [
                        f"https://www.exploit-db.com/search?cve={cve_id}",
                        f"https://github.com/search?q={cve_id}"
                    ]
                    results.append({
                        "original_package": orig_pkg,
                        "version": version_map[orig_pkg],
                        "clean_version": clean_version,
                        "cve": cve_id,
                        "year": str(cve_year),
                        "description": desc,
                        "version_expr": ver_expr,
                        "exploit_links": exploit_links
                    })
                    matched_cves += 1
            except ValueError as ve:
                if debug:
                    print(f"[DEBUG] Invalid condition for {orig_pkg}: {ver_expr}")
                invalid_conditions.append({
                    "package": norm_pkg,
                    "original_package": orig_pkg,
                    "clean_version": clean_version,
                    "expression": ver_expr
                })

    conn.close()
    return results, invalid_conditions


def generate_final_report(matches, fmt="json"):
    if not matches:
        print("\n[=] No vulnerabilities found.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = Path(REPORT_DIR) / f"cve_report_{timestamp}"

    print(BANNER)
    print(f"\n[!] Vulnerability Report — Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")

    for m in matches:
        print(f"Package:      {m['original_package']} ({m['version']})")
        print(f"CVE ID:       {m['cve']}")
        print(f"Year:         {m['year']}")
        print(f"Description:  {m['description']}")
        print(f"Version Expr: {m['version_expr']}")
        print(f"Public Exploits:")
        for link in m['exploit_links']:
            print(f"  - {link}")
        print("-" * 60)

    if fmt in ["json", "all"]:
        with open(base_name.with_suffix(".json"), "w") as f:
            json.dump(matches, f, indent=2)
        print(f"[+] Saved JSON report: {base_name}.json")

    if fmt in ["txt", "all"]:
        with open(base_name.with_suffix(".txt"), "w") as f:
            f.write(BANNER + "\n\n")
            for m in matches:
                f.write(f"Package:      {m['original_package']} ({m['version']})\n")
                f.write(f"CVE ID:       {m['cve']}\n")
                f.write(f"Year:         {m['year']}\n")
                f.write(f"Description:  {m['description']}\n")
                f.write(f"Version Expr: {m['version_expr']}\n")
                f.write("Public Exploits:\n")
                for link in m['exploit_links']:
                    f.write(f"  - {link}\n")
                f.write("-" * 60 + "\n")
        print(f"[+] Saved TXT report: {base_name}.txt")

    if fmt in ["csv", "all"]:
        with open(base_name.with_suffix(".csv"), "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "original_package", "version", "cve", "year", "description", "version_expr", "exploit_links"
            ])
            writer.writeheader()
            for m in matches:
                row = {key: m[key] for key in writer.fieldnames}
                row["exploit_links"] = "\n".join(m["exploit_links"])
                writer.writerow(row)
        print(f"[+] Saved CSV report: {base_name}.csv")

    if fmt in ["html", "all"]:
        with open(base_name.with_suffix(".html"), "w") as f:
            f.write("<html><head><title>Drishti CVE Scanner</title></head><body>")
            f.write(f"<pre>{BANNER.replace('\n', '<br>').replace(' ', '&nbsp;')}</pre><hr>")
            for m in matches:
                f.write(f"<h3>{m['cve']}</h3>")
                f.write(f"<p><b>Package:</b> {m['original_package']}<br>")
                f.write(f"<b>Version:</b> {m['version']}<br>")
                f.write(f"<b>CVE Year:</b> {m['year']}<br>")
                f.write(f"<b>Description:</b> {m['description']}<br>")
                f.write(f"<b>Version Expr:</b> {m['version_expr']}<br>")
                f.write("<b>Exploit Links:</b><ul>")
                for link in m['exploit_links']:
                    f.write(f"<li><a href='{link}'>{link}</a></li>")
                f.write("</ul></p><hr>")
            f.write("</body></html>")
        print(f"[+] Saved HTML report: {base_name}.html")
        
def save_invalid_conditions(invalid_conditions):
    if not invalid_conditions:
        return



    report_path = Path("NillDrik's-Reports")
    report_path.mkdir(exist_ok=True)

    invalid_file = report_path / "invalid_version_expressions.json"
    with open(invalid_file, "w") as f:
        json.dump(invalid_conditions, f, indent=2)

    print(f"[!] Saved invalid version expressions to: {invalid_file}")
