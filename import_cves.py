# import_cves.py

import sqlite3
import json
import os
import sys
import platform
from pathlib import Path


def supports_emoji():
    if os.name == 'nt':
        win_ver = float(platform.win32_ver()[0])
        return win_ver >= 10
    return True


def create_db():
    conn = sqlite3.connect("cve.db")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            package TEXT,
            vendor TEXT,
            version_expr TEXT,
            status TEXT,
            description TEXT
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_package ON cves(package)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_id ON cves(cve_id)")
    conn.commit()
    return conn


def import_cves_into_db(conn):
    cur = conn.cursor()
    count = 0

    cve_dir = "cve_db/cves"
    if not os.path.exists(cve_dir):
        print(f"[-] CVE data directory not found: {cve_dir}")
        return 0

    SKIP_FILES = {"deltaLog.json", "delta.json"}

    for root, dirs, files in os.walk(cve_dir):
        for file in files:
            if not file.endswith(".json"):
                continue
            if file in SKIP_FILES:
                print(f"[-] Skipping metadata file: {file}")
                continue

            path = os.path.join(root, file)

            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                if not isinstance(data, dict) or "cveMetadata" not in data:
                    print(f"[-] Skipping non-CVE file: {file}")
                    continue

                cna = data.get("containers", {}).get("cna", {})
                affected = cna.get("affected", [])
                desc = cna.get("descriptions", [{}])[0].get("value", "")
                cve_id = data.get("cveMetadata", {}).get("cveId", "")

                for item in affected:
                    product = item.get("product", "").lower()
                    vendor = item.get("vendor", "").lower()
                    versions = item.get("versions", [])

                    for vinfo in versions:
                        ver = vinfo.get("version", "")
                        status = vinfo.get("status", "")

                        cur.execute("""
                            INSERT INTO cves (cve_id, package, vendor, version_expr, status, description)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (cve_id, product, vendor, ver, status, desc))
                        count += 1

            except Exception as e:
                print(f"[-] Error parsing {file}: {e}")
                continue

    conn.commit()
    print(f"[+] Imported {count} CVE records into SQLite.")
    return count


def count_cves_in_db():
    if not os.path.exists("cve.db"):
        return 0
    try:
        conn = sqlite3.connect("cve.db")
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM cves")
        count = cur.fetchone()[0]
        conn.close()
        return count
    except Exception as e:
        print(f"[-] Could not count CVEs in DB: {e}")
        return 0



def rebuild_database():
    print("[*] Updating CVE database...")
    
    if os.path.exists("cve.db"):
        os.remove("cve.db")

    conn = create_db()
    print("[*] Importing CVE data...")
    after_count = import_cves_into_db(conn)
    conn.close()

    print(f"[+] Database rebuilt successfully. Imported {after_count:,} CVE records.")
