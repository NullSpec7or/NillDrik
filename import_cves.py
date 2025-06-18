# import_cves.py

import sqlite3
import json
import os
from pathlib import Path


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
    import json
    import os

    cur = conn.cursor()
    count = 0

    for root, _, files in os.walk("cve_db/cves"):
        for file in files:
            if not file.endswith(".json"):
                continue
            path = os.path.join(root, file)
            try:
                with open(path) as f:
                    data = json.load(f)

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
                pass

    conn.commit()
    print(f"[+] Imported {count} CVE records into SQLite.")


def rebuild_database():
    if os.path.exists("cve.db"):
        os.remove("cve.db")
    conn = create_db()
    import_cves_into_db(conn)
    conn.close()
