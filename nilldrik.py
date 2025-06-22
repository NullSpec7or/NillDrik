# nilldrik.py

import argparse
import subprocess
import os
import sys
import json
from pathlib import Path
from datetime import datetime

sys.path.append(str(Path(__file__).parent))

from fetch_cve import update_cve_repo
from import_cves import rebuild_database, count_cves_in_db
from query_cves import scan_sqlite_for_cves, generate_final_report, save_invalid_conditions
from normalize_packages import generate_normalized_package_list


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


def supports_emoji():
    if os.name == 'nt':
        win_ver = float(os.environ.get('OS_VERSION', '10'))
        return win_ver >= 10
    return True


def get_installed_packages():
    print("[*] Scanning for installed packages...")

    try:
        if os.path.exists("/etc/debian_version"):
            result = subprocess.run(
                ["dpkg", "--get-selections"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            lines = result.stdout.strip().splitlines()
            packages = {}
            for line in lines:
                if "install" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == "install":
                        pkg_name = parts[0]
                        ver_result = subprocess.run(
                            ["dpkg-query", "-W", "-f='${Version}'", pkg_name],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            text=True
                        )
                        version = ver_result.stdout.strip("'")
                        packages[pkg_name] = version
            return packages

        elif os.path.exists("/etc/redhat-release") or os.path.exists("/etc/fedora-release"):
            result = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}\n"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            packages = {}
            for line in result.stdout.strip().splitlines():
                parts = line.strip().split(" ", 1)
                if len(parts) == 2:
                    packages[parts[0]] = parts[1]
            return packages

        elif os.path.exists("/etc/arch-release"):
            result = subprocess.run(
                ["pacman", "-Qs"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            packages = {}
            for line in result.stdout.strip().splitlines():
                if line.startswith("local/"):
                    name_part = line[len("local/"):]
                    parts = name_part.split(" ", 1)
                    if len(parts) == 2:
                        packages[parts[0]] = parts[1]
            return packages

        else:
            print("[-] Unsupported OS for automatic package scanning.")
            return None

    except Exception as e:
        print(f"[-] Error retrieving installed packages: {e}")
        return None


def save_installed_packages(packages, filename="installed_packages.txt"):
    with open(filename, "w") as f:
        json.dump(packages, f, indent=2)
    print(f"[+] Installed packages saved to {filename}")


def main():
    try:
        parser = argparse.ArgumentParser(
            description="CVE Scanner - Scan installed packages against known vulnerabilities",
            formatter_class=argparse.RawTextHelpFormatter
        )
        parser.add_argument("--update", action="store_true", help="Update CVE database before scanning")
        parser.add_argument("--update-db", action="store_true", help="Force-rebuild SQLite DB")
        parser.add_argument("--format", choices=["json", "csv", "txt", "html", "all"], default="json",
                            help="Output format for report\n(default: json)")
        parser.add_argument("--min-cve-year", type=int, help="Only match CVEs from this year or newer")
        parser.add_argument("--debug", action="store_true", help="Enable debug output")
        parser.add_argument("--keepfiles", action="store_true",
                    help="Keep temp files (installed_packages.txt, etc.) after scan")

        args = parser.parse_args()

        # Show help if no args passed
        if len(sys.argv) == 1:
            print(BANNER)
            parser.print_help()
            print("\n[*] Tip: Use --update to fetch latest CVEs")
            print("      Use --help for full usage details")
            return

        print(BANNER)


        # Show last commit hash if available
        if os.path.exists("last_commit.txt"):
            with open("last_commit.txt") as f:
                last_commit = f.read().strip()
            if supports_emoji():
                print(f"📌 [*] Last commit: {last_commit[:12]}")
            else:
                print(f"[*] Last commit: {last_commit[:12]}")
        else:
            print("[-] No commit info found. Run --update first.")

        repo_updated = False

        # Step 1 & Step 2 combined: Handle CVE update & DB rebuild
        should_rebuild = False

        if args.update:
           #print("[*] Updating CVE repo...")
            repo_updated = update_cve_repo()

            if repo_updated:
                print("[*] Rebuilding database due to CVE update...")
                should_rebuild = True
            else:
                print("[=] No updates found.")

        if args.update_db:
            print("[*] Forcing database rebuild (--update-db)")
            should_rebuild = True

        # Do the rebuild only once if needed
        if should_rebuild:
            if os.path.exists("cve.db"):
                os.remove("cve.db")
                print("[*] Deleted old cve.db")

            rebuild_database()

        # Step 3: Scan installed packages (always)
        packages = get_installed_packages()
        if not packages:
            print("[-] Failed to retrieve installed packages. Aborting.")
            return

        save_installed_packages(packages)
       #print("[*] Generating normalized package list...")
        normalized_packages, version_map = generate_normalized_package_list()

        # Step 4: Scan SQLite DB for CVE matches
       #print("[*] Matching packages against CVEs...")
        matches, invalid_conditions = scan_sqlite_for_cves(
            normalized_packages, version_map, debug=args.debug, min_cve_year=args.min_cve_year
        )

        # Step 5: Generate final report
        generate_final_report(matches, fmt=args.format)
        save_invalid_conditions(invalid_conditions)

        # Auto-delete package files unless --keepfiles is passed
        if not args.keepfiles:
            print("[*] Cleaning up old package files (use --keepfiles to preserve)")
            for f in ["installed_packages.txt", "package_version_map.json", "normalized_packages.json"]:
                if os.path.exists(f):
                    os.remove(f)
                    print(f"[+] Removed {f}")

    except KeyboardInterrupt:
        print("\n[-] Operation interrupted by user. Exiting gracefully...")
        sys.exit(1)

if __name__ == "__main__":
    main()
