import argparse
import subprocess
import os
import sys
import json
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from fetch_cve import update_cve_repo
from import_cves import rebuild_database
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


def main():
    parser = argparse.ArgumentParser(description="CVE Scanner")
    parser.add_argument("--update", action="store_true", help="Update CVE database before scanning")
    parser.add_argument("--update-db", action="store_true", help="Force-rebuild SQLite DB")
    parser.add_argument("--format", choices=["json", "csv", "txt", "html", "all"], default="json",
                        help="Output format for report")
    parser.add_argument("--min-cve-year", type=int, help="Only match CVEs from this year or newer")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    print(BANNER)

    if args.update:
        update_cve_repo()

    if args.update_db:
        rebuild_database()

    print("[*] Generating normalized package list...")
    normalized_packages, version_map = generate_normalized_package_list()

    matches, invalid_conditions = scan_sqlite_for_cves(
        normalized_packages, version_map, debug=args.debug, min_cve_year=args.min_cve_year
    )

    generate_final_report(matches, fmt=args.format)
    save_invalid_conditions(invalid_conditions)

if __name__ == "__main__":
    main()
