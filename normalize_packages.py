# normalize_packages.py

import json
import os
import re
from pathlib import Path

PKG_FILE = "installed_packages.txt"
NORM_PKG_FILE = "normalized_packages.json"
VERSION_MAP_FILE = "package_version_map.json"


def normalize_version(version):
    """Normalize Debian-style version strings"""
    if not version:
        return ""
    # Strip epoch (e.g., '1:1.1.1w')
    version = re.sub(r'^\d+:', '', version)
    # Strip suffixes like -1+b1, +dfsg, ~git
    version = re.sub(r'[-+~][^-\d].*$', '', version)
    return version.strip()


def load_installed_packages():
    """Load installed packages from JSON"""
    if not os.path.exists(PKG_FILE):
        return {}
    with open(PKG_FILE) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            print("[-] Corrupted installed_packages.txt — delete and rescan")
            return {}


def load_package_map():
    """Load custom mappings from package_map.json"""
    if os.path.exists("package_map.json"):
        with open("package_map.json") as f:
            return json.load(f)
    return {}


def normalize_package_name(pkg, package_map=None):
    """Dynamically normalize package name"""
    if package_map is None:
        package_map = {}

    pkg = pkg.lower().strip()

    # Step 1: Apply known mappings
    if pkg in package_map:
        return package_map[pkg]

    # Step 2: Strip prefixes
    prefixes = [
    "lib", "node-", "ruby-", "perl-", "python", "gir1.2:", "7zip",
    "golang-", "php", "java:", "dotnet-", "postgresql-", "mysql-"
]
    for pre in prefixes:
        if pkg.startswith(pre):
            pkg = pkg[len(pre):]

    # Step 3: Strip suffixes
    suffixes = [
    "-dev", "-dbg", "-doc", "-server", "-ng", "-bin", "-common", "-tools", "-devel",
    "-runtime", "-client", "-utils", "-data", "-gui", "-minimal", "-light", "-full"
]
    for suf in suffixes:
        if pkg.endswith(suf):
            pkg = pkg[:-len(suf)]

    # Step 4: Strip versioned suffixes like -1.2.3, _git2023
    pkg = re.sub(r'[-_][\d+.*$]+', '', pkg)


    return pkg.strip()


def generate_normalized_package_list():
    """Generate normalized package list + version map"""
    print("[*] Generating normalized package list...")
    original_packages = load_installed_packages()
    package_map = load_package_map()

    normalized = {}
    version_map = {}

    for orig_pkg, raw_version in original_packages.items():
        norm_pkg = normalize_package_name(orig_pkg, package_map)
        clean_version = normalize_version(raw_version)

        if norm_pkg:
            normalized[orig_pkg] = norm_pkg
            version_map[orig_pkg] = clean_version

    # Save normalized package names
    with open(NORM_PKG_FILE, "w") as f:
        json.dump(normalized, f, indent=2)

    # Save version map
    with open(VERSION_MAP_FILE, "w") as f:
        json.dump(version_map, f, indent=2)

    print(f"[+] Created {NORM_PKG_FILE} with {len(normalized)} normalized packages.")
    print(f"[+] Created {VERSION_MAP_FILE} with {len(version_map)} versions.")

    return normalized, version_map
