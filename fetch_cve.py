# fetch_cve.py

import os
import zipfile
import requests
from pathlib import Path
from git import Repo


CVE_REPO_URL = "https://github.com/CVEProject/cvelistV5.git" 
CVE_ZIP_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip" 
CVE_DIR = Path("cve_db")
LAST_COMMIT_FILE = Path("last_commit.txt")


def download_and_extract_zip():
    print("[*] First run: downloading ZIP archive...")
    zip_path = Path("cvelistV5-main.zip")

    try:
        response = requests.get(CVE_ZIP_URL, stream=True)
        with open(zip_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(".")
        os.rename("cvelistV5-main", CVE_DIR)
        zip_path.unlink()
        print("[+] Extracted ZIP to cve_db")

    except Exception as e:
        print(f"[-] Failed to download/unzip: {e}")
        exit(1)


def setup_git_repo():
    """Initialize Git repo inside cve_db folder"""
    print("[*] Initializing Git repository from ZIP data...")

    try:
        repo = Repo.init(CVE_DIR)

        origin = repo.create_remote('origin', CVE_REPO_URL)
        origin.fetch()

        # Force add all files to index
        repo.git.add(all=True)
        repo.index.commit("Initial commit from ZIP import")

        # Force checkout main branch
        try:
            repo.git.checkout("main", "--force")
        except:
            # Fallback if main doesn't exist yet
            repo.create_head('main', origin.refs.main).set_tracking_branch(origin.refs.main).checkout()

        # Save current commit hash
        with open(LAST_COMMIT_FILE, "w") as f:
            f.write(repo.head.commit.hexsha)

        print("[+] Git repo initialized successfully.")

    except Exception as e:
        print(f"[-] Git initialization failed: {e}")
        exit(1)


def update_cve_repo(force_update=False):
    """
    Update CVE database using Git.
    Returns True if updated, False otherwise
    """
    if not CVE_DIR.exists():
        download_and_extract_zip()
        setup_git_repo()
        return True

    repo = Repo(CVE_DIR)
    origin = repo.remotes.origin
    origin.fetch()

    current_commit = repo.head.commit.hexsha
    if force_update:
        print("[*] Pulling latest updates via Git...")
        origin.pull()

    new_commit = repo.head.commit.hexsha
    if current_commit == new_commit:
        print("[=] No new CVE updates.")
        return False
    else:
        print(f"[+] Updated from {current_commit[:8]} to {new_commit[:8]}")
        with open(LAST_COMMIT_FILE, "w") as f:
            f.write(new_commit)
        return True
