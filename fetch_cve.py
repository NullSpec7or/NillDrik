# fetch_cve.py

import os
import zipfile
import requests
from pathlib import Path
from git import Repo, GitCommandError


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
        print("[+] Extracted ZIP to temporary folder")

        extracted_dir = Path("cvelistV5-main")
        target_cves = CVE_DIR / "cves"

        # Move cves folder into place
        source_cves = extracted_dir / "cves"
        if source_cves.exists():
            os.rename(source_cves, target_cves)
        else:
            target_cves.mkdir(exist_ok=True)
            for file in extracted_dir.glob("*.json"):
                os.rename(file, target_cves / file.name)

        zip_path.unlink()
        os.rmdir(extracted_dir)

        print("[+] CVE data moved to cve_db/cves/")
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

        repo.git.add(all=True)
        repo.index.commit("Initial commit from ZIP import")

        # Create main branch and track origin/main
        if 'main' in [head.name for head in repo.heads]:
            repo.git.checkout("main", "--force")
        else:
            repo.git.checkout("-b", "main", f"origin/main")

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
    print("[*] Updating CVE repo...")

    if not CVE_DIR.exists():
        download_and_extract_zip()
        setup_git_repo()
        return True

    try:
        repo = Repo(CVE_DIR)

        if 'origin' not in [remote.name for remote in repo.remotes]:
            repo.create_remote('origin', CVE_REPO_URL)

        origin = repo.remotes.origin
        origin.fetch()

        current_commit = repo.head.commit.hexsha

        if not force_update:
            remote_commit = origin.refs.main.commit.hexsha
            if current_commit == remote_commit:
                print("[=] Already up-to-date.")
                return False

        print("[*] Pulling latest updates via Git...")
        repo.git.reset('--hard')
        repo.git.clean('-xdf')
        repo.git.fetch('origin', 'main', depth=1)
        repo.git.reset('--hard', 'origin/main')

        new_commit = repo.head.commit.hexsha
        print(f"[+] Updated from {current_commit[:8]} to {new_commit[:8]}")

        with open(LAST_COMMIT_FILE, "w") as f:
            f.write(new_commit)

        return True

    except GitCommandError as e:
        print(f"[-] Git operation failed: {e}")
        return False
    except Exception as e:
        print(f"[-] Error during update: {e}")
        return False
