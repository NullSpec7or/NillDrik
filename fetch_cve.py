import os
from pathlib import Path
from git import Repo, GitCommandError
import shutil

CVE_REPO_URL = "https://github.com/CVEProject/cvelistV5.git" 
CVE_DIR = Path("cve_db")
LAST_COMMIT_FILE = Path("last_commit.txt")


def clone_full_github_repo():
    """
    Perform a full Git clone of the CVE repository.
    Returns True if successful.
    """
    print("[*] Initializing CVE database ...")
    
    if CVE_DIR.exists():
        print(f"[*] Removing existing {CVE_DIR} directory...")
        shutil.rmtree(CVE_DIR)

    try:
        # Full clone with complete history
        repo = Repo.clone_from(
            CVE_REPO_URL,
            CVE_DIR,
        )
        print("[+] Successfully cloned full CVE repository.")

        # Save commit hash
        commit_hash = repo.head.commit.hexsha
        with open(LAST_COMMIT_FILE, "w") as f:
            f.write(commit_hash)
        print(f"[+] Commit hash saved: {commit_hash[:12]}")

        return True

    except Exception as e:
        print(f"[-] Failed to fetch the CVE Repository: {e}")
        return False


def update_cve_repo(force_update=False):
    """
    Update the local CVE repo using Git.
    Returns True if updated, False otherwise
    """
    print("[*] Updating CVE repo...")

    if not CVE_DIR.exists():
        print("[*] CVE database not found. Cloning repo ...")
        success = clone_full_github_repo()
        if not success:
            print("[-] Failed to initialize CVE database.")
            return False
        return True

    try:
        repo = Repo(CVE_DIR)

        # Ensure origin remote exists
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
        origin.pull('main')

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
