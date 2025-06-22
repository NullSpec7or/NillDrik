
# 🔮NillDrik – The Seer from Niladri

> *"Where the sacred eye rests, shadows in code unravel."*  
A CVE scanner built with precision — designed to peer into the darkness of software dependencies.


## 🌟 About

![NillDrik Logo](assets/logo.png)


**NillDrik** is an advanced static vulnerability scanner that identifies known security flaws (CVEs) in installed packages across major Linux distributions. It operates entirely offline using a locally built SQLite database, making it fast, secure, and ideal for red teaming, penetration testing, and system hardening.

Crafted by [Rupesh Kumar (@Null Spec7or)](https://twitter.com/nullspec7or), NillDrik brings clarity to chaos—detecting vulnerabilities before they become exploits.

---

## 🛠 Key Features

| Feature               | Description                                      |
|------------------------|--------------------------------------------------|
| 🔍 CVE Detection       | Matches installed packages against known CVEs   |
| 🗃️ Offline Database     | Uses SQLite for fast, API-free scanning          |
| 🔄 Auto-Update Support | Fetches latest CVE data from upstream sources   |
| 🧹 Smart Cleanup        | Deletes temporary files after scan (optional)   |
| 📄 Multi-format Output  | Supports JSON, CSV, TXT, HTML, or all formats   |
| 🧪 Debug Mode           | Helps in diagnosing issues during matching      |
| 📅 Year Filtering       | Scan only relevant CVEs using year-based filters|

---

## 👤 Author

- **Rupesh Kumar** ([@Null Spec7or](https://twitter.com/nullspec7or))  
  - GitHub: [@NullSpec7or](https://github.com/NullSpec7or)  
  - LinkedIn: [Connect with me on LinkedIn](https://www.linkedin.com/in/rupeshkumar33)

> "Niladri sees all — even what hides in code."

---

## 📦 Supported Distributions

NillDrik supports automatic package detection for:

- 🐧 **Debian / Ubuntu**
- 🐘 **Red Hat / Fedora**
- 🏆 **Arch Linux**

Custom plugin support for others coming soon.

---

## ⚙️ Installation

```bash
git clone https://github.com/NullSpec7or/NillDrik.git
cd NillDrik
pip install -r requirements.txt
Python3 nilldrik.py
````

✅ Ensure `git`, `sqlite3`, and Python ≥ 3.8 are installed.

---

## 🚀 Quick Start

### 🔧 First-Time Setup

```bash
python3 nilldrik.py --update --update-db
```

* Pulls latest CVEs from [cvelistV5](https://github.com/CVEProject/cvelistV5)
* Builds an optimized local CVE SQLite DB

### 📊 Run a Basic Scan with reports saved in different formats

```bash
python3 nilldrik.py --format all
```

* Scans installed packages
* Compares with CVE database
* Generates report (default: `JSON`)

---

## 🧾 CLI Options

| Flag             | Description                                                |
| ---------------- | ---------------------------------------------------------- |
| `--update`       | Update CVE data from upstream GitHub repo                  |
| `--update-db`    | Rebuild the local SQLite CVE database                      |
| `--format`       | Output formats: `json`, `csv`, `txt`, `html`, `all`        |
| `--min-cve-year` | Filter CVEs from specific year onward                      |
| `--debug`        | Enable verbose output for troubleshooting                  |
| `--keepfiles`    | Retain temporary files like `installed_packages.txt`, etc. |

---

## 📁 Output Reports

Stored in `NillDrik-Reports/`:

* `cve_report.json`
* `cve_report.csv`
* `cve_report.txt`
* `cve_report.html`

Also generates:

* `invalid_conditions.log` – logs skipped CVEs with unsupported version formats

---

## 🧱 Project Structure

```
NillDrik/
├── fetch_cve.py           # Pulls CVE data from GitHub
├── import_cves.py         # Parses CVE and loads to DB
├── query_cves.py          # Scans installed packages
├── normalize_packages.py  # Normalizes package names for matching
├── nilldrik.py            # Main execution script
├── requirements.txt       # Python dependencies
└── last_commit.txt        # Tracks last pull commit hash
```


## 🩸 Let the Seer guide your path through vulnerabilities.

> "In code as in life, the unseen may harm the most."


## 🤝 Contributing

You're welcome to contribute! ✨

Suggestions:

* Add more distro support
* Improve CVE parsing heuristics
* Build integrations (e.g., Slack, Teams, SIEM)
* Extend functionality to Docker images

## First Run (Initial Setup)
```bash
python3 nilldrik.py --debug --keepfiles --format all
```
## Subsequent Runs 
```bash
nilldrik.py [-h] [--update] [--update-db] [--format {json,csv,txt,html,all}] [--min-cve-year MIN_CVE_YEAR] [--debug] [--keepfiles]
```

Open issues or submit pull requests anytime!


## 📬 Feedback & Contact

* 📧 Email: [nullspec7or@gmail.com](mailto:nullspec7or@gmail.com)
* 🐦 Twitter: [@nullspec7or](https://twitter.com/nullspec7or)

---

## 📜 License

Licensed under **Apache License 2.0**
See `LICENSE` for full details.
