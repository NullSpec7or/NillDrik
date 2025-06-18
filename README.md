|| Om Shri Hari ||

# 🩸 NillDrik – The Seer from Niladri

> *"Where the sacred eye rests, shadows in code unravel."*  
> A CVE scanner that peers into the darkness of your dependencies.

---

## 🔍 Overview

**NillDrik** is a powerful and lightweight tool designed to scan your installed software packages against known Common Vulnerabilities and Exposures (CVEs). Built with precision, it leverages local SQLite databases of CVE data to provide fast and accurate vulnerability detection without relying on external APIs.

This tool was created by [@Null Spec7or](https://twitter.com/nullspec7or) and is ideal for penetration testing, red teaming, or simply keeping your systems secure.

---

## 🧰 Features

- ✅ CVE scanning of locally installed packages
- 📦 Automatic normalization of package names and versions
- 🗃️ Local SQLite-based CVE database for speed and offline usage
- 🔄 Full support for updating CVE data from official sources
- 📄 Generate reports in multiple formats: JSON, CSV, TXT, HTML
- 🗂️ Supports filtering by minimum CVE year
- 💻 Debug mode for advanced diagnostics

---

## 🧑‍💻 Code Authors

- **Rupesh Kumar (@Null Spec7or)** <br>
  Linkdein: https://www.linkedin.com/in/rupeshkumar33 <br>
  Twitter: [@nullspec7or](https://twitter.com/nullspec7or)  
  GitHub: [github.com/NullSpec7or](https://github.com/NullSpec7or)

---

## 🛠 Requirements

Make sure you have the following installed:

- Python 3.8+
- Git (for fetching CVE data)
- `sqlite3` (comes pre-installed with Python)

---

## 📦 Installation

```bash
git clone https://github.com/NullSpec7or/NillDrik.git
cd nilldrik
pip install -r requirements.txt
```


---

## ⚙️ Usage

### First Scan

For the first scan , it is required to run this command in order to build your local CVE DB. This process can take anywhere between 18-40 minutes on first run. Subsequent scans are expected to complete under 20 minutes , however, this depends upon the system which is being scanned. 

```bash
python3 nilldrik.py --update --update-db 
```
### Basic Scan

```bash
python nilldrik.py
```

### Options

| Flag              | Description                                      |
|-------------------|--------------------------------------------------|
| `--update`        | Update the local CVE repository before scanning  |
| `--update-db`     | Rebuild the SQLite CVE database                  |
| `--format [json/csv/txt/html/all]` | Set output format for the report |
| `--min-cve-year Y`| Only match CVEs from year Y or newer             |
| `--debug`         | Enable debug output                              |

### Example Commands

Update CVE database and rebuild SQLite:

```bash
python nilldrik.py --update --update-db
```

Run a scan and generate all report types:

```bash
python nilldrik.py --format all --min-cve-year 2020
```

---

## 📁 Output

The final report will be saved in the NillDrik's-Report's directory in the specified format(s):

- `cve_report.json`
- `cve_report.csv`
- `cve_report.txt`
- `cve_report.html`

Also, any invalid conditions found during matching will be saved in `invalid_conditions.log`.

---

## 📁 Project Structure

```
nilldrik/
├── fetch_cve.py           # Fetches raw CVE data
├── import_cves.py         # Imports CVE data into SQLite
├── query_cves.py          # Scans SQLite DB for matches
├── normalize_packages.py  # Normalizes package names and versions
├── nilldrik.py            # Main script
└── requirements.txt       # Python dependencies
```

---

## 📜 License

This project is licensed under the **Apache 2.0 License**. See `LICENSE` for more details.

---

## 🌟 Acknowledgments

- CVE data sourced from public repositories and MITRE.
- Inspired by tools like `cvechecker`, `pkgscan`, and `CVE-bin-tool`.

---

## 📬 Feedback & Contributions

Feel free to open issues or PRs! Your feedback helps make **NillDrik** stronger.

---

# 🩸 Let the Seer guide your path through vulnerabilities.

> "In code as in life, the unseen may harm the most."

--- 
