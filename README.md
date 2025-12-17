# NetObserver

**Defensive Network Visibility & Incident Response Tool**

NetObserver is a **PyQt6-based graphical application** for **authorized, defensive network monitoring**, incident response, and forensic triage. It provides real-time visibility into network activity, highlights suspicious patterns, and helps security practitioners investigate potential threats — without offensive or intrusive capabilities.

![netobserver1](https://github.com/user-attachments/assets/aa1cf80c-b4e9-43ba-b08c-2ea6a669b5a0)

---

## 🚨 Legal & Ethical Notice

> **Authorization is mandatory.**

NetObserver **must only be used on networks you own or have explicit written permission to monitor**.

* Designed **strictly for defensive security** (blue team, IR, forensics)
* No exploitation, evasion, or offensive tooling
* No packet injection or active manipulation
* Users are solely responsible for complying with local laws and regulations

If you are unsure whether you are authorized — **do not use this tool**.

---

## 🎯 Purpose & Use Cases

NetObserver is built to support:

* Incident response and threat investigation
* Network traffic visibility during security events
* Forensic triage using live traffic or PCAP files
* Detection of anomalous or suspicious network behavior
* SOC-style monitoring in small to medium environments

It focuses on **metadata analysis and heuristics**, not deep packet exploitation.

---

## ✨ Key Features

* **Real-Time Network Monitoring**
  Capture traffic from live interfaces or replay PCAP files

* **Protocol Awareness**
  Metadata parsing for common protocols (DNS, HTTP, TLS, SSH, DHCP, SMB, etc.)

* **Heuristic Threat Detection**
  Detects suspicious patterns such as:

  * Port scanning behavior
  * Traffic spikes
  * DNS anomalies
  * Suspicious service ports

* **Visual Alert System**
  Color-coded alerts with severity levels (Low → Critical)

* **Whitelist System**
  Reduce noise by safely suppressing known-benign alerts (with audit trail)

* **Dark-Themed GUI**
  Designed for long-running monitoring and SOC-style environments

* **PCAP Export**
  Save captured traffic for offline forensic analysis

---

## 🧰 System Requirements

### Minimum

* Python **3.8+**
* 4 GB RAM
* Linux, macOS, or Windows

### Recommended

* Python **3.10+**
* 8 GB RAM
* Linux (best capture support)

### Optional Dependencies

* `pyshark` – advanced packet parsing
* `scapy` – extended packet inspection

> ⚠️ Live capture may require **root/admin privileges** or `CAP_NET_RAW` capability.

---

## 📦 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/MonarchoftheShadows/NetObserver.git
cd NetObserver
```

### 2. Create a Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate     # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run NetObserver

```bash
python run.py
```

---

## 🔐 Running with Capture Permissions (Linux)

### Option 1: Run as root (not recommended for development)

```bash
sudo python run.py
```

### Option 2: Grant CAP_NET_RAW (recommended)

```bash
sudo setcap cap_net_raw+ep $(which python3)
python run.py
```

This allows packet capture **without running the entire app as root**.

---

## 🗂 Project Structure

```text
NetObserver/
├─ run.py                  # Application entry point
├─ requirements.txt
├─ docs/
│  └─ USAGE.md             # Detailed user documentation
├─ core/                   # Core application logic
├─ capture/                # Network capture backends
├─ parsers/                # Protocol parsers (metadata-only)
├─ analytics/              # Heuristics & alert engine
├─ storage/                # Database & PCAP handling
└─ ui/                     # PyQt6 user interface
```

---

## ⚙️ Configuration & Data Storage

On first run, NetObserver creates a configuration directory:

```text
~./NetObserver/configs/
├─ config.json             # Application settings
├─ keys.json               # API keys (permissions: 0600)
├─ netgui.db               # SQLite events & alerts database
├─ whitelist.json          # Alert whitelist rules
├─ whitelist_audit.log     # Whitelist change history
└─ logs/                   # Application logs
```

No raw packet payloads are stored by default.

---

## 📘 Usage Documentation

For full usage instructions, UI walkthroughs, alert explanations, and whitelist management, see:

📄 **[docs/USAGE.md](docs/USAGE.md)**

---

## 🛡 Security Design Principles

* Passive, read-only monitoring
* Metadata-focused parsing
* No packet crafting or injection
* Clear audit trails for whitelist actions

NetObserver is intentionally **not stealthy** and **not offensive**.

---

## 🧪 Development & Contributions

Contributions are welcome — especially for:

* New protocol parsers (defensive only)
* Improved heuristics
* Performance optimizations
* UI/UX improvements
* Documentation

### Contribution Guidelines

* Maintain defensive-only scope
* Include docstrings and comments
* Avoid introducing active network behavior
* Update documentation when adding features

---

## 📞 Support

- **Issues**: Report bugs and request features via GitHub Issues or Email: RealEnemyintheMirror@proton.me
- **Documentation**: Additional documentation available in `docs/` directory
- **Community**: Join our Discord server for discussions and support

---

## 📜 License

NetObserver is released under the **GNU General Public License (GPL)**.

* You are free to use, modify, and distribute this software
* Derivative works **must remain open-source under the GPL**
* There is **no warranty** of any kind


---

## ⚠️ Disclaimer

This software is provided **"as is"**, without warranty of any kind. The authors are **not responsible for misuse**, legal violations, or damages resulting from improper or unauthorized use.

**Always obtain proper authorization before monitoring any network.**


