<div align="center">

```
██████╗ ██╗  ██╗████████╗██████╗  ██████╗ ███╗   ██╗
██╔══██╗██║  ██║╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
██████╔╝███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║
██╔═══╝ ╚════██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║
██║          ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
╚═╝          ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
      ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗
      ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝
      ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗
      ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝
      ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗
       ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝
```

**Advanced Web Vulnerability Scanner**  
`XSS` · `SQL Injection` · `LFI` · `Recursive Crawler` · `Telegram Alerts`

![Python](https://img.shields.io/badge/Python-3.10%2B-red?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-white?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-red?style=flat-square)

</div>

---

> ⚠️ **DISCLAIMER — READ BEFORE USE**
>
> P4TRON-Ultimate is developed strictly for **authorized penetration testing**, **CTF competitions**, and **educational research**. Running this tool against systems without **explicit written permission** from the owner is **illegal** and may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws in your jurisdiction. The authors assume **zero liability** for any misuse or damage caused by this tool. **You are solely responsible for your actions.**

---

## Features

| Feature | Description |
|---|---|
| 🕷️ **Recursive Crawler** | Scope-constrained link discovery up to configurable depth |
| 💉 **XSS Scanner** | Reflected XSS detection via polyglot & standard payloads |
| 🗃️ **SQLi Scanner** | Error-based SQL injection across GET params & POST forms |
| 📂 **LFI Scanner** | Local File Inclusion detection with path traversal variants |
| 🔀 **Thread Pool** | `concurrent.futures.ThreadPoolExecutor` for high-speed scanning |
| 🎭 **UA Rotation** | Random User-Agent per request for basic evasion |
| 📲 **Telegram Alerts** | Real-time push notifications on vulnerability discovery |
| 📝 **Timestamped Logs** | All findings saved to `scan_results.txt` |

---

## Installation

**Requirements:** Python 3.10+

```bash
# 1. Clone the repository
git clone https://github.com/Patr10on/Advanced-Web-Vuln-Scanner
cd Advanced-Web-Vuln-Scanner

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate.bat      # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Help Menu

```bash
python p4tron.py --help
```

### Standard Scan

```bash
python p4tron.py -u https://target.example.com
```

### High-Performance Scan (20 threads, depth 4)

```bash
python p4tron.py -u https://target.example.com -t 20 --depth 4
```

### Scan with Telegram Alerts

```bash
python p4tron.py -u https://target.example.com \
    --telegram-token 123456789:AABBccDDeeFFggHH \
    --telegram-chat-id 987654321
```

### Custom Output File

```bash
python p4tron.py -u https://target.example.com -o my_audit.txt
```

### Full Options Reference

```
usage: p4tron [-h] -u URL [-t THREADS] [--depth DEPTH] [--max-urls MAX_URLS]
              [-o OUTPUT] [--telegram-token TOKEN] [--telegram-chat-id CHAT_ID]

options:
  -h, --help                 show this help message and exit
  -u, --url URL              Target URL (e.g. https://example.com)
  -t, --threads THREADS      Number of threads (default: 10)
  --depth DEPTH              Crawler depth (default: 3)
  --max-urls MAX_URLS        Max URLs to crawl (default: 500)
  -o, --output OUTPUT        Output log file (default: scan_results.txt)
  --telegram-token TOKEN     Telegram Bot API token
  --telegram-chat-id CHAT_ID Telegram Chat ID
```

---

## Setting Up Telegram Alerts

1. Open Telegram → search `@BotFather` → `/newbot`
2. Copy the **API Token** provided
3. Start a chat with your bot, then get your **Chat ID** via:
   ```
   https://api.telegram.org/bot<TOKEN>/getUpdates
   ```
4. Pass both values via CLI flags as shown above.

---

## Project Structure

```
P4TRON-Ultimate/
├── p4tron.py           # Main scanner engine
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── .gitignore          # Git ignore rules
```

---

## Detection Capabilities

| Vulnerability | Method | Detection Signal |
|---|---|---|
| Reflected XSS | GET params + POST forms | Payload reflected in response body |
| SQL Injection | GET params + POST forms | Known DB error strings in response |
| LFI | GET params + POST forms | `/etc/passwd`, `root:x:` signatures |

---

## License

GNU GPLv3 License — see `LICENSE` for details.

---

<div align="center">
  Made for the security research community. <strong>Hack responsibly.</strong>
</div>
