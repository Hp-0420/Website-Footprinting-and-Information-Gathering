# 🌐 Website Footprinting and Information Gathering

This project demonstrates how to perform **passive and active reconnaissance** on a target website using ethical and legal methods. It helps cybersecurity students and professionals understand what information is publicly available and how attackers might use it during the initial phases of a cyber attack.

---

## 📌 Features

- WHOIS lookup
- DNS record enumeration
- Subdomain discovery
- Port scanning (Nmap wrapper)
- HTTP headers & server fingerprinting
- Directory bruteforcing (basic wordlist-based)
- Technologies used on the site (via Wappalyzer API)
- Screenshot capture of target page
- Report generation in text/HTML

---

## 🧰 Tools & Technologies Used

- Python 3.x
- `whois` Python module
- `socket` and `dns.resolver` (for DNS queries)
- `requests`, `http.client`, `urllib`
- `nmap` (with `python-nmap`)
- `subprocess` (to run tools like `nslookup`, `dig`)
- `Shodan` API *(optional)*
- `Wappalyzer` API *(optional)*

---

## 🚀 Getting Started

### 🔧 Prerequisites

- Python 3.8+
- Linux/macOS/Windows
- Nmap installed
- `pip install -r requirements.txt`

### 📦 Installation

```bash
git clone https://github.com/yourusername/website-footprinting.git
cd website-footprinting
pip install -r requirements.txt
````

---

## 🧪 Usage

```bash
python footprinting.py --target example.com
```

### 🔍 Sample Output

```
[*] WHOIS Info:
    Domain Name: example.com
    Registrar: XYZ Registrar
    ...

[*] DNS Records:
    A Record: 93.184.216.34
    MX Record: mail.example.com

[*] Subdomains:
    blog.example.com
    shop.example.com

[*] Open Ports (Top 1000):
    80/tcp - HTTP
    443/tcp - HTTPS

[*] HTTP Headers:
    Server: Apache/2.4.41
    X-Powered-By: PHP/7.4.3

[*] Directories Found:
    /admin/
    /login/
    /uploads/

[*] Technologies Detected:
    - WordPress
    - Google Analytics

[*] Screenshot captured: reports/example.com/screenshot.png
```

---

## 📁 Project Structure

```
website-footprinting/
├── footprinting.py
├── subdomain_finder.py
├── dns_lookup.py
├── port_scanner.py
├── dir_bruteforce.py
├── whois_lookup.py
├── wappalyzer_api.py
├── report_generator.py
├── utils/
│   └── logger.py
├── wordlists/
│   └── common_dirs.txt
├── reports/
│   └── example.com/
├── requirements.txt
└── README.md
```

---

## ✅ Legal Disclaimer

This project is for **educational purposes only**. Do not use these techniques on websites you don’t own or have explicit permission to test. Unauthorized scanning and probing is illegal.

---

## 🤝 Contributing

Contributions, suggestions, and improvements are welcome! Feel free to fork the repo and submit a pull request.

---

## 📜 License

This project is licensed under the MIT License.

````
### 🛠 Sample Python Script Snippets (Mini Example)

**whois_lookup.py**
```python
import whois

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return str(e)
````

**port\_scanner.py**

```python
import nmap

def scan_ports(domain):
    nm = nmap.PortScanner()
    nm.scan(domain, '1-1000')
    return nm[domain].all_protocols()
```

**dir\_bruteforce.py**

```python
import requests

def bruteforce_dirs(domain, wordlist):
    found = []
    for word in open(wordlist):
        url = f"http://{domain}/{word.strip()}/"
        r = requests.get(url)
        if r.status_code == 200:
            found.append(url)
    return found
