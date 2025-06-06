import requests
import random
import qrcode
import io
import os
import ssl
import socket
from datetime import datetime, UTC
import re
import whois
from urllib.parse import urlparse, quote
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from pystyle import Colors, Colorate, Center
from concurrent.futures import ThreadPoolExecutor, as_completed 

user_agents = [
    "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17",
    "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4",
    "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4",
    "Mozilla/5.0 (Windows NT 6.1; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/600.6.3 (KHTML, like Gecko) Version/8.0.6 Safari/600.6.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/600.5.17 (KHTML, like Gecko) Version/8.0.5 Safari/600.5.17",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.203",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.5; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A736B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-T870) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-T720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.1.3035.111",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 EdgA/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Whale/3.21.192.18 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPX/120.0.0.0"
]

shorteners = [
    "https://tinyurl.com/api-create.php?url=",
    "https://is.gd/create.php?format=simple&url=",
    "https://v.gd/create.php?format=simple&url=",
    "https://cleanuri.com/api/v1/shorten?url=",
    "https://cutt.ly/api/api.php?short=",
    "https://clck.ru/--?url=",
    "https://tny.im/yourls-api.php?url=",
    "https://shorturl.at/api?url=",
    "https://0rz.tw/create.php?url=",
    "https://shrtco.de/api/v2/shorten?url=",
    "https://ulvis.net/api.php?url=",
    "https://ln.run/api?url=",
    "https://chilp.it/api.php?url=",
    "https://short.cm/api/shorten?url=",
    "https://s.id/api/public/link/shorten?url=",
    "https://t.ly/api/v1/link/shorten?url=",
    "https://linklyhq.com/link/api?url=",
    "https://urlzs.com/api.php?url=",
    "https://tiny.cc/?c=rest_api&m=shorten&version=2.0.3&longUrl=",
    "https://api.wee.ink/shorten?url=",
    "https://da.gd/s?url=",
    "https://short.fyi/api?link=",
    "https://0x0.st",
    "https://ttm.sh"
]


def banner():
    text = r"""
 _   _ ____  _     _  ___ _
| | | |  _ \| |   | |/ (_) |_
| | | | |_) | |   | ' /| | __|
| |_| |  _ <| |___| . \| | |_
 \___/|_| \_\_____|_|\_\_|\__|

Made by Blurredness/PA3MblTOCTb
TGC: t.me/Blurredness (russian language only)
Use VPN for security and less blockings
Enjoy <3
"""
    print(Colorate.Horizontal(Colors.blue_to_purple, Center.XCenter(text)))



def generate_qr():
    url = input("Enter URL to generate QR Code: ")
    while True:
        save_mode = input("Save to script path or custom path? (s/c): ").strip().lower()
        if save_mode in ["s", "script", "script path"]:
            save_path = os.getcwd()
            break
        elif save_mode in ["c", "custom", "custom path", "my path"]:
            custom = input("Enter full folder path to save QR Code: ").strip()
            if os.path.isdir(custom):
                save_path = custom
                break
            else:
                print("Invalid path. Try again.")
        elif save_mode in ["q", "b", "quit", "back"]:
            return
        elif save_mode == "":
            continue
        else:
            print("Invalid input. Try again.")

    img = qrcode.make(url)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    filename = f"qrcode_{random.randint(1000,9999)}.png"
    full_path = os.path.join(save_path, filename)
    with open(full_path, "wb") as f:
        f.write(buffer.getvalue())
    print(Colorate.Horizontal(Colors.green_to_white, f"QR Code saved as: {full_path}"))




def shorten_url(user_agents, shorteners):
    url = input("Enter URL to shorten: ").strip()
    if not url.startswith("http"):
        url = "http://" + url

    headers = {"User-Agent": random.choice(user_agents)}
    random.shuffle(shorteners)

    for endpoint in shorteners:
        try:
            if callable(endpoint):
                full_url = endpoint(url)
                if "0x0.st" in full_url or "ttm.sh" in full_url:
                    response = requests.post(full_url, data={'url': url}, headers=headers, timeout=7)
                    short = response.text.strip()
                else:
                    response = requests.get(full_url, headers=headers, timeout=7)
                    short = response.text.strip()
            else:
                full_url = endpoint + url
                response = requests.get(full_url, headers=headers, timeout=7)
                short = response.text.strip()

            if short.startswith("http") and "<html" not in short.lower():
                print(Colorate.Horizontal(Colors.green_to_blue, f"\nShortened: {short}"))
                break
        except Exception:
            continue
    else:
        print(f"{Fore.RED}[!] Failed to shorten URL with all services.{Style.RESET_ALL}")





def expand_url(user_agents):
    url = input("Enter shortened URL to expand: ").strip()
    if not url.startswith("http"):
        url = "http://" + url

    headers = {"User-Agent": random.choice(user_agents)}

    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        final_url = response.url

        if final_url.startswith("http"):
            print(Colorate.Horizontal(Colors.green_to_blue, f"\nExpanded URL: {final_url}"))
        else:
            print(f"{Fore.RED}[!] Unable to resolve final URL.{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")




def check_phishing_url(user_agents):
    url = input("Enter URL to scan: ").strip()
    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    print(f"\nAnalyzing: {domain}")

    suspicious_signs = []

    if not url.startswith("https://"):
        suspicious_signs.append("No HTTPS")

    if "@" in domain:
        suspicious_signs.append("Contains @ symbol")

    if "xn--" in domain:
        suspicious_signs.append("Punycode (possible Unicode spoofing)")

    if domain.count("-") > 3:
        suspicious_signs.append("Too many hyphens in domain")

    if domain.endswith((".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".py", ".zip", ".click", ".top", ".monster")):
        suspicious_signs.append(f"Suspicious TLD: .{domain.split('.')[-1]}")

    if len(domain.split(".")) >= 4:
        suspicious_signs.append("Too many subdomains")

    if len(domain) < 5:
        suspicious_signs.append("Domain is too short")
    if len(domain) > 50:
        suspicious_signs.append("Domain is very long")

    print("\nHeuristic Analysis:")
    if suspicious_signs:
        for sign in suspicious_signs:
            print(f"  [-] {sign}")
    else:
        print("  [+] No immediate red flags.")

    print("\nSSL Certificate Check:")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])['organizationName']
                valid_from = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                valid_to = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                now = datetime.now(UTC)

                print(f"  Issuer      : {issuer}")
                print(f"  Valid From  : {valid_from}")
                print(f"  Valid Until : {valid_to}")

                if now < valid_from or now > valid_to:
                    print("  [!] Certificate expired or not yet valid")
                else:
                    print("  [+] Certificate is valid")
    except Exception as e:
        print(f"  [!] Failed to retrieve SSL info: {e}")

    print("\nPhishTank Check:")
    try:
        r = requests.get("https://checkurl.phishtank.com/checkurl/", params={"url": url, "format": "json"}, headers={"User-Agent": random.choice(user_agents)})
        if "phish" in r.text.lower():
            print("  [!] Reported phishing match found")
        else:
            print("  [+] No match in PhishTank")
    except:
        print("  [!] Failed to query PhishTank")

    print("\nExternal Sources for Manual Check:")
    print(f"  URLScan           → https://urlscan.io/search/#url:{domain}")
    print(f"  Google SafeReport → https://transparencyreport.google.com/safe-browsing/search?url={domain}")
    print(f"  ScamAdviser       → https://www.scamadviser.com/check-website/{domain}")



def redirect_chain(user_agents):
    url = input("Enter URL to trace redirects: ").strip()
    if not url.startswith("http"):
        url = "http://" + url

    headers = {"User-Agent": random.choice(user_agents)}

    try:
        r = requests.get(url, headers=headers, timeout=10, allow_redirects=True)

        print(f"\n{Colorate.Horizontal(Colors.cyan_to_blue, 'Redirect Chain:')}\n")
        if r.history:
            for i, step in enumerate(r.history):
                code = step.status_code
                loc = step.headers.get("Location", step.url)
                print(f"  [{i}] {Fore.YELLOW}{step.url}{Style.RESET_ALL} → ({code})")
            print(f"\n  [Final] {Fore.GREEN}{r.url}{Style.RESET_ALL} ← ({r.status_code})")
        else:
            print(f"  No redirects. Final URL: {Fore.GREEN}{r.url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")



def find_admin_panels(user_agents):
    base = input("Enter base URL (e.g. https://example.com): ").strip()
    if not base.startswith("http"):
        base = "http://" + base

    print(f"\nScanning common admin/login paths on: {base}\n")

    paths = [
        "admin", "admin/login", "login", "admin.php", "admin.html", "cpanel",
        "wp-admin", "wp-login.php", "dashboard", "user/login", "signin", "backend",
        "manager", "portal", "secure", "adminpanel", "access", "auth", "webadmin"
    ]

    headers = {"User-Agent": random.choice(user_agents)}
    found = []

    for path in paths:
        full_url = f"{base.rstrip('/')}/{path}"
        try:
            r = requests.get(full_url, headers=headers, timeout=7, allow_redirects=False)
            if r.status_code in [200, 301, 302, 401, 403]:
                found.append((full_url, r.status_code))
                color = Fore.GREEN if r.status_code == 200 else Fore.YELLOW
                print(f"{color}[+] {full_url} — {r.status_code}{Style.RESET_ALL}")
        except:
            continue

    if not found:
        print(f"{Fore.RED}[!] No accessible admin/login pages found.{Style.RESET_ALL}")
    else:
        print(Colorate.Horizontal(Colors.green_to_blue, f"\n[+] Total found: {len(found)}"))




def domain_age():
    url = input("Enter URL or domain: ").strip()
    if url.startswith("http"):
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
    else:
        domain = url

    print(f"\nChecking domain: {domain}")

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        registrar = w.registrar or "Unknown"
        country = w.country or "Unknown"

        today = datetime.now(UTC)
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=UTC)

        age_days = (today - creation_date).days

        print(Colorate.Horizontal(Colors.blue_to_cyan, f"\n[+] Domain: {domain}"))
        print(f"    Registrar     : {registrar}")
        print(f"    Country       : {country}")
        print(f"    Created On    : {creation_date.strftime('%Y-%m-%d')}")
        print(f"    Domain Age    : {age_days} days")
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to retrieve WHOIS info: {e}{Style.RESET_ALL}")





def extract_data(user_agents):
    url = input("Enter URL to extract data from: ").strip()
    if not url.startswith("http"):
        url = "http://" + url

    headers = {"User-Agent": random.choice(user_agents)}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        text = soup.get_text()

        print(Colorate.Horizontal(Colors.yellow_to_red, "\n[+] Extracted Data:"))

        emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text))
        phones = set(re.findall(r"(\+?\d[\d\s\-]{7,})", text))
        telegrams = set(re.findall(r"(?:https?://)?t\.me/([a-zA-Z0-9_]{4,})", text))
        usernames = set(re.findall(r"(?<!\w)@([a-zA-Z0-9_]{4,})", text))
        usernames = usernames - {email.split("@")[0] for email in emails}

        instas = set(re.findall(r"(?:https?://)?(?:www\.)?instagram\.com/([a-zA-Z0-9_.]+)", text))
        vk = set(re.findall(r"(?:https?://)?(?:www\.)?vk\.com/([a-zA-Z0-9_.]+)", text))
        fb = set(re.findall(r"(?:https?://)?(?:www\.)?facebook\.com/([a-zA-Z0-9_.]+)", text))
        twitter = set(re.findall(r"(?:https?://)?(?:www\.)?twitter\.com/([a-zA-Z0-9_.]+)", text))

        btc = set(re.findall(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", text))
        eth = set(re.findall(r"\b0x[a-fA-F0-9]{40}\b", text))

        ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
        proxies = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b", text))

        def display(title, data, prefix=""):
            if data:
                print(f"\n  {title}:")
                for item in data:
                    print(f"    {prefix}{item}")

        display("Emails", emails)
        display("Phones", phones)
        display("Telegram", telegrams, "https://t.me/")
        display("Usernames (@)", usernames, "@")
        display("Instagram", instas, "https://instagram.com/")
        display("VK", vk, "https://vk.com/")
        display("Facebook", fb, "https://facebook.com/")
        display("Twitter", twitter, "https://twitter.com/")
        display("Bitcoin Wallets", btc)
        display("Ethereum Wallets", eth)
        display("IP Addresses", ips)
        display("Proxies", proxies)

        if not any([emails, phones, telegrams, usernames, instas, vk, fb, twitter, btc, eth, ips, proxies]):
            print("  No recognizable data found.")

    except Exception as e:
        print(f"{Fore.RED}[!] Failed to extract: {e}{Style.RESET_ALL}")





def preview_meta_extractor(user_agents):
    url = input("Enter URL to preview: ").strip()
    if not url.startswith("http"):
        url = "http://" + url

    headers = {"User-Agent": random.choice(user_agents)}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')

        print(Colorate.Horizontal(Colors.purple_to_blue, "\n[+] Meta Preview:"))

        title = soup.title.string.strip() if soup.title and soup.title.string else "N/A"
        desc = soup.find("meta", attrs={"name": "description"})
        keywords = soup.find("meta", attrs={"name": "keywords"})
        og_title = soup.find("meta", property="og:title")
        og_desc = soup.find("meta", property="og:description")
        og_image = soup.find("meta", property="og:image")
        icon = soup.find("link", rel=lambda x: x and "icon" in x.lower())

        print(f"  Title              : {title}")
        print(f"  Description        : {desc['content'] if desc and 'content' in desc.attrs else 'N/A'}")
        print(f"  Keywords           : {keywords['content'] if keywords and 'content' in keywords.attrs else 'N/A'}")
        print(f"  OG Title           : {og_title['content'] if og_title and 'content' in og_title.attrs else 'N/A'}")
        print(f"  OG Description     : {og_desc['content'] if og_desc and 'content' in og_desc.attrs else 'N/A'}")
        print(f"  OG Image           : {og_image['content'] if og_image and 'content' in og_image.attrs else 'N/A'}")
        print(f"  Favicon            : {icon['href'] if icon and 'href' in icon.attrs else 'N/A'}")

    except Exception as e:
        print(f"{Fore.RED}[!] Failed to extract meta data: {e}{Style.RESET_ALL}")




def wayback_history(user_agents):
    input_url = input("Enter URL or domain to check Wayback history: ").strip()
    if not input_url.startswith("http"):
        full_url = "http://" + input_url
    else:
        full_url = input_url

    parsed = urlparse(full_url)
    cleaned_url = parsed.netloc + parsed.path
    if "/" not in parsed.path:
        cleaned_url += "/*"

    headers = {"User-Agent": random.choice(user_agents)}
    api_url = "http://web.archive.org/cdx/search/cdx"

    try:
        params = {
            "url": cleaned_url,
            "output": "json",
            "fl": "timestamp,original",
            "collapse": "timestamp"
        }
        r = requests.get(api_url, headers=headers, params=params, timeout=10)
        if not r.text.strip():
            raise ValueError("Empty response from Wayback Machine")

        data = r.json()
        if len(data) <= 1:
            raise ValueError("No snapshots found")

        snapshots = data[1:]
        first = snapshots[0][0]
        last = snapshots[-1][0]

        first_link = f"https://web.archive.org/web/{first}/{full_url}"
        last_link = f"https://web.archive.org/web/{last}/{full_url}"

        print(Colorate.Horizontal(Colors.blue_to_purple, f"\n[+] Wayback Machine Results for: {parsed.netloc}"))
        print(f"    First snapshot : {first[:4]}-{first[4:6]}-{first[6:8]} → {first_link}")
        print(f"    Last snapshot  : {last[:4]}-{last[4:6]}-{last[6:8]} → {last_link}")
        print(f"    Total snapshots: {len(snapshots)}")

    except Exception:
        fallback = f"https://web.archive.org/web/*/{parsed.netloc}"
        print(f"{Fore.YELLOW}[!] No direct snapshot data available.{Style.RESET_ALL}")
        print(Colorate.Horizontal(Colors.white_to_red, f"\n[→] View manually: {fallback}"))




def domain_reputation(user_agents):
    url = input("Enter URL or domain to check reputation: ").strip()
    if url.startswith("http"):
        parsed = urlparse(url)
        domain = parsed.netloc
    else:
        domain = url

    print(f"\nChecking domain reputation: {domain}\n")

    
    print(Colorate.Horizontal(Colors.red_to_yellow, "[+] PhishTank Check:"))
    try:
        phish_url = f"https://checkurl.phishtank.com/checkurl/"
        headers = {"User-Agent": random.choice(user_agents)}
        params = {
            "url": f"http://{domain}",
            "format": "json"
        }
        response = requests.get(phish_url, headers=headers, params=params, timeout=10)
        if "phish" in response.text.lower():
            print(f"    [!] Reported phishing domain")
        else:
            print(f"    [+] No match found in PhishTank")
    except Exception as e:
        print(f"    [!] Error checking PhishTank: {e}")

    
    print(Colorate.Horizontal(Colors.red_to_yellow, "\n[+] AbuseIPDB (via resolved IP):"))
    try:
        ip = socket.gethostbyname(domain)
        print(f"    Resolved IP      : {ip}")
        print(f"    Lookup AbuseIPDB : https://www.abuseipdb.com/check/{ip}")
    except Exception as e:
        ip = None
        print(f"    [!] Failed to resolve IP: {e}")

    
    print(Colorate.Horizontal(Colors.red_to_yellow, "\n[+] IPQualityScore Trust Lookup:"))
    print(f"    View Reputation  : https://www.ipqualityscore.com/domain-reputation/lookup/{domain}")

    
    print(Colorate.Horizontal(Colors.red_to_yellow, "\n[+] DNS-based Blacklist (DNSBL) Check:"))
    dnsbl_servers = {
        "Spamhaus ZEN"    : "zen.spamhaus.org",
        "SpamCop"         : "bl.spamcop.net",
        "SORBS"           : "dnsbl.sorbs.net",
        "Abuse.ch"        : "dnsbl.abuse.ch"
    }

    if ip:
        reversed_ip = ".".join(reversed(ip.split(".")))
        for name, bl in dnsbl_servers.items():
            query = f"{reversed_ip}.{bl}"
            try:
                socket.gethostbyname(query)
                print(f"    [!] Listed in {name}")
            except socket.gaierror:
                print(f"    [+] Not listed in {name}")
    else:
        print(f"    [!] Skipped DNSBL check due to unresolved IP")

    
    print(Colorate.Horizontal(Colors.blue_to_purple, "\n[+] External Reputation Sources:"))
    links = {
        "Google Safe Browsing"   : f"https://transparencyreport.google.com/safe-browsing/search?url={domain}",
        "Norton Safe Web"        : f"https://safeweb.norton.com/report/show?url={domain}",
        "URLVoid"                : f"https://www.urlvoid.com/scan/{domain}/",
        "ScamAdviser"            : f"https://www.scamadviser.com/check-website/{domain}",
        "Yandex Protect"         : f"https://yandex.com/infected?url={domain}",
        "TrendMicro Site Safety" : f"https://global.sitesafety.trendmicro.com/result.php?url={domain}"
    }

    for name, link in links.items():
        print(f"    {name:<25} → {link}")



def reverse_ip_lookup(user_agents):
    url = input("Enter URL or domain to reverse-lookup IP: ").strip()
    if url.startswith("http"):
        parsed = urlparse(url)
        domain = parsed.netloc
    else:
        domain = url

    print(f"\nLooking up domains on same IP as: {domain}\n")

    try:
        ip = socket.gethostbyname(domain)
        print(f"Resolved IP: {ip}\n")

        headers = {"User-Agent": random.choice(user_agents)}
        lookup_url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
        response = requests.get(lookup_url, headers=headers, timeout=10)

        found = re.findall(r"<td>([a-zA-Z0-9\.\-]+\.[a-z]{2,})</td>", response.text)
        domains = list(dict.fromkeys(found))  

        shown = 0
        if domains:
            print(Colorate.Horizontal(Colors.blue_to_cyan, "[+] Found Domains:"))
            for d in domains:
                if shown >= 10:
                    break
                if d.lower() != domain.lower():
                    print(f"    → {d}")
                    shown += 1

            if len(domains) > 10:
                print(f"\n[!] Showing 10 of {len(domains)} total. Full list:")
        else:
            print(f"{Fore.YELLOW}[!] No other domains found on this IP.{Style.RESET_ALL}")

        print(f"{Fore.CYAN}View full result: {lookup_url}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error resolving or checking IP: {e}{Style.RESET_ALL}")




def find_admin_panels(user_agents):
    base = input("Enter base URL (e.g. https://example.com): ").strip()
    if not base.startswith("http"):
        base = "http://" + base

    print(f"\nScanning common admin/login paths on: {base}\n")

    paths = [
        "admin", "admin/login", "login", "admin.php", "admin.html", "cpanel",
        "wp-admin", "wp-login.php", "dashboard", "user/login", "signin", "backend",
        "manager", "portal", "secure", "adminpanel", "access", "auth", "webadmin",
        "register", "panel", "administration", "manage", "authentication", "signup",
        "owner", "adminarea", "staff", "member", "users", "private", "logon", "admin1",
        "admin2", "adminlogin", "controlpanel", "server", "moderator"
    ]

    found = []

    def scan_path(path):
        full_url = f"{base.rstrip('/')}/{path}"
        headers = {"User-Agent": random.choice(user_agents)} 
        try:
            r = requests.get(full_url, headers=headers, timeout=6, allow_redirects=False)
            if r.status_code in [200, 301, 302, 401, 403]:
                return (full_url, r.status_code)
        except:
            return None

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(scan_path, p) for p in paths]
        for future in as_completed(futures):
            result = future.result()
            if result:
                url, status = result
                found.append((url, status))
                color = Fore.GREEN if status == 200 else Fore.YELLOW
                print(f"{color}[+] {url} — {status}{Style.RESET_ALL}")

    if not found:
        print(f"{Fore.RED}[!] No accessible admin/login pages found.{Style.RESET_ALL}")
    else:
        print(Colorate.Horizontal(Colors.green_to_blue, f"\n[+] Total found: {len(found)}"))

    #Advanced Search
    print(Colorate.Horizontal(Colors.blue_to_purple, "\nGenerating advanced search suggestions...\n"))

    domain = base.replace("http://", "").replace("https://", "").split("/")[0]

    search_engines = {
        "Bing": "https://www.bing.com/search?q=",
        "DuckDuckGo": "https://duckduckgo.com/?q=",
        "StartPage": "https://www.startpage.com/sp/search?q="
    }

    queries = [
        f'site:{domain} inurl:admin',
        f'site:{domain} intitle:"login"',
        f'site:{domain} inurl:cpanel',
        f'site:{domain} inurl:dashboard',
        f'site:{domain} intext:"admin panel"',
        f'site:{domain} inurl:auth',
        f'site:{domain} intitle:"control panel"',
        f'site:{domain} inurl:secure',
        f'site:{domain} intitle:"administrator login"',
        f'site:{domain} inurl:backend'
    ]

    all_links = []

    for engine, base_url in search_engines.items():
        for q in queries:
            clean_q = quote(q)
            full_url = f"{base_url}{clean_q}"
            all_links.append((engine, full_url))

    # Save or Print
    while True:
        choice = input("\nSave advanced search results to file OR print in console? (s/p): ").strip().lower()
        if choice in ['s', 'save']:
            path = input("Enter path to save .txt file (e.g. /sdcard/search_links.txt): ").strip()
            try:
                with open(path, "w", encoding="utf-8") as f:
                    for engine, link in all_links:
                        f.write(f"[{engine}] {link}\n")
                print(f"{Fore.GREEN}[✓] Saved to: {path}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Failed to save file: {e}{Style.RESET_ALL}")
            break
        elif choice in ['p', 'print']:
            print("\nGenerated Search URLs:\n")
            for engine, link in all_links:
                print(f"[{engine}] {link}")
            break
        else:
            print("Invalid choice. Type 's' to save or 'p' to print.")







def scan_ports():
    target = input("Enter domain or IP to scan ports: ").strip()
    if target.startswith("http"):
        parsed = urlparse(target)
        target = parsed.netloc

    print(f"\nScanning ports on: {target}\n")

    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 8080: "HTTP-Alt",
        6379: "Redis", 3389: "RDP", 8443: "HTTPS-Alt", 993: "IMAPS", 995: "POP3S",
        1723: "PPTP", 111: "RPCbind", 587: "SMTP (SSL)", 465: "SMTPS"
    }

    open_ports = []

    for port, name in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                print(f"{Fore.GREEN}[+] Port {port} ({name}) is OPEN{Style.RESET_ALL}")
                open_ports.append(port)
            else:
                print(f"{Fore.RED}[-] Port {port} ({name}) is closed{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error checking port {port}: {e}{Style.RESET_ALL}")

    if open_ports:
        print(Colorate.Horizontal(Colors.green_to_blue, f"\n[✓] Total open ports: {len(open_ports)}"))
    else:
        print(f"{Fore.RED}\n[!] No open ports found.{Style.RESET_ALL}")





def global_availability():
    url = input("Enter URL or domain to check availability: ").strip()
    if url.startswith("http"):
        parsed = urlparse(url)
        domain = parsed.netloc
    else:
        domain = url

    print(f"\nChecking global availability for: {domain}\n")

    services = {
        "DownForEveryoneOrJustMe": f"https://downforeveryoneorjustme.com/{domain}",
        "GeoPeeker": f"https://geopeeker.com/fetch/?url={domain}",
        "IsItDown": f"https://isitdown.site/report/{domain}",
        "Site24x7": f"https://www.site24x7.com/public/t/results.html?domain={domain}",
        "Uptime.com": f"https://uptime.com/website-monitoring/check?check_url={domain}",
        "AppBeat": f"https://tools.appbeat.io/network-tools/http-request?url=https://{domain}",
        "Uptrends": f"https://www.uptrends.com/tools/uptime?url=https://{domain}"
    }

    for name, link in services.items():
        print(f"[+] {name}: {link}")




def analyze_robots_sitemap(user_agents):
    url = input("Enter domain to analyze (e.g. example.com): ").strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    headers = {"User-Agent": random.choice(user_agents)}

    print(f"\nFetching robots.txt from: {base}/robots.txt\n")

    try:
        r = requests.get(f"{base}/robots.txt", headers=headers, timeout=7)
        lines = r.text.splitlines()
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to fetch robots.txt: {e}{Style.RESET_ALL}")
        lines = []

    disallows, allows, sitemaps = [], [], []

    for line in lines:
        line = line.strip()
        if line.lower().startswith("disallow:"):
            disallows.append(line.split(":", 1)[1].strip())
        elif line.lower().startswith("allow:"):
            allows.append(line.split(":", 1)[1].strip())
        elif line.lower().startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())

    if disallows:
        print(Colorate.Horizontal(Colors.yellow_to_red, "[+] Disallowed paths:"))
        for p in disallows:
            print(f"  - {p}")
    if allows:
        print(Colorate.Horizontal(Colors.green_to_blue, "\n[+] Allowed paths:"))
        for p in allows:
            print(f"  - {p}")
    if sitemaps:
        print(Colorate.Horizontal(Colors.blue_to_purple, "\n[+] Sitemap URLs from robots.txt:"))
        for s in sitemaps:
            print(f"  - {s}")

    #idk
    if not sitemaps:
        print(Colorate.Horizontal(Colors.yellow_to_red, "\n[~] No Sitemap found in robots.txt. Trying common sitemap locations..."))
        common_sitemaps = [
            f"{base}/sitemap.xml",
            f"{base}/sitemap_index.xml"
        ]
        for test_url in common_sitemaps:
            try:
                test = requests.get(test_url, headers=headers, timeout=7)
                if "<urlset" in test.text or "<sitemapindex" in test.text:
                    sitemaps.append(test_url)
                    print(f"[+] Found sitemap: {test_url}")
            except:
                continue

    
    if sitemaps:
        print(Colorate.Horizontal(Colors.yellow_to_red, "\n[+] Parsing sitemap URLs..."))
        for sitemap in sitemaps:
            try:
                sr = requests.get(sitemap, headers=headers, timeout=7)
                urls = re.findall(r"<loc>(.*?)</loc>", sr.text)
                print(f"\n{Fore.CYAN}Sitemap: {sitemap}{Style.RESET_ALL}")
                for u in urls[:40]:
                    print(f"    → {u}")
                if len(urls) > 40:
                    print(f"    ... and {len(urls) - 40} more")
            except Exception as e:
                print(f"    [!] Failed to parse sitemap: {e}")
    else:
        print(f"{Fore.YELLOW}[!] No sitemap found.{Style.RESET_ALL}")




def about():
    text = """
    URLKit — advanced URL and domain toolkit by Blurredness

    Tool GitHub: https://github.com/Blurredness/URLKit
    GitHub     : https://github.com/Blurredness
    Telegram   : https://t.me/Blurredness
    Author     : Blurredness(aka PA3MblTOCTb)
    Status     : Actively developed (2025)

    This tool is designed for ethical OSINT, educational use,
    and personal research of domain and URL structures.
    Please, do NOT abuse this toolkit for illegal purposes.
    The author does NOT bear any responsibility for actions you take with this toolkit.
    """
    print(Colorate.Horizontal(Colors.blue_to_cyan, Center.XCenter(text.strip())))
    





def menu():
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        banner()
        print(Colorate.Horizontal(Colors.blue_to_purple, "\n[1] QR Code Generator"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[2] Shorten URL"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[3] Expand URL"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[4] Phishing URL Checker"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[5] Show Redirect Chain"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[6] Check Domain Age"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[7] Extract Data from URL"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[8] Meta Preview Extractor"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[9] Wayback Machine Snapshot Check"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[10] Domain Reputation Checker"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[11] Reverse IP Lookup"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[12] Find Admin/Login Panels"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[13] Fast Port Scanner"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[14] Global Availability Checker"))
        print(Colorate.Horizontal(Colors.blue_to_purple, "[15] Robots.txt & Sitemap Analyzer"))
        print(Colorate.Horizontal(Colors.blue_to_cyan, "[i] About"))
        print(Colorate.Horizontal(Colors.blue_to_cyan, "[q] Exit\n"))
        choice = input("Choose: ")
        if choice == '1':
            generate_qr()
        elif choice == '2':
            shorten_url(user_agents, shorteners)
        elif choice == '3':
            expand_url(user_agents)
        elif choice == '4':
            check_phishing_url(user_agents)
        elif choice == '5':
            redirect_chain(user_agents)
        elif choice == '6':
            domain_age()
        elif choice == '7':
            extract_data(user_agents)
        elif choice == '8':
            preview_meta_extractor(user_agents)
        elif choice == '9':
            wayback_history(user_agents)
        elif choice == '10':
            domain_reputation(user_agents)
        elif choice == '11':
            reverse_ip_lookup(user_agents)
        elif choice == '12':
            find_admin_panels(user_agents)
        elif choice == '13':
            scan_ports()
        elif choice == '14':
            global_availability()
        elif choice == '15':
            analyze_robots_sitemap(user_agents)
        elif choice.lower() == 'q':
            print("Thanks for using!")
            break
        elif choice.lower() == 'i':
            about()
        input("\nPress Enter to return...")

if __name__ == "__main__":
    menu()
#998
#999
# 1000!!!!!!!!!!!!!!!!!
