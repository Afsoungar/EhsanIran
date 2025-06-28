import requests, yaml, os, socket, time
from datetime import datetime

SOURCES = [
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country=IR", "socks5"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&country=IR", "http"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&country=IR", "http"),
    ("https://proxyspace.pro/http.txt?country=ir", "http"),
    ("https://proxyspace.pro/socks5.txt?country=ir", "socks5"),
    ("https://proxyscan.io/download?type=http&format=txt&country=IR", "http"),
    ("https://proxyscan.io/download?type=socks5&format=txt&country=IR", "socks5")
]

def is_alive(ip, port, timeout=3):
    try:
        start = time.time()
        s = socket.create_connection((ip, int(port)), timeout=timeout)
        s.close()
        ping = int((time.time() - start) * 1000)
        return True, ping
    except:
        return False, None

def ip_is_ir(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        return r.get("countryCode") == "IR"
    except:
        return False

proxies_all = []
proxy_names_clean = []
proxy_names_raw = []
seen_ips = set()

for url, ptype in SOURCES:
    try:
        r = requests.get(url, timeout=15)
    except:
        continue
    lines = r.text.strip().splitlines()
    for line in lines:
        entry = line.strip().split()[0]
        if ":" not in entry:
            continue
        ip, port = entry.strip().split(":")[:2]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        if not ip_is_ir(ip):
            continue

        proxy_type = ptype or ("socks5" if port == "1080" else "http")
        base_name = f"{ip}:{port}"
        proxy_entry = {
            "type": proxy_type,
            "server": ip,
            "port": int(port),
            "udp": True
        }

        # بررسی سلامت
        alive, ping = is_alive(ip, port)
        if alive:
            full_name = f"{base_name} ({ping}ms)"
            proxy_entry["name"] = full_name
            proxy_names_clean.append(full_name)
        else:
            proxy_entry["name"] = base_name
            proxy_names_raw.append(base_name)

        proxies_all.append(proxy_entry)

# ساخت فایل کانفیگ Clash
config = {
    "mixed-port": 7890,
    "allow-lan": True,
    "mode": "Rule",
    "log-level": "info",
    "proxies": proxies_all,
    "proxy-groups": [
        {
            "name": "IR-ALL",
            "type": "select",
            "proxies": proxy_names_clean
        },
        {
            "name": "IR-ALL-RAW",
            "type": "select",
            "proxies": proxy_names_clean + proxy_names_raw
        }
    ],
    "rules": ["MATCH,IR-ALL"]
}

os.makedirs("output", exist_ok=True)
with open("output/config.yaml", "w", encoding="utf-8") as f:
    yaml.dump(config, f, allow_unicode=True)

print(f"✅ Updated {len(proxy_names_clean)} clean proxies and {len(proxies_all)} total")
