import requests, yaml, os, socket
from datetime import datetime

# منابع مختلف پراکسی
SOURCES = [
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country=IR", "socks5"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&country=IR", "socks4"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&country=IR", "http"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&country=IR", "http"),
    ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/proxies/roosterkid.public.list", None)
]

def is_alive(ip, port, timeout=3):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, int(port)))
        s.close()
        return True
    except:
        return False

def ip_is_ir(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        return r.get("countryCode") == "IR"
    except:
        return False

proxies = []
idx = 0

for url, ptype in SOURCES:
    r = requests.get(url, timeout=15)
    lines = r.text.strip().splitlines()
    for line in lines:
        parts = line.split()
        entry = parts[0] if len(parts)>0 else line
        if ":" not in entry: continue
        ip, port = entry.strip().split(":")[:2]
        if not ip_is_ir(ip): continue
        if not is_alive(ip, port): continue
        idx += 1
        ptype_final = ptype or ("socks5" if port=="1080" else "http")
        proxies.append({
            "name": f"ir-{ptype_final}-{idx}",
            "type": ptype_final,
            "server": ip,
            "port": int(port),
            "udp": True
        })

config = {
    "mixed-port": 7890,
    "allow-lan": True,
    "mode": "Rule",
    "log-level": "info",
    "proxies": proxies,
    "proxy-groups": [{
        "name": "IR-ALL",
        "type": "select",
        "proxies": [p["name"] for p in proxies]
    }],
    "rules": ["MATCH,IR-ALL"]
}

os.makedirs("output", exist_ok=True)
with open("output/config.yaml","w",encoding="utf-8") as f:
    yaml.dump(config, f, allow_unicode=True)

print(f"✅ Updated {len(proxies)} proxies at {datetime.now()}")
