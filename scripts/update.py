import requests, yaml, os, socket, time
from datetime import datetime

SOURCES = [
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country=IR", "socks5"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&country=IR", "socks4"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&country=IR", "http"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&country=IR", "http"),
    ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/proxies/roosterkid.public.list", None)
]

def is_alive(ip, port, timeout=3):
    try:
        start = time.time()
        s = socket.create_connection((ip, int(port)), timeout=timeout)
        s.close()
        ping = int((time.time() - start) * 1000)  # ping in ms
        return True, ping
    except:
        return False, None

def ip_is_ir(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        return r.get("countryCode") == "IR"
    except:
        return False

# لیست‌های نهایی
proxies_clean = []
proxies_raw = []
seen = set()
idx = 0

for url, ptype in SOURCES:
    try:
        r = requests.get(url, timeout=15)
    except:
        continue
    lines = r.text.strip().splitlines()
    for line in lines:
        parts = line.strip().split()
        entry = parts[0] if len(parts)>0 else line
        if ":" not in entry: continue
        ip, port = entry.split(":")[:2]
        if ip in seen: continue
        seen.add(ip)
        if not ip_is_ir(ip): continue  # فقط پراکسی ایرانی
        # در هر صورت پراکسی رو به RAW اضافه کن
        proxy_entry = {
            "name": f"{ip}:{port}",
            "type": ptype or ("socks5" if port == "1080" else "http"),
            "server": ip,
            "port": int(port),
            "udp": True
        }
        proxies_raw.append(proxy_entry)

        # تست سالم بودن و پینگ
        alive, ping = is_alive(ip, port)
        if alive:
            idx += 1
            proxy_entry_clean = proxy_entry.copy()
            proxy_entry_clean["name"] = f"{ip}:{port} ({ping}ms)"
            proxies_clean.append(proxy_entry_clean)

# ساخت کانفیگ Clash
config = {
    "mixed-port": 7890,
    "allow-lan": True,
    "mode": "Rule",
    "log-level": "info",
    "proxies": proxies_clean,
    "proxy-groups": [
        {
            "name": "IR-ALL",  # فقط پراکسی‌های سالم
            "type": "select",
            "proxies": [p["name"] for p in proxies_clean]
        },
        {
            "name": "IR-ALL-RAW",  # همه پراکسی‌های ایرانی (حتی ناسالم)
            "type": "select",
            "proxies": [p["name"] for p in proxies_clean + proxies_raw if p["name"] not in [x["name"] for x in proxies_clean]]
        }
    ],
    "rules": ["MATCH,IR-ALL"]
}

os.makedirs("output", exist_ok=True)
with open("output/config.yaml","w",encoding="utf-8") as f:
    yaml.dump(config, f, allow_unicode=True)

print(f"✅ Updated {len(proxies_clean)} clean proxies and {len(proxies_raw)} total at {datetime.now()}")
