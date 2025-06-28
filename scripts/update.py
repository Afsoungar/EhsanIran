import requests, yaml, os, socket, time, base64, json
from datetime import datetime

# منابع پراکسی عمومی
SOURCES = [
    # SOCKS5 / HTTP منابع
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country=IR", "socks5"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&country=IR", "http"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&country=IR", "http"),
    ("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt", "http"),
    ("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", "socks5"),

    # VMESS / VLESS / SS منابع
    ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vmess.txt", "vmess"),
    ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vless.txt", "vless"),
    ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/ss.txt", "ss")
]

def is_alive(ip, port, timeout=7):
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
idx = 0

for url, ptype in SOURCES:
    try:
        r = requests.get(url, timeout=20)
    except:
        continue
    lines = r.text.strip().splitlines()

    # حالت vmess/vless/ss (base64 encoded)
    if ptype in ["vmess", "vless", "ss"]:
        for line in lines:
            line = line.strip()
            if line.startswith("vmess://"):
                try:
                    decoded = base64.b64decode(line[8:] + "==").decode()
                    conf = json.loads(decoded)
                    ip = conf.get("add")
                    port = conf.get("port")
                    if not ip or not port or not ip_is_ir(ip):
                        continue
                    alive, ping = is_alive(ip, port)
                    name = f"{ip}:{port} ({ping}ms)" if alive else f"{ip}:{port}"
                    proxy_entry = {
                        "name": name,
                        "type": "vmess",
                        "server": ip,
                        "port": int(port),
                        "uuid": conf.get("id"),
                        "alterId": int(conf.get("aid", 0)),
                        "cipher": conf.get("cipher", "auto"),
                        "tls": conf.get("tls") == "tls",
                        "network": conf.get("net", "tcp"),
                        "udp": True
                    }
                    if conf.get("net") == "ws":
                        proxy_entry["ws-opts"] = {
                            "path": conf.get("path", "/"),
                            "headers": {"Host": conf.get("host", "")}
                        }
                    proxies_all.append(proxy_entry)
                    if alive:
                        proxy_names_clean.append(name)
                    else:
                        proxy_names_raw.append(name)
                except:
                    continue
            elif line.startswith("vless://") or line.startswith("ss://"):
                # ساده‌سازی: فقط در صورت تمایل این بخش رو کامل می‌کنیم
                continue
        continue

    # حالت معمول socks/http
    for line in lines:
        if ":" not in line:
            continue
        ip, port = line.strip().split(":")[:2]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        if not ip_is_ir(ip):
            continue
        proxy_type = ptype
        base_name = f"{ip}:{port}"
        alive, ping = is_alive(ip, port)
        name = f"{base_name} ({ping}ms)" if alive else base_name
        proxy_entry = {
            "name": name,
            "type": proxy_type,
            "server": ip,
            "port": int(port),
            "udp": True
        }
        proxies_all.append(proxy_entry)
        if alive:
            proxy_names_clean.append(name)
        else:
            proxy_names_raw.append(name)

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
            "proxies": list(set(proxy_names_clean + proxy_names_raw))
        }
    ],
    "rules": ["MATCH,IR-ALL"]
}

os.makedirs("output", exist_ok=True)
with open("output/config.yaml", "w", encoding="utf-8") as f:
    yaml.dump(config, f, allow_unicode=True)

print(f"✅ Updated {len(proxy_names_clean)} clean proxies and {len(proxies_all)} total")
