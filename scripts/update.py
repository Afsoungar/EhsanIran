import requests, yaml, os, socket, time, base64, json
from urllib.parse import urlparse, parse_qs

SOURCES = [
    # SOCKS5 / HTTP منابع
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country=IR", "socks5"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&country=IR", "http"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&country=IR", "http")
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

def parse_ss(url):
    try:
        from urllib.parse import unquote
        url = url[5:]
        if "#" in url:
            url, tag = url.split("#", 1)
        else:
            tag = "ss"
        if "@" not in url:
            url = base64.b64decode(url + "==").decode()
            method, rest = url.split(":", 1)
            password, serverport = rest.split("@")
            server, port = serverport.split(":")
        else:
            userinfo, serverinfo = url.split("@")
            method, password = base64.b64decode(userinfo + "==").decode().split(":")
            server, port = serverinfo.split(":")
        return {
            "name": tag,
            "type": "ss",
            "server": server,
            "port": int(port),
            "cipher": method,
            "password": password,
            "udp": True
        }
    except:
        return None

def parse_vless(url):
    try:
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        return {
            "name": parsed.fragment or f"{parsed.hostname}:{parsed.port}",
            "type": "vless",
            "server": parsed.hostname,
            "port": int(parsed.port),
            "uuid": parsed.username,
            "tls": q.get("security", ["none"])[0] == "tls",
            "udp": True,
            "network": q.get("type", ["tcp"])[0],
            "ws-opts": {
                "path": q.get("path", ["/"])[0],
                "headers": {"Host": q.get("host", [""])[0]}
            } if q.get("type", ["tcp"])[0] == "ws" else {}
        }
    except:
        return None

proxies_all = []
proxy_names_clean = []
proxy_names_raw = []
seen_ips = set()

for url, ptype in SOURCES:
    try:
        r = requests.get(url, timeout=20)
    except:
        continue
    lines = r.text.strip().splitlines()

    for line in lines:
        line = line.strip()

        if ptype == "vmess" and line.startswith("vmess://"):
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

        elif ptype == "vless" and line.startswith("vless://"):
            conf = parse_vless(line)
            if not conf or not ip_is_ir(conf["server"]):
                continue
            alive, ping = is_alive(conf["server"], conf["port"])
            conf["name"] = f"{conf['server']}:{conf['port']} ({ping}ms)" if alive else f"{conf['server']}:{conf['port']}"
            proxies_all.append(conf)
            if alive:
                proxy_names_clean.append(conf["name"])
            else:
                proxy_names_raw.append(conf["name"])

        elif ptype == "ss" and line.startswith("ss://"):
            conf = parse_ss(line)
            if not conf or not ip_is_ir(conf["server"]):
                continue
            alive, ping = is_alive(conf["server"], conf["port"])
            conf["name"] = f"{conf['server']}:{conf['port']} ({ping}ms)" if alive else f"{conf['server']}:{conf['port']}"
            proxies_all.append(conf)
            if alive:
                proxy_names_clean.append(conf["name"])
            else:
                proxy_names_raw.append(conf["name"])

        elif ":" in line and ptype in ["http", "socks5"]:
            ip, port = line.strip().split(":")[:2]
            if ip in seen_ips or not ip_is_ir(ip):
                continue
            seen_ips.add(ip)
            alive, ping = is_alive(ip, port)
            name = f"{ip}:{port} ({ping}ms)" if alive else f"{ip}:{port}"
            proxy_entry = {
                "name": name,
                "type": ptype,
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
        },
        {
            "name": "IR-AUTO",
            "type": "url-test",
            "proxies": proxy_names_clean,
            "url": "http://www.gstatic.com/generate_204",
            "interval": 600
        },
        {
            "name": "IR-BALANCE",
            "type": "load-balance",
            "proxies": proxy_names_clean,
            "url": "http://www.gstatic.com/generate_204",
            "interval": 600
        }
    ],
    "rules": ["MATCH,IR-AUTO"]
}

os.makedirs("output", exist_ok=True)
with open("output/config.yaml", "w", encoding="utf-8") as f:
    yaml.dump(config, f, allow_unicode=True)

print(f"✅ Updated {len(proxy_names_clean)} clean proxies and {len(proxies_all)} total")
