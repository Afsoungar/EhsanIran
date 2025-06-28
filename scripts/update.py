import requests, yaml, os, base64, json
from urllib.parse import urlparse, parse_qs

SOURCES = [
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country=IR", "socks5"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&country=IR", "http"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&country=IR", "http"),
    ("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt", "http"),
    ("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", "socks5"),
    ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vmess.txt", "vmess"),
    ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vless.txt", "vless"),
    ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/ss.txt", "ss")
]

proxies_all = []
proxy_names = []
seen_ips = set()


def ip_is_ir(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        return r.get("countryCode") == "IR"
    except:
        return False


def parse_ss(url):
    try:
        if url.startswith("ss://"):
            url = url[5:]
            if "#" in url:
                url, tag = url.split("#", 1)
            else:
                tag = "ss"
            decoded = base64.b64decode(url.split("@")[-1] if "@" in url else url + "==").decode()
            method_pass, server_port = decoded.split("@")
            method, password = method_pass.split(":", 1)
            server, port = server_port.split(":")
            return {
                "name": f"{server}:{port}",
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
            "name": f"{parsed.hostname}:{parsed.port}",
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
                name = f"{ip}:{port}"
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
                proxy_names.append(name)
            except:
                continue

        elif ptype == "vless" and line.startswith("vless://"):
            conf = parse_vless(line)
            if not conf or not ip_is_ir(conf["server"]):
                continue
            proxies_all.append(conf)
            proxy_names.append(conf["name"])

        elif ptype == "ss" and line.startswith("ss://"):
            conf = parse_ss(line)
            if not conf or not ip_is_ir(conf["server"]):
                continue
            proxies_all.append(conf)
            proxy_names.append(conf["name"])

        elif ":" in line and ptype in ["http", "socks5"]:
            ip, port = line.strip().split(":")[:2]
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            if not ip_is_ir(ip):
                continue
            name = f"{ip}:{port}"
            proxy_entry = {
                "name": name,
                "type": ptype,
                "server": ip,
                "port": int(port),
                "udp": True
            }
            proxies_all.append(proxy_entry)
            proxy_names.append(name)

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
            "proxies": proxy_names
        }
    ],
    "rules": ["MATCH,IR-ALL"]
}

os.makedirs("output", exist_ok=True)
with open("output/config.yaml", "w", encoding="utf-8") as f:
    yaml.dump(config, f, allow_unicode=True)

print(f"✅ Collected {len(proxies_all)} Iranian proxies.")
