import requests, yaml, os, socket
from datetime import datetime

# دریافت لیست پراکسی از Proxyscrape
URL = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country=IR"
res = requests.get(URL)
lines = res.text.strip().split("\n")

# بررسی سالم بودن پراکسی
def is_proxy_alive(ip, port, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.close()
        return True
    except:
        return False

# بررسی و ساخت لیست نهایی
proxy_list = []
for i, line in enumerate(lines):
    parts = line.strip().split(":")
    if len(parts) != 2:
        continue
    ip, port = parts
    if is_proxy_alive(ip, port):
        proxy_list.append({
            "name": f"ir-proxy-{i+1}",
            "type": "socks5",
            "server": ip,
            "port": int(port),
            "udp": True
        })

# ساخت فایل Clash YAML
config = {
    "mixed-port": 7890,
    "allow-lan": True,
    "mode": "Rule",
    "log-level": "info",
    "proxies": proxy_list,
    "proxy-groups": [
        {
            "name": "IR-PROXIES",
            "type": "url-test",
            "proxies": [p["name"] for p in proxy_list],
            "interval": 300
        }
    ],
    "rules": [
        "MATCH,IR-PROXIES"
    ]
}

os.makedirs("output", exist_ok=True)
with open("output/config.yaml", "w", encoding="utf-8") as f:
    yaml.dump(config, f, allow_unicode=True)

print(f"✅ آپدیت شد: {len(proxy_list)} پراکسی سالم در {datetime.now()}")
