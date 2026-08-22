#!/usr/bin/env python3
"""Build a ranked Happ subscription directly from Liberty VPN."""

import argparse
import base64
import hashlib
import html
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode


SOURCE_URL = "https://connliberty.com/connection/subs/d950be8a-ab95-4618-bf67-21b76c969342?r=1"
CONFIG_KEYS = {"remarks", "outbounds", "routing"}
PROXY_SITES = [
    # The vendored geosite database maintains broad Russia-specific lists:
    # sites blocked inside Russia and services applying geo-blocks to Russia.
    "geosite:ru-blocked", "geosite:ru-geoblock",
    "geosite:telegram", "geosite:youtube", "geosite:twitch",
    "geosite:pinterest", "geosite:github",
    "domain:t.me", "domain:telegram.me", "domain:telegram.org",
    "domain:telegram.dog", "domain:telegra.ph",
    "domain:gemini.google.com", "domain:generativelanguage.googleapis.com",
    "domain:accounts.google.com", "domain:ai.google.dev",
    "domain:googleapis.com", "domain:gstatic.com", "domain:googleusercontent.com",
    "domain:chatgpt.com", "domain:chat.openai.com", "domain:openai.com",
    "domain:oaistatic.com", "domain:oaiusercontent.com", "domain:auth0.com",
    "geosite:youtube", "domain:youtube.com", "domain:youtu.be",
    "domain:youtube-nocookie.com", "domain:googlevideo.com",
    "domain:ytimg.com", "domain:ggpht.com",
    "domain:youtubei.googleapis.com", "domain:youtube.googleapis.com",
    "domain:instagram.com", "domain:cdninstagram.com",
    "domain:fbcdn.net", "domain:fbsbx.com", "domain:facebook.com",
    "domain:facebook.net", "domain:fb.com",
    "domain:threads.net", "domain:reddit.com", "domain:redd.it",
    "domain:anthropic.com", "domain:claude.ai", "domain:perplexity.ai",
    "domain:copilot.microsoft.com", "domain:discord.com", "domain:discord.gg",
]
PROXY_IP = [
    "geoip:ru-blocked", "geoip:ru-geoblock",
    "91.105.192.0/23", "91.108.4.0/22", "91.108.8.0/21",
    "91.108.16.0/21", "91.108.56.0/22", "95.161.64.0/20",
    "149.154.160.0/20", "185.76.151.0/24",
    "2001:67c:4e8::/48", "2001:b28:f23c::/47", "2001:b28:f23f::/48",
    "2a0a:f280::/32",
]
DIRECT_SITES = [
    # Keep the embedded Happ routing deeplink compact. With GlobalProxy=false,
    # unmatched traffic is already direct; these rules explicitly protect the
    # Russian namespaces and the services most likely to use non-.ru domains.
    "domain:ru", "domain:xn--p1ai", "geosite:category-ru",
    "geosite:russia-inside", "geosite:category-bank-ru",
    "geosite:sber", "geosite:tbank-ru",
    "domain:ozon.ru", "domain:ozonusercontent.com",
    "domain:wildberries.ru", "domain:wb.ru", "domain:wbbasket.ru",
    "domain:sberbank.ru", "domain:sber.ru",
    "domain:tbank.ru", "domain:tinkoff.ru", "domain:tinkoff.com",
    "domain:alfabank.ru", "domain:gosuslugi.ru", "domain:nalog.ru",
    "domain:mos.ru", "domain:yandex.ru", "domain:yandex.net",
    "domain:vk.com", "domain:mail.ru",
]
PRIVATE_IP = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
]
COUNTRY_NAMES_RU = {
    "AT": "Австрия", "BR": "Бразилия", "CA": "Канада", "CH": "Швейцария",
    "DE": "Германия", "ES": "Испания", "FI": "Финляндия", "FR": "Франция",
    "GB": "Англия", "HK": "Гонконг", "HU": "Венгрия", "IN": "Индия",
    "IT": "Италия", "JP": "Япония", "KZ": "Казахстан", "LT": "Литва",
    "MD": "Молдова", "NL": "Нидерланды", "PL": "Польша", "RO": "Румыния",
    "RU": "Россия", "SE": "Швеция", "TR": "Турция", "US": "США",
}


def fetch_source(url=SOURCE_URL):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "VPN_BEST direct-liberty/2.0",
            "Accept": "application/json,text/plain,text/html,*/*",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        raw_text = response.read().decode("utf-8-sig", errors="replace")
    configs = deduplicate_configs(extract_configs(raw_text))
    if not configs:
        raise ValueError("Liberty returned no usable configurations")
    return (json.dumps(configs, ensure_ascii=False, indent=2) + "\n").encode()


def looks_like_config(value):
    return isinstance(value, dict) and CONFIG_KEYS <= set(value)


def extract_configs(raw_text):
    """Extract Liberty configs from either its JSON response or HTML cards."""
    raw_text = html.unescape(raw_text)
    try:
        value = json.loads(raw_text)
    except json.JSONDecodeError:
        value = None
    if isinstance(value, list) and all(looks_like_config(item) for item in value):
        return value

    decoder = json.JSONDecoder()
    configs = []
    for index, character in enumerate(raw_text):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(raw_text[index:])
        except json.JSONDecodeError:
            continue
        if looks_like_config(value):
            configs.append(value)
    if not configs:
        raise ValueError("Could not extract Liberty configurations")
    remarks_markers = raw_text.count('"remarks"')
    if remarks_markers and len(configs) != remarks_markers:
        raise ValueError(
            f"Liberty response looks partial: {len(configs)} configs for "
            f"{remarks_markers} remarks markers"
        )
    return configs


def deduplicate_configs(configs):
    """Keep the latest Liberty card per name while preserving its position."""
    result, positions = [], {}
    for config in configs:
        name = config.get("remarks") or "Liberty VPN"
        if name in positions:
            result[positions[name]] = config
        else:
            positions[name] = len(result)
            result.append(config)
    return result


def vless_outbounds(config):
    return [
        outbound for outbound in config.get("outbounds", [])
        if outbound.get("protocol") == "vless"
    ]


def ordered_entries(configs):
    """Prefer individually named configs, then recover aggregate-only nodes."""
    entries = []
    for config in configs:
        outbounds = vless_outbounds(config)
        if len(outbounds) == 1:
            entries.append((outbounds[0], config.get("remarks") or "Liberty VPN"))
    for config in configs:
        for outbound in vless_outbounds(config):
            entries.append((outbound, outbound.get("tag") or config.get("remarks") or "Liberty VPN"))
    return entries


def first(mapping, *keys):
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", []):
            return value
    return None


def outbound_uri(outbound, label):
    settings = outbound.get("settings") or {}
    vnext = settings.get("vnext") or []
    if not vnext or not (vnext[0].get("users") or []):
        return None
    server = vnext[0]
    user = server["users"][0]
    address, port, user_id = server.get("address"), server.get("port"), user.get("id")
    if not all((address, port, user_id)):
        return None

    stream = outbound.get("streamSettings") or {}
    network = str(stream.get("network") or "tcp").lower()
    security = str(stream.get("security") or "none").lower()
    params = {
        "encryption": user.get("encryption") or "none",
        "type": network,
        "security": security,
    }
    if user.get("flow"):
        params["flow"] = user["flow"]

    if security == "reality":
        reality = stream.get("realitySettings") or {}
        params.update({
            "sni": first(reality, "serverName"),
            "fp": first(reality, "fingerprint") or "chrome",
            "pbk": first(reality, "publicKey"),
            "sid": first(reality, "shortId"),
            "spx": first(reality, "spiderX"),
        })
    elif security == "tls":
        tls = stream.get("tlsSettings") or {}
        params.update({
            "sni": first(tls, "serverName"),
            "fp": first(tls, "fingerprint") or "chrome",
        })
        if tls.get("alpn"):
            params["alpn"] = ",".join(tls["alpn"])

    transport = {}
    if network == "ws":
        transport = stream.get("wsSettings") or {}
        params["path"] = transport.get("path")
        params["host"] = transport.get("host") or (transport.get("headers") or {}).get("Host")
    elif network == "grpc":
        transport = stream.get("grpcSettings") or {}
        params["serviceName"] = transport.get("serviceName")
        params["authority"] = transport.get("authority")
    elif network == "xhttp":
        transport = stream.get("xhttpSettings") or {}
        params["path"] = transport.get("path")
        params["host"] = transport.get("host")
        params["mode"] = transport.get("mode")
        if transport.get("extra") is not None:
            params["extra"] = json.dumps(transport["extra"], separators=(",", ":"))
    elif network == "httpupgrade":
        transport = stream.get("httpupgradeSettings") or {}
        params["path"] = transport.get("path")
        params["host"] = transport.get("host")

    params = {key: str(value) for key, value in params.items() if value not in (None, "")}
    if security == "reality" and not all(params.get(key) for key in ("sni", "pbk")):
        return None
    if security == "tls" and not params.get("sni"):
        return None
    host = f"[{address}]" if ":" in str(address) and not str(address).startswith("[") else address
    query = urlencode(params, quote_via=quote, safe="/-._~")
    return f"vless://{quote(str(user_id), safe='-')}@{host}:{int(port)}?{query}#{quote(str(label), safe='')}"


def node_key(uri):
    return hashlib.sha256(uri.partition("#")[0].encode()).hexdigest()[:20]


def server_records(configs):
    records, identities = [], set()
    for outbound, label in ordered_entries(configs):
        uri = outbound_uri(outbound, label)
        if not uri:
            continue
        identity = uri.partition("#")[0]
        if identity in identities:
            continue
        identities.add(identity)
        settings = outbound.get("settings") or {}
        server = ((settings.get("vnext") or [{}])[0])
        records.append({
            "uri": uri,
            "identity": identity,
            "key": node_key(uri),
            "label": str(label),
            "address": server.get("address"),
            "port": int(server.get("port") or 0),
            "outbound": outbound,
        })
    return records


def location_priority(label):
    """Fallback order by practical distance from Moscow, not flag alone."""
    priorities = [
        ("Финлянд", 10), ("Эстони", 12), ("Латви", 14), ("Литв", 16),
        ("Польш", 20), ("Швец", 24), ("Молдов", 26), ("Герм", 30),
        ("Нидерланд", 34), ("Венгр", 36), ("Турц", 38), ("Франц", 42),
        ("Швейцар", 44), ("Англ", 46), ("Итал", 48), ("Испан", 52),
        ("Казахстан", 58), ("Канада", 90), ("США", 95), ("Япони", 100),
        ("Гонконг", 105), ("Инд", 110), ("Бразил", 130),
        # Russian exits can be fast but usually cannot bypass service geoblocks.
        ("Росси", 500),
    ]
    for marker, priority in priorities:
        if marker.casefold() in label.casefold():
            return priority
    return 200


def ranked_uri(record, measurement):
    label = record["label"]
    exit_country = measurement.get("exit_country")
    if label.startswith("proxy-") and exit_country:
        flag = "".join(chr(127397 + ord(letter)) for letter in exit_country)
        label = f"{flag} {COUNTRY_NAMES_RU.get(exit_country, exit_country)} • Liberty"
    elif label.startswith("proxy-"):
        label = f"🌐 Liberty • резерв {record['key'][:4]}"
    latency = measurement.get("latency_ms")
    speed = measurement.get("speed_mbps")
    details = []
    if latency is not None:
        details.append(f"{latency:.0f} ms")
    if speed is not None and measurement.get("tunnel_ok"):
        details.append(f"{speed:.1f} Mbps")
    if details:
        label = f"{label} • {' • '.join(details)}"
    return record["identity"] + "#" + quote(label, safe="")


def build_subscription(configs, measurements=None):
    servers_measurements = (measurements or {}).get("servers", {})
    records = server_records(configs)

    def is_publishable(record):
        data = servers_measurements.get(record["key"])
        if not data:
            return True
        if "publishable" in data:
            return bool(data["publishable"])
        # Backward compatibility with measurements created before publication
        # hysteresis was introduced.
        return int(data.get("consecutive_failures") or 0) < 3

    def sort_key(item):
        index, record = item
        data = servers_measurements.get(record["key"], {})
        latency = data.get("latency_ms")
        speed = data.get("speed_mbps")
        tunnel_ok = bool(data.get("tunnel_ok"))
        failures = int(data.get("consecutive_failures") or 0)
        russian_exit = data.get("exit_country") == "RU"
        exit_penalty = 500 if russian_exit or "росси" in record["label"].casefold() else 0
        if record["label"].startswith("proxy-") and not data.get("exit_country"):
            exit_penalty = max(exit_penalty, 300)
        if tunnel_ok:
            score = (latency if latency is not None else 500) + 160 / max(speed or 0.5, 0.5)
            return (0, score + exit_penalty, index)
        if latency is not None and failures < 2:
            return (1, latency + exit_penalty, index)
        return (2, location_priority(record["label"]), index)

    publishable = [record for record in records if is_publishable(record)]
    ordered = [record for _, record in sorted(enumerate(publishable), key=sort_key)]
    return [
        ranked_uri(record, servers_measurements.get(record["key"], {}))
        for record in ordered
    ]


def source_direct_domains(configs):
    # The source contains hundreds of explicit domains. Embedding all of them
    # makes the happ:// line exceed common line-scanner limits, so Happ imports
    # the nodes but silently skips the routing profile. GlobalProxy=false makes
    # all unmatched traffic direct; a compact explicit safety list is enough.
    return list(DIRECT_SITES)


def routing_profile(configs):
    return {
        "Name": "Russia",
        "GlobalProxy": "false",
        "RemoteDNSType": "DoH",
        "RemoteDNSDomain": "https://dns.google/dns-query",
        "RemoteDNSIP": "8.8.8.8",
        "DomesticDNSType": "DoU",
        "DomesticDNSDomain": "",
        "DomesticDNSIP": "77.88.8.8",
        "Geositeurl": (
            "https://raw.githubusercontent.com/dfantomasd/VPN_BEST/"
            "29251629d66d9adaad30994407a611182ecc2aea/"
            "routing-data/geosite.dat"
        ),
        "Geoipurl": (
            "https://raw.githubusercontent.com/dfantomasd/VPN_BEST/"
            "29251629d66d9adaad30994407a611182ecc2aea/"
            "routing-data/geoip.dat"
        ),
        "LastUpdated": "1787408711",
        "DnsHosts": {},
        "DirectSites": source_direct_domains(configs),
        "DirectIp": ["geoip:ru", *PRIVATE_IP],
        "ProxySites": PROXY_SITES,
        "ProxyIp": PROXY_IP,
        "BlockSites": [],
        "BlockIp": [],
        "DomainStrategy": "IPIfNonMatch",
        "FakeDNS": "false",
    }


def routing_link(configs):
    payload = json.dumps(
        routing_profile(configs), ensure_ascii=False, separators=(",", ":")
    ).encode()
    # Happ documents standard Base64 here. URL-safe Base64 silently fails for
    # profiles whose payload contains '/' or '+' sextets.
    encoded = base64.b64encode(payload).decode()
    return "happ://routing/onadd/" + encoded


def generate(source_bytes, output_dir=Path("."), measurements=None):
    configs = json.loads(source_bytes.decode("utf-8-sig"))
    if not isinstance(configs, list):
        raise ValueError("Liberty source must contain a JSON array")
    node_lines = build_subscription(configs, measurements)
    if not node_lines:
        raise ValueError("source contains no valid VLESS outbounds")
    source_count = len(server_records(configs))
    minimum = min(5, source_count)
    if len(node_lines) < minimum:
        raise ValueError(
            f"refusing to replace the last-known-good subscription: only "
            f"{len(node_lines)} of {source_count} nodes are publishable"
        )

    lines = [
        routing_link(configs),
        "#routing-enable: 1",
        "#subscription-autoconnect: 1",
        "#subscription-autoconnect-type: lowestdelay",
        "#subscription-ping-onopen-enabled: 1",
        "#subscription-auto-update-enable: 1",
        "#profile-update-interval: 1",
        "#subscription-auto-update-open-enable: 1",
        "#profile-title: VPN_BEST",
        *node_lines,
    ]
    plain = ("\n".join(lines) + "\n").encode()
    output_dir.joinpath("whitelist_configs_combined.json").write_bytes(source_bytes)
    output_dir.joinpath("subscription.txt").write_bytes(plain)
    output_dir.joinpath("subscription_base64.txt").write_text(
        base64.b64encode(plain).decode() + "\n", encoding="utf-8"
    )
    profile = routing_profile(configs)
    output_dir.joinpath("routing.json").write_text(
        json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    output_dir.joinpath("routing.txt").write_text(
        routing_link(configs) + "\n", encoding="utf-8"
    )
    status = {
        "source": SOURCE_URL,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "server_count": len(node_lines),
        "source_server_count": source_count,
        "excluded_server_count": source_count - len(node_lines),
        "tunnel_verified_count": sum(
            bool(item.get("tunnel_ok"))
            for item in ((measurements or {}).get("servers") or {}).values()
        ),
        "routing": "Russia split tunnel",
        "ranking": {
            "origin": "Moscow TCP probes + Xray tunnel throughput",
            "service_checks": "diagnostic only; never used for ranking or publication",
            "measurements_updated_at": (measurements or {}).get("updated_at"),
        },
    }
    output_dir.joinpath("status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return node_lines


def load_source(source_file=None, fallback_path=Path("whitelist_configs_combined.json")):
    if source_file:
        return Path(source_file).read_bytes()
    try:
        fresh = fetch_source()
        fresh_configs = json.loads(fresh.decode("utf-8-sig"))
        fresh_count = len(server_records(fresh_configs))
        if not fresh_count:
            raise ValueError("Liberty returned no valid VLESS servers")
        if fallback_path.exists():
            previous_configs = json.loads(fallback_path.read_text(encoding="utf-8-sig"))
            previous_count = len(server_records(previous_configs))
            minimum = max(5, previous_count // 2)
            if fresh_count < minimum:
                raise ValueError(
                    f"Liberty catalog shrank unexpectedly: {fresh_count} < {minimum}"
                )
        return fresh
    except Exception as exc:
        if not fallback_path.exists():
            raise
        print(f"Upstream unavailable ({exc}); using committed source snapshot")
        return fallback_path.read_bytes()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-file")
    parser.add_argument("--measurements")
    args = parser.parse_args()
    source = load_source(args.source_file)
    measurements = None
    if args.measurements and Path(args.measurements).exists():
        measurements = json.loads(Path(args.measurements).read_text())
    lines = generate(source, measurements=measurements)
    print(f"Built {len(lines)} unique VLESS servers directly from Liberty VPN")


if __name__ == "__main__":
    main()
