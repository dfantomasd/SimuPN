#!/usr/bin/env python3
"""Build a ranked Happ subscription directly from Liberty VPN."""

import argparse
import base64
import hashlib
import html
import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit


SOURCE_URL = "https://connliberty.com/connection/subs/d950be8a-ab95-4618-bf67-21b76c969342?r=1"
SOURCES_FILE = Path("sources.json")
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
    "geosite:sber", "geosite:tbank-ru", "geosite:whitelist",
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


def source_specs(path=SOURCES_FILE):
    """Load enabled upstreams, with an environment override for deployments."""
    override = os.environ.get("SIMUPN_SOURCE_URLS", "").strip()
    if override:
        return [
            {"name": f"source-{index}", "url": url.strip(), "enabled": True}
            for index, url in enumerate(override.split(","), 1) if url.strip()
        ]
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        value = [{"name": "liberty", "url": SOURCE_URL, "enabled": True}]
    if not isinstance(value, list):
        raise ValueError("sources.json must contain an array")
    specs = [item for item in value if isinstance(item, dict) and item.get("enabled", True)]
    if not specs or any(not item.get("name") or not item.get("url") for item in specs):
        raise ValueError("every enabled source needs a name and url")
    return specs


def fetch_catalog(url):
    request = urllib.request.Request(url, headers={
        "User-Agent": "SimuPN multi-source/1.0",
        "Accept": "application/json,text/plain,text/html,*/*",
        "Cache-Control": "no-cache",
    })
    with urllib.request.urlopen(request, timeout=60) as response:
        raw_text = response.read().decode("utf-8-sig", errors="replace")
    configs = extract_configs(raw_text)
    if "vless://" not in maybe_decode_subscription(raw_text):
        configs = deduplicate_configs(configs)
    if not configs:
        raise ValueError("source returned no usable configurations")
    return configs


def select_candidates(configs, limit, source_name):
    """Rotate a bounded public-source sample daily without random output churn."""
    if not limit:
        return configs
    day = datetime.now(timezone.utc).date().isoformat()
    ranked = []
    for config in configs:
        identities = [
            outbound_uri(outbound, config.get("remarks") or source_name)
            for outbound in vless_outbounds(config)
        ]
        identity = next((item.partition("#")[0] for item in identities if item), "")
        digest = hashlib.sha256(f"{day}:{source_name}:{identity}".encode()).hexdigest()
        ranked.append((digest, config))
    return [config for _, config in sorted(ranked, key=lambda item: item[0])[:int(limit)]]


def tag_source(configs, name, short=None):
    short = (short or name[:3]).strip().upper()
    result = []
    for config in configs:
        config = dict(config)
        config["_simupn_source"] = name
        config["_simupn_source_short"] = short
        tagged_outbounds = []
        for outbound in config.get("outbounds") or []:
            outbound = dict(outbound)
            outbound["_simupn_source"] = name
            outbound["_simupn_source_short"] = short
            tagged_outbounds.append(outbound)
        config["outbounds"] = tagged_outbounds
        result.append(config)
    return result


def load_catalogs(specs=None, fallback_path=Path("whitelist_configs_combined.json")):
    """Fetch sources independently and retain the last-known-good part on failure."""
    specs = specs or source_specs()
    previous = []
    if fallback_path.exists():
        try:
            previous = json.loads(fallback_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            previous = []
    combined, report = [], []
    for index, spec in enumerate(specs):
        name, url = str(spec["name"]), str(spec["url"])
        short = str(spec.get("short") or name[:3]).strip().upper()
        old = [item for item in previous if item.get("_simupn_source") == name]
        if not old and index == 0:
            old = [item for item in previous if not item.get("_simupn_source")]
        try:
            fresh = select_candidates(
                tag_source(fetch_catalog(url), name, short),
                spec.get("max_nodes"), name,
            )
            fresh_count = len(server_records(fresh))
            old_count = len(server_records(old))
            minimum = max(int(spec.get("min_nodes") or 1), old_count // 2)
            if old_count and fresh_count < minimum:
                raise ValueError(f"catalog shrank unexpectedly: {fresh_count} < {minimum}")
            combined.extend(fresh)
            report.append({"name": name, "url": url, "status": "fresh", "nodes": fresh_count})
        except Exception as exc:
            if not old:
                report.append({"name": name, "url": url, "status": "failed", "error": str(exc)[:180]})
                continue
            combined.extend(tag_source(old, name, short))
            report.append({"name": name, "url": url, "status": "snapshot", "nodes": len(server_records(old)), "error": str(exc)[:180]})
    combined = deduplicate_nodes(combined)
    if not server_records(combined):
        raise ValueError("all configured sources failed and no snapshot is available")
    return (json.dumps(combined, ensure_ascii=False, indent=2) + "\n").encode(), report


def deduplicate_nodes(configs):
    """Deduplicate VLESS identities across providers, preferring source order."""
    seen, result = set(), []
    for config in configs:
        kept = []
        for outbound in vless_outbounds(config):
            uri = outbound_uri(outbound, config.get("remarks") or "SimuPN")
            identity = uri.partition("#")[0] if uri else None
            if identity and identity not in seen:
                seen.add(identity)
                kept.append(outbound)
        if kept:
            config = dict(config)
            config["outbounds"] = kept
            result.append(config)
    return result


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
        configs = extract_vless_subscription(raw_text)
    if not configs:
        raise ValueError("Could not extract JSON or VLESS configurations")
    remarks_markers = raw_text.count('"remarks"')
    if remarks_markers and len(configs) != remarks_markers:
        raise ValueError(
            f"Liberty response looks partial: {len(configs)} configs for "
            f"{remarks_markers} remarks markers"
        )
    return configs


def maybe_decode_subscription(raw_text):
    compact = "".join(raw_text.split())
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"
    if not compact or any(character not in alphabet for character in compact):
        return raw_text
    try:
        decoded = base64.urlsafe_b64decode(
            compact + "=" * (-len(compact) % 4)
        ).decode("utf-8-sig")
        return decoded if "vless://" in decoded else raw_text
    except (ValueError, UnicodeDecodeError):
        return raw_text


def extract_vless_subscription(raw_text):
    """Convert plain or Base64 VLESS subscriptions to the internal Xray shape."""
    configs = []
    for line in maybe_decode_subscription(raw_text).splitlines():
        line = line.strip()
        if not line.startswith("vless://"):
            continue
        try:
            parsed = urlsplit(line)
            params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
            user_id = unquote(parsed.username or "")
            if not user_id or not parsed.hostname or not parsed.port:
                continue
            network = params.get("type", "tcp").lower()
            security = params.get("security", "none").lower()
            stream = {"network": network, "security": security}
            if security == "reality":
                stream["realitySettings"] = {
                    "serverName": params.get("sni"),
                    "fingerprint": params.get("fp", "chrome"),
                    "publicKey": params.get("pbk"),
                    "shortId": params.get("sid"),
                    "spiderX": params.get("spx"),
                }
            elif security == "tls":
                stream["tlsSettings"] = {
                    "serverName": params.get("sni"),
                    "fingerprint": params.get("fp", "chrome"),
                }
            transport_key = {
                "ws": "wsSettings", "grpc": "grpcSettings",
                "xhttp": "xhttpSettings", "httpupgrade": "httpupgradeSettings",
            }.get(network)
            if transport_key:
                stream[transport_key] = {
                    key: params[key] for key in (
                        "path", "host", "serviceName", "authority", "mode"
                    ) if params.get(key)
                }
            configs.append({
                "remarks": unquote(parsed.fragment) or parsed.hostname,
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": parsed.hostname, "port": parsed.port,
                        "users": [{
                            "id": user_id,
                            "encryption": params.get("encryption", "none"),
                            **({"flow": params["flow"]} if params.get("flow") else {}),
                        }],
                    }]},
                    "streamSettings": stream,
                }],
                "routing": {},
            })
        except (TypeError, ValueError):
            continue
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
            "source": outbound.get("_simupn_source") or "liberty",
            "source_short": outbound.get("_simupn_source_short") or "LIB",
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
    if measurement.get("overloaded"):
        label = f"🟠 резерв • {label}"
    label = f"[{record.get('source_short') or 'SRC'}] {label}"
    return record["identity"] + "#" + quote(label, safe="")


def inferred_exit_country(record, measurement):
    """Return a verified or explicitly named exit country, if known."""
    measured = measurement.get("exit_country")
    if measured:
        return str(measured).upper()
    label = record["label"].casefold()
    if "russia" in label:
        return "RU"
    for code, name in COUNTRY_NAMES_RU.items():
        if name.casefold() in label:
            return code
    return None


def build_subscription(configs, measurements=None, confirmed_non_russian_only=False):
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

    def is_allowed_country(record):
        if not confirmed_non_russian_only:
            return True
        country = inferred_exit_country(
            record, servers_measurements.get(record["key"], {})
        )
        # Karing auto-select must never see an RU or unknown exit: an unknown
        # technical node could otherwise resolve to Russia on the next run.
        return country is not None and country != "RU"

    def sort_key(item):
        index, record = item
        data = servers_measurements.get(record["key"], {})
        stream = record["outbound"].get("streamSettings") or {}
        network = str(stream.get("network") or "tcp").lower()
        security = str(stream.get("security") or "none").lower()
        # GitHub can reach WS/XHTTP nodes that Russian mobile operators do not.
        # Prefer the TCP/Reality transport proven to work on the target iPhone;
        # keep other transports available as reserves.
        transport_tier = 0 if (network, security) == ("tcp", "reality") else 1
        latency = data.get("latency_ms")
        speed = data.get("speed_mbps")
        tunnel_ok = bool(data.get("tunnel_ok"))
        overloaded = bool(data.get("overloaded"))
        failures = int(data.get("consecutive_failures") or 0)
        russian_exit = data.get("exit_country") == "RU"
        exit_penalty = 500 if russian_exit or "росси" in record["label"].casefold() else 0
        if record["label"].startswith("proxy-") and not data.get("exit_country"):
            exit_penalty = max(exit_penalty, 300)
        if tunnel_ok:
            score = (latency if latency is not None else 500) + 160 / max(speed or 0.5, 0.5)
            return (1 if overloaded else 0, transport_tier, score + exit_penalty, index)
        if latency is not None and failures < 2:
            return (1, transport_tier, latency + exit_penalty, index)
        return (2, transport_tier, location_priority(record["label"]), index)

    publishable = [
        record for record in records
        if is_publishable(record) and is_allowed_country(record)
    ]
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
        "RemoteDNSDomain": "https://8.8.8.8/dns-query",
        "RemoteDNSIP": "8.8.8.8",
        "DomesticDNSType": "DoU",
        "DomesticDNSDomain": "",
        "DomesticDNSIP": "77.88.8.8",
        "Geositeurl": (
            "https://raw.githubusercontent.com/dfantomasd/SimuPN/main/"
            "routing-data/geosite.dat"
        ),
        "Geoipurl": (
            "https://raw.githubusercontent.com/dfantomasd/SimuPN/main/"
            "routing-data/geoip.dat"
        ),
        "LastUpdated": "1787410061",
        "DnsHosts": {
            "lkfl2.nalog.ru": "213.24.64.175",
            "lknpd.nalog.ru": "213.24.64.181",
        },
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


def generate(source_bytes, output_dir=Path("."), measurements=None, sources_report=None):
    configs = json.loads(source_bytes.decode("utf-8-sig"))
    if not isinstance(configs, list):
        raise ValueError("Liberty source must contain a JSON array")
    node_lines = build_subscription(configs, measurements)
    if not node_lines:
        raise ValueError("source contains no valid VLESS outbounds")
    source_count = len(server_records(configs))
    if not sources_report:
        specs_by_name = {item["name"]: item for item in source_specs()}
        counts = {}
        for record in server_records(configs):
            name = record.get("source") or "unknown"
            counts[name] = counts.get(name, 0) + 1
        sources_report = [
            {
                "name": name,
                "short": str(specs_by_name.get(name, {}).get("short") or name[:3]).upper(),
                "url": specs_by_name.get(name, {}).get("url"),
                "status": "snapshot",
                "nodes": count,
            }
            for name, count in sorted(counts.items())
        ]
    minimum = min(5, source_count)
    if len(node_lines) < minimum:
        raise ValueError(
            f"refusing to replace the last-known-good subscription: only "
            f"{len(node_lines)} of {source_count} nodes are publishable"
        )
    karing_node_lines = build_subscription(
        configs, measurements, confirmed_non_russian_only=True
    )
    if len(karing_node_lines) < minimum:
        raise ValueError(
            f"refusing to replace the last-known-good Karing subscription: "
            f"only {len(karing_node_lines)} confirmed non-RU nodes"
        )

    lines = [
        routing_link(configs),
        "#routing-enable: 1",
        "#profile-update-interval: 1",
        "#subscription-auto-update-open-enable: 1",
        "#profile-title: SimuPN",
        *node_lines,
    ]
    plain = ("\n".join(lines) + "\n").encode()
    output_dir.joinpath("whitelist_configs_combined.json").write_bytes(source_bytes)
    output_dir.joinpath("subscription.txt").write_bytes(plain)
    output_dir.joinpath("subscription_base64.txt").write_text(
        base64.b64encode(plain).decode() + "\n", encoding="utf-8"
    )
    karing_plain = ("\n".join(karing_node_lines) + "\n").encode()
    output_dir.joinpath("subscription_karing_plain.txt").write_bytes(karing_plain)
    output_dir.joinpath("subscription_karing.txt").write_text(
        base64.b64encode(karing_plain).decode() + "\n", encoding="utf-8"
    )
    profile = routing_profile(configs)
    output_dir.joinpath("routing.json").write_text(
        json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    output_dir.joinpath("routing.txt").write_text(
        routing_link(configs) + "\n", encoding="utf-8"
    )
    status = {
        "source": "multi-source",
        "sources": sources_report,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "server_count": len(node_lines),
        "karing_server_count": len(karing_node_lines),
        "karing_filter": "confirmed non-RU exits only",
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
    sources_report = []
    if args.source_file:
        source = load_source(args.source_file)
    else:
        source, sources_report = load_catalogs()
    measurements = None
    if args.measurements and Path(args.measurements).exists():
        measurements = json.loads(Path(args.measurements).read_text())
    lines = generate(source, measurements=measurements, sources_report=sources_report)
    print(f"Built {len(lines)} unique VLESS servers from {max(1, len(sources_report))} source(s)")


if __name__ == "__main__":
    main()
