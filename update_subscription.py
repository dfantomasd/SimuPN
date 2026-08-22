#!/usr/bin/env python3
"""Mirror kenkaral45's VLESS catalog without ranking or filtering servers."""

import argparse
import base64
import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode


SOURCE_URL = (
    "https://raw.githubusercontent.com/kenkaral45/happ-subscription/"
    "main/whitelist_configs_combined.json"
)
PROXY_SITES = [
    "domain:t.me", "domain:telegram.me", "domain:telegram.org",
    "domain:telegram.dog", "domain:telegra.ph",
    "domain:gemini.google.com", "domain:generativelanguage.googleapis.com",
    "domain:accounts.google.com", "domain:ai.google.dev",
    "domain:googleapis.com", "domain:gstatic.com", "domain:googleusercontent.com",
    "domain:chatgpt.com", "domain:chat.openai.com", "domain:openai.com",
    "domain:oaistatic.com", "domain:oaiusercontent.com", "domain:auth0.com",
]
PROXY_IP = [
    "91.105.192.0/23", "91.108.4.0/22", "91.108.8.0/21",
    "91.108.16.0/21", "91.108.56.0/22", "95.161.64.0/20",
    "149.154.160.0/20", "185.76.151.0/24",
    "2001:67c:4e8::/48", "2001:b28:f23c::/47", "2001:b28:f23f::/48",
    "2a0a:f280::/32",
]
PRIVATE_IP = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
]


def fetch_source(url=SOURCE_URL):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "VPN_BEST exact-source-mirror/1.0",
            "Accept": "application/json",
            "Cache-Control": "no-cache",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


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
            entries.append((outbounds[0], config.get("remarks") or "kenkaral45"))
    for config in configs:
        for outbound in vless_outbounds(config):
            entries.append((outbound, outbound.get("tag") or config.get("remarks") or "kenkaral45"))
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


def build_subscription(configs):
    lines, identities = [], set()
    for outbound, label in ordered_entries(configs):
        uri = outbound_uri(outbound, label)
        if not uri:
            continue
        identity = uri.partition("#")[0]
        if identity in identities:
            continue
        identities.add(identity)
        lines.append(uri)
    return lines


def source_direct_domains(configs):
    for config in configs:
        for rule in (config.get("routing") or {}).get("rules") or []:
            domains = rule.get("domain")
            if rule.get("outboundTag") == "direct" and isinstance(domains, list):
                # Keep the source's explicit domain and regexp rules. Avoid
                # geosite dependencies in this deliberately minimal profile.
                return list(dict.fromkeys(
                    value for value in domains
                    if isinstance(value, str) and not value.startswith("geosite:")
                ))
    return ["domain:ru", "domain:xn--p1ai", "regexp:.*\\.ru$"]


def routing_profile(configs):
    return {
        "Name": "SIMUTIN",
        "GlobalProxy": "false",
        "UseChunkFiles": "false",
        "RemoteDns": "8.8.8.8",
        "DomesticDns": "77.88.8.8",
        "RemoteDNSType": "DoH",
        "RemoteDNSDomain": "https://8.8.8.8/dns-query",
        "RemoteDNSIP": "8.8.8.8",
        "DomesticDNSType": "DoU",
        "DomesticDNSDomain": "",
        "DomesticDNSIP": "77.88.8.8",
        "DnsHosts": {},
        "RouteOrder": "block-direct-proxy",
        "DirectSites": source_direct_domains(configs),
        "DirectIp": PRIVATE_IP,
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
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return "happ://routing/onadd/" + encoded


def generate(source_bytes, output_dir=Path(".")):
    configs = json.loads(source_bytes.decode("utf-8-sig"))
    if not isinstance(configs, list):
        raise ValueError("kenkaral45 source must contain a JSON array")
    node_lines = build_subscription(configs)
    if not node_lines:
        raise ValueError("source contains no valid VLESS outbounds")

    lines = [
        routing_link(configs),
        "#routing-enable: 1",
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
    status = {
        "source": SOURCE_URL,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "server_count": len(node_lines),
        "routing": "SIMUTIN minimal split tunnel",
    }
    output_dir.joinpath("status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return node_lines


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-file")
    args = parser.parse_args()
    source = Path(args.source_file).read_bytes() if args.source_file else fetch_source()
    lines = generate(source)
    print(f"Mirrored {len(lines)} unique VLESS servers from kenkaral45")


if __name__ == "__main__":
    main()
