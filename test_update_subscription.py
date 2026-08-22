import json
import base64
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import update_subscription


class MirrorTests(unittest.TestCase):
    def test_extracts_and_deduplicates_liberty_html_cards(self):
        first = {"remarks": "France", "outbounds": [], "routing": {}}
        replacement = {"remarks": "France", "outbounds": [{"protocol": "freedom"}], "routing": {}}
        second = {"remarks": "Finland", "outbounds": [], "routing": {}}
        page = "<html data-a='{}' data-b='{}' data-c='{}'></html>".format(
            json.dumps(first), json.dumps(second), json.dumps(replacement)
        )
        configs = update_subscription.deduplicate_configs(
            update_subscription.extract_configs(page)
        )
        self.assertEqual([item["remarks"] for item in configs], ["France", "Finland"])
        self.assertEqual(configs[0]["outbounds"], [{"protocol": "freedom"}])

    def test_preserves_reality_parameters_and_shared_uuid_nodes(self):
        def config(address, public_key, remarks):
            return {
                "remarks": remarks,
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": address,
                        "port": 443,
                        "users": [{
                            "id": "48235668-f3f0-4e7c-a8b2-190ddf7a5b37",
                            "encryption": "none",
                            "flow": "xtls-rprx-vision",
                        }],
                    }]},
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": "storage.yandex.net",
                            "publicKey": public_key,
                            "shortId": "abcd",
                            "fingerprint": "firefox",
                        },
                    },
                }],
            }

        lines = update_subscription.build_subscription([
            config("203.0.113.10", "key-one", "Poland"),
            config("203.0.113.11", "key-two", "Hungary"),
        ])
        self.assertEqual(len(lines), 2)
        query = parse_qs(urlsplit(lines[0]).query)
        self.assertEqual(query["flow"], ["xtls-rprx-vision"])
        self.assertEqual(query["sni"], ["storage.yandex.net"])
        self.assertEqual(query["fp"], ["firefox"])
        self.assertEqual(query["pbk"], ["key-one"])
        self.assertEqual(query["sid"], ["abcd"])

    def test_aggregate_and_individual_configs_are_exactly_deduplicated(self):
        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "203.0.113.10", "port": 443,
                "users": [{"id": "id", "encryption": "none"}],
            }]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {"serverName": "example.com", "publicKey": "key"},
            },
        }
        configs = [
            {"remarks": "aggregate", "outbounds": [outbound, dict(outbound)]},
            {"remarks": "named", "outbounds": [outbound]},
        ]
        self.assertEqual(len(update_subscription.build_subscription(configs)), 1)

    def test_ranking_prefers_verified_fast_node_and_keeps_reserve(self):
        def config(address, remarks):
            return {
                "remarks": remarks,
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": address, "port": 443,
                        "users": [{"id": "id", "encryption": "none"}],
                    }]},
                    "streamSettings": {
                        "network": "tcp", "security": "reality",
                        "realitySettings": {"serverName": "example.com", "publicKey": "key"},
                    },
                }],
            }

        configs = [
            config("203.0.113.1", "🇫🇮 Финляндия"),
            config("203.0.113.2", "🇩🇪 Германия"),
            config("203.0.113.3", "🇫🇷 Франция"),
        ]
        records = update_subscription.server_records(configs)
        measurements = {"servers": {
            records[0]["key"]: {"latency_ms": 35, "consecutive_failures": 2},
            records[1]["key"]: {"latency_ms": 55, "speed_mbps": 20, "tunnel_ok": True},
            records[2]["key"]: {"latency_ms": 80, "speed_mbps": 2, "tunnel_ok": True},
        }}
        lines = update_subscription.build_subscription(configs, measurements)
        self.assertIn("203.0.113.2", lines[0])
        self.assertIn("20.0%20Mbps", lines[0])
        self.assertIn("203.0.113.3", lines[1])
        self.assertIn("203.0.113.1", lines[2])

    def test_russian_exit_is_demoted_even_when_fast(self):
        def config(address, remarks):
            return {
                "remarks": remarks,
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": address, "port": 443,
                        "users": [{"id": "id", "encryption": "none"}],
                    }]},
                    "streamSettings": {
                        "network": "tcp", "security": "reality",
                        "realitySettings": {"serverName": "example.com", "publicKey": "key"},
                    },
                }],
            }
        configs = [config("203.0.113.1", "Fast unknown"), config("203.0.113.2", "Finland")]
        records = update_subscription.server_records(configs)
        measurements = {"servers": {
            records[0]["key"]: {
                "latency_ms": 5, "speed_mbps": 50, "tunnel_ok": True,
                "exit_country": "RU",
            },
            records[1]["key"]: {
                "latency_ms": 30, "speed_mbps": 10, "tunnel_ok": True,
                "exit_country": "FI",
            },
        }}
        lines = update_subscription.build_subscription(configs, measurements)
        self.assertIn("203.0.113.2", lines[0])

    def test_tcp_reality_is_preferred_over_faster_websocket_on_mobile(self):
        def config(address, network, security, remarks):
            stream = {"network": network, "security": security}
            if security == "reality":
                stream["realitySettings"] = {
                    "serverName": "example.com", "publicKey": "key"
                }
            else:
                stream["tlsSettings"] = {"serverName": "example.com"}
                stream["wsSettings"] = {"path": "/vpn"}
            return {
                "remarks": remarks,
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": address, "port": 443,
                        "users": [{"id": "id", "encryption": "none"}],
                    }]},
                    "streamSettings": stream,
                }],
            }
        configs = [
            config("203.0.113.1", "ws", "tls", "Fast from GitHub"),
            config("203.0.113.2", "tcp", "reality", "Mobile compatible"),
        ]
        records = update_subscription.server_records(configs)
        measurements = {"servers": {
            records[0]["key"]: {
                "latency_ms": 4, "speed_mbps": 50, "tunnel_ok": True,
                "exit_country": "DE",
            },
            records[1]["key"]: {
                "latency_ms": 40, "speed_mbps": 2, "tunnel_ok": True,
                "exit_country": "FI",
            },
        }}
        lines = update_subscription.build_subscription(configs, measurements)
        self.assertIn("203.0.113.2", lines[0])

    def test_service_diagnostics_do_not_change_speed_ranking(self):
        def config(address, remarks):
            return {
                "remarks": remarks,
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": address, "port": 443,
                        "users": [{"id": "id", "encryption": "none"}],
                    }]},
                    "streamSettings": {
                        "network": "tcp", "security": "reality",
                        "realitySettings": {"serverName": "example.com", "publicKey": "key"},
                    },
                }],
            }
        configs = [config("203.0.113.1", "Fast"), config("203.0.113.2", "Compatible")]
        records = update_subscription.server_records(configs)
        ok_services = {
            name: {"ok": True} for name in ("gemini", "telegram", "youtube", "instagram", "chatgpt")
        }
        blocked_services = dict(ok_services)
        blocked_services["gemini"] = {"ok": False}
        measurements = {"servers": {
            records[0]["key"]: {
                "latency_ms": 5, "speed_mbps": 50, "tunnel_ok": True,
                "services": blocked_services,
            },
            records[1]["key"]: {
                "latency_ms": 60, "speed_mbps": 5, "tunnel_ok": True,
                "services": ok_services,
            },
        }}
        lines = update_subscription.build_subscription(configs, measurements)
        self.assertIn("203.0.113.1", lines[0])

    def test_unpublishable_node_is_excluded(self):
        def config(address):
            return {
                "remarks": address,
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": address, "port": 443,
                        "users": [{"id": "id", "encryption": "none"}],
                    }]},
                    "streamSettings": {
                        "network": "tcp", "security": "reality",
                        "realitySettings": {"serverName": "example.com", "publicKey": "key"},
                    },
                }],
            }
        configs = [config("203.0.113.1"), config("203.0.113.2")]
        records = update_subscription.server_records(configs)
        measurements = {"servers": {
            records[0]["key"]: {"publishable": False, "consecutive_failures": 3},
            records[1]["key"]: {"publishable": True, "tunnel_ok": True},
        }}
        lines = update_subscription.build_subscription(configs, measurements)
        self.assertEqual(len(lines), 1)
        self.assertIn("203.0.113.2", lines[0])

    def test_technical_node_without_exit_country_is_reserve(self):
        def config(address, remarks):
            return {
                "remarks": remarks,
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": address, "port": 443,
                        "users": [{"id": "id", "encryption": "none"}],
                    }]},
                    "streamSettings": {
                        "network": "tcp", "security": "reality",
                        "realitySettings": {"serverName": "example.com", "publicKey": "key"},
                    },
                }],
            }
        configs = [config("203.0.113.1", "proxy-wl-unknown"), config("203.0.113.2", "Finland")]
        records = update_subscription.server_records(configs)
        measurements = {"servers": {
            records[0]["key"]: {"latency_ms": 2, "speed_mbps": 50, "tunnel_ok": True},
            records[1]["key"]: {
                "latency_ms": 30, "speed_mbps": 10, "tunnel_ok": True,
                "exit_country": "FI",
            },
        }}
        lines = update_subscription.build_subscription(configs, measurements)
        self.assertIn("203.0.113.2", lines[0])
        self.assertIn("Liberty%20%E2%80%A2%20%D1%80%D0%B5%D0%B7%D0%B5%D1%80%D0%B2", lines[1])

    def test_minimal_routing_keeps_russia_direct_and_required_apps_proxied(self):
        configs = [{
            "routing": {"rules": [{
                "outboundTag": "direct",
                "domain": [
                    "domain:ozon.ru", "domain:wildberries.ru", "domain:sberbank.ru",
                    "geosite:category-ru",
                ],
            }]},
        }]
        profile = update_subscription.routing_profile(configs)
        self.assertEqual(profile["Name"], "Russia")
        self.assertEqual(profile["GlobalProxy"], "false")
        self.assertNotIn("UseChunkFiles", profile)
        self.assertRegex(profile["LastUpdated"], r"^\d{9,11}$")
        self.assertTrue(profile["Geositeurl"].startswith("https://"))
        self.assertTrue(profile["Geoipurl"].startswith("https://"))
        self.assertIn("raw.githubusercontent.com/dfantomasd/VPN_BEST", profile["Geositeurl"])
        self.assertIn("raw.githubusercontent.com/dfantomasd/VPN_BEST", profile["Geoipurl"])
        self.assertIn("/main/", profile["Geositeurl"])
        self.assertIn("/main/", profile["Geoipurl"])
        self.assertEqual(profile["RemoteDNSDomain"], "https://8.8.8.8/dns-query")
        self.assertIn("domain:ozon.ru", profile["DirectSites"])
        self.assertIn("domain:wildberries.ru", profile["DirectSites"])
        self.assertIn("geosite:category-ru", profile["DirectSites"])
        self.assertIn("geosite:category-bank-ru", profile["DirectSites"])
        self.assertIn("geosite:whitelist", profile["DirectSites"])
        self.assertIn("geoip:ru", profile["DirectIp"])
        for domain in (
            "domain:telegram.org", "domain:gemini.google.com", "domain:chatgpt.com",
            "geosite:youtube", "domain:googlevideo.com", "domain:instagram.com",
            "domain:cdninstagram.com", "geosite:ru-blocked",
            "geosite:ru-geoblock", "domain:claude.ai", "domain:reddit.com",
        ):
            self.assertIn(domain, profile["ProxySites"])
        self.assertIn("149.154.160.0/20", profile["ProxyIp"])
        self.assertIn("geoip:ru-blocked", profile["ProxyIp"])
        self.assertIn("geoip:ru-geoblock", profile["ProxyIp"])
        link = update_subscription.routing_link(configs)
        encoded = link.removeprefix("happ://routing/onadd/")
        decoded = json.loads(base64.b64decode(encoded))
        self.assertEqual(decoded["Name"], "Russia")
        self.assertLess(len(link), 4096)

    def test_generated_subscription_does_not_force_server_switching(self):
        def config(index):
            return {
                "remarks": f"node-{index}",
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": f"203.0.113.{index}", "port": 443,
                        "users": [{"id": f"id-{index}", "encryption": "none"}],
                    }]},
                    "streamSettings": {
                        "network": "tcp", "security": "reality",
                        "realitySettings": {"serverName": "example.com", "publicKey": "key"},
                    },
                }],
            }
        configs = [config(index) for index in range(1, 6)]
        source = (json.dumps(configs) + "\n").encode()
        with tempfile.TemporaryDirectory() as directory:
            update_subscription.generate(source, Path(directory))
            lines = Path(directory, "subscription.txt").read_text().splitlines()
        self.assertIn("#profile-update-interval: 1", lines)
        self.assertIn("#subscription-auto-update-open-enable: 1", lines)
        self.assertNotIn("#subscription-autoconnect: 1", lines)
        self.assertNotIn("#subscription-autoconnect-type: lowestdelay", lines)

    def test_generation_refuses_too_few_publishable_nodes(self):
        def config(index):
            return {
                "remarks": f"node-{index}",
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": f"203.0.113.{index}", "port": 443,
                        "users": [{"id": f"id-{index}", "encryption": "none"}],
                    }]},
                    "streamSettings": {
                        "network": "tcp", "security": "reality",
                        "realitySettings": {"serverName": "example.com", "publicKey": "key"},
                    },
                }],
            }
        configs = [config(index) for index in range(1, 7)]
        records = update_subscription.server_records(configs)
        measurements = {"servers": {
            record["key"]: {"publishable": index < 4}
            for index, record in enumerate(records)
        }}
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "last-known-good"):
                update_subscription.generate(
                    (json.dumps(configs) + "\n").encode(), Path(directory), measurements
                )

    def test_upstream_failure_uses_committed_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            fallback = Path(directory) / "whitelist_configs_combined.json"
            fallback.write_bytes(b'[{"outbounds": []}]')
            with mock.patch.object(update_subscription, "fetch_source", side_effect=OSError("gone")):
                self.assertEqual(
                    update_subscription.load_source(fallback_path=fallback),
                    fallback.read_bytes(),
                )

    def test_suspiciously_small_liberty_update_uses_snapshot(self):
        def config(address):
            return {
                "remarks": address,
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": address, "port": 443,
                        "users": [{"id": "id", "encryption": "none"}],
                    }]},
                    "streamSettings": {
                        "network": "tcp", "security": "reality",
                        "realitySettings": {"serverName": "example.com", "publicKey": "key"},
                    },
                }],
            }
        with tempfile.TemporaryDirectory() as directory:
            fallback = Path(directory) / "whitelist_configs_combined.json"
            fallback.write_text(json.dumps([config(f"203.0.113.{i}") for i in range(1, 21)]))
            tiny = json.dumps([config("198.51.100.1")]).encode()
            with mock.patch.object(update_subscription, "fetch_source", return_value=tiny):
                self.assertEqual(
                    update_subscription.load_source(fallback_path=fallback),
                    fallback.read_bytes(),
                )


if __name__ == "__main__":
    unittest.main()
