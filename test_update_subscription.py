import json
import base64
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import update_subscription


class MirrorTests(unittest.TestCase):
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
        self.assertEqual(profile["UseChunkFiles"], "true")
        self.assertRegex(profile["LastUpdated"], r"^\d{9,11}$")
        self.assertTrue(profile["Geositeurl"].startswith("https://"))
        self.assertTrue(profile["Geoipurl"].startswith("https://"))
        self.assertIn("domain:ozon.ru", profile["DirectSites"])
        self.assertIn("domain:wildberries.ru", profile["DirectSites"])
        self.assertNotIn("geosite:category-ru", profile["DirectSites"])
        for domain in ("domain:telegram.org", "domain:gemini.google.com", "domain:chatgpt.com"):
            self.assertIn(domain, profile["ProxySites"])
        self.assertIn("149.154.160.0/20", profile["ProxyIp"])
        link = update_subscription.routing_link(configs)
        encoded = link.removeprefix("happ://routing/onadd/")
        decoded = json.loads(base64.b64decode(encoded))
        self.assertEqual(decoded["Name"], "Russia")

    def test_upstream_failure_uses_committed_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            fallback = Path(directory) / "whitelist_configs_combined.json"
            fallback.write_bytes(b'[{"outbounds": []}]')
            with mock.patch.object(update_subscription, "fetch_source", side_effect=OSError("gone")):
                self.assertEqual(
                    update_subscription.load_source(fallback_path=fallback),
                    fallback.read_bytes(),
                )


if __name__ == "__main__":
    unittest.main()
