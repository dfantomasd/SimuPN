import unittest

import rank_servers


class RankServersTests(unittest.TestCase):
    def record(self):
        return {
            "key": "node-key", "label": "Finland", "address": "203.0.113.1",
            "port": 443,
        }

    def test_success_resets_failure_counter(self):
        result = rank_servers.merge_measurements(
            [self.record()],
            {("203.0.113.1", 443): {"latency_ms": 42, "packet_loss": 0}},
            {"node-key": {"tunnel_ok": True, "speed_mbps": 12.5}},
            True,
            {"servers": {"node-key": {"consecutive_failures": 1}}},
        )["servers"]["node-key"]
        self.assertTrue(result["tunnel_ok"])
        self.assertEqual(result["consecutive_failures"], 0)
        self.assertEqual(result["latency_ms"], 42)

    def test_fresh_results_are_smoothed_to_prevent_hourly_reordering(self):
        previous = {"servers": {"node-key": {
            "latency_ms": 40, "tunnel_ok": True, "speed_mbps": 10,
            "consecutive_failures": 0, "exit_country": "FI",
        }}}
        result = rank_servers.merge_measurements(
            [self.record()],
            {("203.0.113.1", 443): {"latency_ms": 60, "packet_loss": 0}},
            {"node-key": {"tunnel_ok": True, "speed_mbps": 20}},
            True, previous,
        )["servers"]["node-key"]
        self.assertEqual(result["latency_ms"], 48)
        self.assertEqual(result["speed_mbps"], 14)
        self.assertEqual(result["exit_country"], "FI")

    def test_one_failed_run_keeps_previous_working_result(self):
        previous = {"servers": {"node-key": {
            "tunnel_ok": True, "speed_mbps": 9.5,
            "consecutive_failures": 0, "verified_at": "before",
        }}}
        result = rank_servers.merge_measurements(
            [self.record()], {},
            {"node-key": {"tunnel_ok": False, "speed_error": "temporary"}},
            True, previous,
        )["servers"]["node-key"]
        self.assertTrue(result["tunnel_ok"])
        self.assertTrue(result["speed_stale"])
        self.assertEqual(result["consecutive_failures"], 1)

    def test_second_failed_run_demotes_node(self):
        previous = {"servers": {"node-key": {
            "tunnel_ok": True, "speed_mbps": 9.5,
            "consecutive_failures": 1, "verified_at": "before",
        }}}
        result = rank_servers.merge_measurements(
            [self.record()], {},
            {"node-key": {"tunnel_ok": False, "speed_error": "again"}},
            True, previous,
        )["servers"]["node-key"]
        self.assertFalse(result["tunnel_ok"])
        self.assertEqual(result["consecutive_failures"], 2)


if __name__ == "__main__":
    unittest.main()
