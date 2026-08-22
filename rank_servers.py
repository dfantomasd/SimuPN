#!/usr/bin/env python3
"""Measure Liberty nodes and persist a conservative Moscow-oriented ranking."""

import argparse
import copy
import json
import shutil
import socket
import statistics
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import update_subscription


GLOBALPING_API = "https://api.globalping.io/v1/measurements"
SPEED_TEST_URL = "https://speed.cloudflare.com/__down?bytes=524288"
EXIT_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
SERVICE_CHECKS = {
    # Gemini needs both the web frontend and the Google Generative Language API.
    "gemini": (
        "https://gemini.google.com/app",
        "https://generativelanguage.googleapis.com/",
    ),
    "telegram": ("https://telegram.org/",),
    "youtube": ("https://www.youtube.com/generate_204",),
    "instagram": ("https://www.instagram.com/",),
    "chatgpt": ("https://chatgpt.com/",),
}


def api_json(url, payload=None, timeout=30):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "VPN_BEST Moscow ranker/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def measure_moscow_tcp(address, port):
    """Return median TCP RTT from two public probes in Moscow."""
    payload = {
        "type": "ping",
        "target": address,
        "locations": [{"country": "RU", "city": "Moscow", "limit": 2}],
        "measurementOptions": {"packets": 3, "protocol": "TCP", "port": port},
        "timeout": 10,
    }
    created = api_json(GLOBALPING_API, payload)
    measurement_id = created["id"]
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        time.sleep(0.6)
        result = api_json(f"{GLOBALPING_API}/{measurement_id}")
        if result.get("status") != "in-progress":
            break
    else:
        raise TimeoutError("Globalping measurement did not finish")

    samples, losses = [], []
    for item in result.get("results") or []:
        measured = item.get("result") or {}
        stats = measured.get("stats") or {}
        if measured.get("status") == "finished" and stats.get("avg") is not None:
            samples.append(float(stats["avg"]))
            losses.append(float(stats.get("loss") or 0))
    if not samples:
        raise RuntimeError("No successful Moscow probes")
    return {
        "latency_ms": round(statistics.median(samples), 2),
        "packet_loss": round(statistics.mean(losses), 2),
        "moscow_probes": len(samples),
    }


def measure_all_moscow(records, workers=6):
    unique = {(record["address"], record["port"]) for record in records}
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(measure_moscow_tcp, address, port): (address, port)
            for address, port in unique if address and port
        }
        for future in as_completed(futures):
            endpoint = futures[future]
            try:
                results[endpoint] = future.result()
            except Exception as exc:
                results[endpoint] = {"latency_error": str(exc)[:180]}
    return results


def xray_config(records, base_port):
    inbounds, outbounds, rules = [], [], []
    for index, record in enumerate(records):
        inbound_tag, outbound_tag = f"rank-in-{index}", f"rank-out-{index}"
        inbounds.append({
            "listen": "127.0.0.1",
            "port": base_port + index,
            "protocol": "socks",
            "tag": inbound_tag,
            "settings": {"auth": "noauth", "udp": True},
        })
        outbound = copy.deepcopy(record["outbound"])
        outbound["tag"] = outbound_tag
        outbounds.append(outbound)
        rules.append({
            "type": "field",
            "inboundTag": [inbound_tag],
            "outboundTag": outbound_tag,
        })
    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


def wait_for_xray(process, ports, timeout=8):
    deadline = time.monotonic() + timeout
    pending = set(ports)
    while pending and time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Xray exited before opening test ports")
        for port in list(pending):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                    pending.remove(port)
            except OSError:
                pass
        if pending:
            time.sleep(0.15)
    if pending:
        raise TimeoutError(f"Xray did not open {len(pending)} test ports")


def curl_status(port, url):
    """Return an HTTP status through one tested VLESS tunnel.

    A 4xx response still proves that the service is reachable (ChatGPT commonly
    returns 403 to a non-browser GitHub runner). 5xx and transport failures do
    not prove that the mobile app can use the node.
    """
    completed = subprocess.run(
        [
            "curl", "--silent", "--show-error", "--location", "--http1.1",
            "--socks5-hostname", f"127.0.0.1:{port}",
            "--connect-timeout", "5", "--max-time", "10",
            "--output", "/dev/null", "--write-out", "%{http_code}", url,
        ],
        text=True, capture_output=True, timeout=15,
    )
    try:
        code = int(completed.stdout.strip())
    except ValueError:
        code = 0
    return {
        "ok": completed.returncode == 0 and 200 <= code < 500,
        "code": code,
        **({} if completed.returncode == 0 else {
            "error": completed.stderr.strip()[:120] or f"curl {completed.returncode}"
        }),
    }


def check_services(port):
    services = {}
    for name, urls in SERVICE_CHECKS.items():
        attempts = [curl_status(port, url) for url in urls]
        services[name] = {
            "ok": all(attempt["ok"] for attempt in attempts),
            "codes": [attempt["code"] for attempt in attempts],
        }
        errors = [attempt.get("error") for attempt in attempts if attempt.get("error")]
        if errors:
            services[name]["error"] = "; ".join(errors)[:180]
    return services


def curl_speed(port):
    command = [
        "curl", "--silent", "--show-error", "--location", "--http1.1",
        "--socks5-hostname", f"127.0.0.1:{port}",
        "--connect-timeout", "5", "--max-time", "15",
        "--output", "/dev/null", "--write-out",
        "%{http_code} %{size_download} %{speed_download} %{time_total}",
        SPEED_TEST_URL,
    ]
    completed = subprocess.run(command, text=True, capture_output=True, timeout=20)
    if completed.returncode != 0:
        return {"tunnel_ok": False, "speed_error": completed.stderr.strip()[:180]}
    code, size, bytes_per_second, elapsed = completed.stdout.strip().split()
    ok = code == "200" and float(size) >= 400_000
    result = {
        "tunnel_ok": ok,
        "speed_mbps": round(float(bytes_per_second) * 8 / 1_000_000, 2) if ok else None,
        "download_bytes": int(float(size)),
        "download_seconds": round(float(elapsed), 3),
        **({} if ok else {"speed_error": f"HTTP {code}, {size} bytes"}),
    }
    if ok:
        trace = subprocess.run(
            [
                "curl", "--silent", "--show-error", "--location", "--http1.1",
                "--socks5-hostname", f"127.0.0.1:{port}",
                "--connect-timeout", "5", "--max-time", "10", EXIT_TRACE_URL,
            ],
            text=True, capture_output=True, timeout=15,
        )
        if trace.returncode == 0:
            values = dict(
                line.split("=", 1) for line in trace.stdout.splitlines() if "=" in line
            )
            result["exit_ip"] = values.get("ip")
            result["exit_country"] = values.get("loc")
        result["services"] = check_services(port)
    return result


def measure_tunnel_speeds(records, xray_path, workers=8):
    if not xray_path or not Path(xray_path).exists() or not shutil.which("curl"):
        return {}, False
    base_port = 18080
    with tempfile.TemporaryDirectory() as directory:
        config_path = Path(directory) / "rank-config.json"
        log_path = Path(directory) / "xray.log"
        config_path.write_text(json.dumps(xray_config(records, base_port)))
        with log_path.open("w") as log:
            process = subprocess.Popen(
                [str(Path(xray_path).resolve()), "run", "-c", str(config_path)],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                wait_for_xray(process, [base_port + i for i in range(len(records))])
                results = {}
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = {
                        pool.submit(curl_speed, base_port + index): record["key"]
                        for index, record in enumerate(records)
                    }
                    for future in as_completed(futures):
                        key = futures[future]
                        try:
                            results[key] = future.result()
                        except Exception as exc:
                            results[key] = {"tunnel_ok": False, "speed_error": str(exc)[:180]}
                return results, True
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()


def load_previous(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError, TypeError):
        return {"servers": {}}


def merge_measurements(records, latency, speeds, speed_attempted, previous):
    now = datetime.now(timezone.utc).isoformat()
    old_servers = previous.get("servers") or {}
    servers = {}
    for record in records:
        key = record["key"]
        old = old_servers.get(key, {})
        endpoint = (record["address"], record["port"])
        current = {
            "label": record["label"],
            "address": record["address"],
            "port": record["port"],
        }
        latency_result = latency.get(endpoint, {})
        if latency_result.get("latency_ms") is not None:
            if old.get("latency_ms") is not None:
                latency_result["raw_latency_ms"] = latency_result["latency_ms"]
                latency_result["latency_ms"] = round(
                    float(old["latency_ms"]) * 0.6
                    + float(latency_result["latency_ms"]) * 0.4,
                    2,
                )
            current.update(latency_result)
        elif old.get("latency_ms") is not None:
            current.update({
                "latency_ms": old["latency_ms"],
                "packet_loss": old.get("packet_loss"),
                "moscow_probes": old.get("moscow_probes"),
                "latency_stale": True,
            })
        else:
            current.update(latency_result)

        if speed_attempted:
            speed = speeds.get(key, {"tunnel_ok": False, "speed_error": "No result"})
            if speed.get("tunnel_ok"):
                if speed.get("speed_mbps") is not None and old.get("speed_mbps") is not None:
                    speed["raw_speed_mbps"] = speed["speed_mbps"]
                    speed["speed_mbps"] = round(
                        float(old["speed_mbps"]) * 0.6
                        + float(speed["speed_mbps"]) * 0.4,
                        2,
                    )
                for field in ("exit_ip", "exit_country"):
                    if not speed.get(field) and old.get(field):
                        speed[field] = old[field]
                current.update(speed)
                current["consecutive_failures"] = 0
                current["verified_at"] = now
            else:
                failures = int(old.get("consecutive_failures") or 0) + 1
                current.update(speed)
                current["consecutive_failures"] = failures
                if old.get("tunnel_ok") and failures < 2:
                    current["tunnel_ok"] = True
                    current["speed_mbps"] = old.get("speed_mbps")
                    current["speed_stale"] = True
                    current["verified_at"] = old.get("verified_at")
                    current["exit_ip"] = old.get("exit_ip")
                    current["exit_country"] = old.get("exit_country")
        else:
            for field in (
                "tunnel_ok", "speed_mbps", "download_bytes", "download_seconds",
                "exit_ip", "exit_country", "services", "consecutive_failures", "verified_at",
            ):
                if field in old:
                    current[field] = old[field]
            current["speed_stale"] = bool(old)
        servers[key] = current
    return {
        "updated_at": now,
        "method": {
            "latency": "median TCP connect time from two Globalping probes in Moscow",
            "speed": "512 KiB HTTPS download through the full VLESS/Xray tunnel from GitHub Actions",
            "services": "HTTP reachability through each VLESS tunnel for Gemini, Telegram, YouTube, Instagram and ChatGPT",
            "policy": "keep all nodes; demote only after repeated tunnel failures",
        },
        "servers": servers,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-file", default="whitelist_configs_combined.json")
    parser.add_argument("--previous", default="measurements.json")
    parser.add_argument("--output", default="measurements.json")
    parser.add_argument("--xray")
    parser.add_argument("--skip-globalping", action="store_true")
    args = parser.parse_args()

    configs = json.loads(Path(args.source_file).read_text(encoding="utf-8-sig"))
    records = update_subscription.server_records(configs)
    previous = load_previous(args.previous)
    latency = {} if args.skip_globalping else measure_all_moscow(records)
    speeds, attempted = measure_tunnel_speeds(records, args.xray)
    result = merge_measurements(records, latency, speeds, attempted, previous)
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    working = sum(bool(value.get("tunnel_ok")) for value in result["servers"].values())
    measured = sum(value.get("latency_ms") is not None for value in result["servers"].values())
    compatible = sum(
        bool(value.get("services"))
        and all(item.get("ok") for item in value["services"].values())
        for value in result["servers"].values()
    )
    print(
        f"Ranked {len(records)} nodes: {working} tunnel-verified, "
        f"{compatible} all-services-compatible, {measured} Moscow latency results"
    )


if __name__ == "__main__":
    main()
