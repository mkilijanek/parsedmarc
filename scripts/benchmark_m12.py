#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List


DEFAULT_SCENARIO = (
    "/health=20,"
    "/metrics=5,"
    "/indicators?limit=100&offset=0=25,"
    "/indicators/json?type=ip&limit=500&offset=0=30,"
    "/correlations?min_sources=2&limit=100=20"
)


@dataclass
class EndpointStats:
    requests: int = 0
    errors: int = 0
    statuses: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    latencies_ms: List[float] = field(default_factory=list)

    def observe(self, status: int, latency_ms: float):
        self.requests += 1
        self.statuses[status] += 1
        self.latencies_ms.append(latency_ms)
        if status >= 400:
            self.errors += 1


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    data = sorted(values)
    idx = int((len(data) - 1) * p)
    return data[idx]


def parse_scenario(scenario: str) -> List[str]:
    weighted: List[str] = []
    parts = [x.strip() for x in scenario.split(",") if x.strip()]
    for part in parts:
        if "=" not in part:
            raise ValueError(f"Invalid scenario part: {part}")
        path, weight_str = part.rsplit("=", 1)
        weight = int(weight_str)
        if weight < 1:
            raise ValueError(f"Weight must be >=1 for {path}")
        weighted.extend([path] * weight)
    if not weighted:
        raise ValueError("Scenario is empty")
    return weighted


def do_request(base_urls: List[str], path: str, timeout: float) -> tuple[int, float]:
    base_url = random.choice(base_urls)
    url = base_url.rstrip("/") + path
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            response.read()
            status = response.getcode()
    except urllib.error.HTTPError as e:
        status = int(e.code)
    except Exception:
        status = 599
    latency_ms = (time.perf_counter() - t0) * 1000.0
    return status, latency_ms


def run_benchmark(base_urls: List[str], duration_s: int, concurrency: int, timeout_s: float, weighted_paths: List[str]):
    stop_at = time.perf_counter() + duration_s
    lock = threading.Lock()
    per_endpoint: Dict[str, EndpointStats] = defaultdict(EndpointStats)
    total = EndpointStats()

    def worker():
        while time.perf_counter() < stop_at:
            path = random.choice(weighted_paths)
            status, latency_ms = do_request(base_urls, path, timeout_s)
            with lock:
                total.observe(status, latency_ms)
                per_endpoint[path].observe(status, latency_ms)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(concurrency)]
    start = time.perf_counter()
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    elapsed = max(0.001, time.perf_counter() - start)

    return total, per_endpoint, elapsed


def summarize(total: EndpointStats, per_endpoint: Dict[str, EndpointStats], elapsed_s: float) -> dict:
    total_rps = total.requests / elapsed_s
    out = {
        "elapsed_seconds": round(elapsed_s, 3),
        "requests_total": total.requests,
        "errors_total": total.errors,
        "error_rate": round((total.errors / total.requests) if total.requests else 0.0, 6),
        "throughput_rps": round(total_rps, 2),
        "latency_ms": {
            "p50": round(percentile(total.latencies_ms, 0.50), 2),
            "p95": round(percentile(total.latencies_ms, 0.95), 2),
            "p99": round(percentile(total.latencies_ms, 0.99), 2),
        },
        "status_codes": dict(sorted(total.statuses.items(), key=lambda kv: kv[0])),
        "endpoints": {},
    }
    for path, stats in sorted(per_endpoint.items(), key=lambda kv: kv[0]):
        rps = stats.requests / elapsed_s
        out["endpoints"][path] = {
            "requests": stats.requests,
            "errors": stats.errors,
            "error_rate": round((stats.errors / stats.requests) if stats.requests else 0.0, 6),
            "throughput_rps": round(rps, 2),
            "latency_ms": {
                "p50": round(percentile(stats.latencies_ms, 0.50), 2),
                "p95": round(percentile(stats.latencies_ms, 0.95), 2),
                "p99": round(percentile(stats.latencies_ms, 0.99), 2),
            },
            "status_codes": dict(sorted(stats.statuses.items(), key=lambda kv: kv[0])),
        }
    return out


def main():
    parser = argparse.ArgumentParser(description="M12 benchmark harness for IOC service")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8080",
        help="Single base URL or comma-separated URLs, e.g. http://127.0.0.1:8080,http://127.0.0.1:8081",
    )
    parser.add_argument("--duration", type=int, default=30, help="Benchmark duration in seconds")
    parser.add_argument("--concurrency", type=int, default=64, help="Number of concurrent workers")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds")
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO, help="Comma-separated path=weight scenario")
    parser.add_argument("--output-json", default="", help="Optional JSON output path")
    args = parser.parse_args()

    random.seed(42)
    weighted_paths = parse_scenario(args.scenario)

    base_urls = [u.strip() for u in args.base_url.split(",") if u.strip()]
    if not base_urls:
        raise ValueError("at least one base URL is required")

    total, per_endpoint, elapsed = run_benchmark(
        base_urls=base_urls,
        duration_s=args.duration,
        concurrency=args.concurrency,
        timeout_s=args.timeout,
        weighted_paths=weighted_paths,
    )
    report = summarize(total, per_endpoint, elapsed)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            f.write(rendered + "\n")


if __name__ == "__main__":
    main()
