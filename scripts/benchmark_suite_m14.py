#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
from pathlib import Path


SCENARIOS = {
    "mixed": "/health=20,/metrics=5,/indicators?limit=100&offset=0=25,/indicators/json?type=ip&limit=500&offset=0=30,/correlations?min_sources=2&limit=100=20",
    "indicator_heavy": "/indicators/json?type=ip&limit=500&offset=0=55,/indicators?limit=100&offset=0=35,/correlations?min_sources=2&limit=100=5,/health=3,/metrics=2",
    "control_light": "/health=60,/metrics=40",
}


def run_once(script: Path, base_url: str, duration: int, concurrency: int, timeout: float, scenario: str, out_file: Path) -> dict:
    cmd = [
        "python3",
        str(script),
        "--base-url",
        base_url,
        "--duration",
        str(duration),
        "--concurrency",
        str(concurrency),
        "--timeout",
        str(timeout),
        "--scenario",
        scenario,
        "--output-json",
        str(out_file),
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(out_file.read_text(encoding="utf-8"))


def median_report(results: list[dict]) -> dict:
    rps = [float(x["throughput_rps"]) for x in results]
    err = [float(x["error_rate"]) for x in results]
    p50 = [float(x["latency_ms"]["p50"]) for x in results]
    p95 = [float(x["latency_ms"]["p95"]) for x in results]
    p99 = [float(x["latency_ms"]["p99"]) for x in results]
    return {
        "runs": len(results),
        "throughput_rps_median": round(statistics.median(rps), 2),
        "error_rate_median": round(statistics.median(err), 6),
        "latency_ms_median": {
            "p50": round(statistics.median(p50), 2),
            "p95": round(statistics.median(p95), 2),
            "p99": round(statistics.median(p99), 2),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="M14 benchmark suite (multi-scenario, multi-run)")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--duration", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--output-dir", default="/tmp/m14-suite")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    script = Path(__file__).with_name("benchmark_m12.py")

    suite: dict[str, dict] = {}
    for scenario_name, scenario_expr in SCENARIOS.items():
        per_run: list[dict] = []
        for i in range(args.runs):
            out_file = out_dir / f"{scenario_name}-run-{i+1}.json"
            per_run.append(
                run_once(
                    script=script,
                    base_url=args.base_url,
                    duration=args.duration,
                    concurrency=args.concurrency,
                    timeout=args.timeout,
                    scenario=scenario_expr,
                    out_file=out_file,
                )
            )
        suite[scenario_name] = median_report(per_run)

    output = {
        "base_url": args.base_url,
        "duration": args.duration,
        "concurrency": args.concurrency,
        "runs_per_scenario": args.runs,
        "scenarios": suite,
    }
    rendered = json.dumps(output, indent=2, sort_keys=True)
    print(rendered)
    (out_dir / "suite-summary.json").write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
