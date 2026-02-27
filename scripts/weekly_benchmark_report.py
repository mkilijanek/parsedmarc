#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def main() -> None:
    summary_path = Path("/tmp/m14-suite/suite-summary.json")
    out_dir = Path("artifacts")
    out_dir.mkdir(parents=True, exist_ok=True)
    history_path = out_dir / "benchmark-trends.json"
    report_path = out_dir / "weekly-benchmark-report.md"

    if not summary_path.exists():
        raise SystemExit(f"Missing benchmark summary: {summary_path}")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc).isoformat()
    point = {
        "generated_at": now,
        "base_url": summary.get("base_url"),
        "duration": summary.get("duration"),
        "concurrency": summary.get("concurrency"),
        "scenarios": summary.get("scenarios", {}),
    }

    history: list[dict] = []
    if history_path.exists():
        history = json.loads(history_path.read_text(encoding="utf-8"))
    history.append(point)
    # Keep one year of weekly points.
    history = history[-52:]
    history_path.write_text(json.dumps(history, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Weekly Benchmark Report",
        "",
        f"Generated: `{now}`",
        "",
        "## Latest Scenarios",
    ]
    latest = point["scenarios"]
    for name, values in latest.items():
        lines.append(f"- **{name}**: rps={values.get('throughput_rps_median')}, "
                     f"p95={values.get('latency_ms_median', {}).get('p95')} ms, "
                     f"error={values.get('error_rate_median')}")

    if len(history) >= 2:
        prev = history[-2].get("scenarios", {})
        lines.append("")
        lines.append("## Week-over-Week Delta")
        for name, values in latest.items():
            p = prev.get(name, {})
            curr_rps = float(values.get("throughput_rps_median", 0.0))
            prev_rps = float(p.get("throughput_rps_median", 0.0))
            curr_p95 = float(values.get("latency_ms_median", {}).get("p95", 0.0))
            prev_p95 = float(p.get("latency_ms_median", {}).get("p95", 0.0))
            lines.append(
                f"- **{name}**: rps_delta={curr_rps - prev_rps:+.2f}, p95_delta_ms={curr_p95 - prev_p95:+.2f}"
            )

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(report_path)


if __name__ == "__main__":
    main()
