#!/usr/bin/env python3
"""从探测结果里归纳规则.

输入是 fuzz_fields 产出的 CSV，输出是「每个字段的接受边界」——
把散落的「哪个值被拒了」变成一句可执行的结论。

用法:
    python -m tools.probe.rule_miner probe_result.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path


def _num(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def mine(rows: list[dict[str, str]]) -> dict[str, dict]:
    by_field: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_field[row["field"]].append(row)

    report: dict[str, dict] = {}
    for field, items in by_field.items():
        accepted = [r for r in items if r["verdict"] == "ACCEPT"]
        rejected = [r for r in items if r["verdict"] == "REJECT"]

        accepted_vals = sorted(
            (v for v in (_num(r["value"]) for r in accepted) if v is not None)
        )
        rejected_vals = sorted(
            (v for v in (_num(r["value"]) for r in rejected) if v is not None)
        )

        entry: dict = {
            "accepted": [r["value"] for r in accepted],
            "rejected": [r["value"] for r in rejected],
            "remarks": sorted({r["remark"] for r in rejected if r["remark"]}),
        }

        if accepted_vals:
            entry["accepted_min"] = min(accepted_vals)
            entry["accepted_max"] = max(accepted_vals)
        if rejected_vals:
            entry["rejected_min"] = min(rejected_vals)
            entry["rejected_max"] = max(rejected_vals)

        # 推断下界：所有被拒的值都小于所有被接受的值 → 存在最低要求
        if accepted_vals and rejected_vals and max(rejected_vals) < min(accepted_vals):
            entry["inferred"] = f"存在下界，介于 {max(rejected_vals)} 和 {min(accepted_vals)} 之间"
        elif accepted_vals and rejected_vals and min(rejected_vals) > max(accepted_vals):
            entry["inferred"] = f"存在上界，介于 {max(accepted_vals)} 和 {min(rejected_vals)} 之间"
        elif accepted_vals and not rejected_vals:
            entry["inferred"] = f"测过的值全部接受，下界 <= {min(accepted_vals)}"
        elif rejected_vals and not accepted_vals:
            entry["inferred"] = "测过的值全部被拒，需要换更接近合规的基准"
        else:
            entry["inferred"] = "接受与拒绝交错，可能还有其它字段联动"

        report[field] = entry

    return report


def render(report: dict[str, dict]) -> None:
    for field, entry in report.items():
        print(f"\n{'=' * 60}\n字段: {field}")
        print(f"  接受: {entry['accepted']}")
        print(f"  拒绝: {entry['rejected']}")
        if entry.get("inferred"):
            print(f"  推断: {entry['inferred']}")
        if entry.get("remarks"):
            print("  拒绝原因:")
            for r in entry["remarks"][:6]:
                print(f"    · {r}")


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="从探测结果归纳字段规则")
    parser.add_argument("csv", type=Path)
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    if not args.csv.exists():
        print(f"文件不存在: {args.csv}", file=sys.stderr)
        return 1

    with args.csv.open(encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))

    if not rows:
        print("CSV 为空")
        return 1

    report = mine(rows)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        render(report)
        print(f"\n共归纳 {len(report)} 个字段")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
