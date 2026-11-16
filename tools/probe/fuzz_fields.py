#!/usr/bin/env python3
"""字段边界探测.

服务端拒绝请求时通常会返回一个原因（remark / msg），这就是天然的 oracle。
把同一个字段换成不同的值去试，从「接受/拒绝」的分布里就能反推出规则。

这个工具只负责三件事：发请求、记录结果、输出表。
签名怎么算由你提供 —— 用 --sign-cmd 挂一个外部脚本，或者先关掉签名。

配置示例（probe.json）:
{
  "url": "https://example.com/api/addRecord",
  "method": "POST",
  "headers": {"Authorization": "Bearer xxx"},
  "base_params": {
    "sportType": "1",
    "sportRange": "2.00",
    "sportTime": "720",
    "stepNumbers": "[120,120,120]"
  },
  "fields": {
    "sportRange": ["0.5", "1.0", "1.9", "2.0", "2.1", "5.0"],
    "sportTime": ["60", "300", "600", "720", "1800"],
    "stepNumbers": ["[0,0,0]", "[50,50,50]", "[120,120,120]", "[600,600,600]"]
  },
  "delay_s": 1.5
}

用法:
    python -m tools.probe.fuzz_fields probe.json -o result.csv
    python -m tools.probe.fuzz_fields probe.json --sign-cmd "python sign.py"
"""

from __future__ import annotations

import argparse
import csv
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    import httpx
except ImportError:
    print("需要 httpx: pip install httpx", file=sys.stderr)
    raise SystemExit(1)


def load_config(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    for key in ("url", "fields"):
        if key not in data:
            raise ValueError(f"配置缺少字段: {key}")
    data.setdefault("method", "POST")
    data.setdefault("headers", {})
    data.setdefault("base_params", {})
    data.setdefault("delay_s", 1.0)
    return data


def external_sign(params: dict[str, Any], cmd: str) -> dict[str, Any]:
    """调用外部脚本算签名.

    约定：把 params 以 JSON 从 stdin 传进去，脚本把补好签名的 JSON 打到 stdout。
    """
    payload = json.dumps(params, ensure_ascii=False)
    proc = subprocess.run(
        shlex.split(cmd), input=payload, capture_output=True, text=True, timeout=30, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(f"签名脚本失败: {proc.stderr[:300]}")
    return json.loads(proc.stdout)


def send(
    client: httpx.Client,
    cfg: dict[str, Any],
    params: dict[str, Any],
    *,
    sign_cmd: str | None,
) -> tuple[int, str, dict[str, Any]]:
    body = external_sign(params, sign_cmd) if sign_cmd else dict(params)
    method = cfg["method"].upper()
    url = cfg["url"]
    headers = cfg["headers"]

    try:
        if method == "GET":
            resp = client.get(url, params=body, headers=headers)
        else:
            resp = client.post(url, data=body, headers=headers)
    except httpx.HTTPError as exc:
        return -1, f"transport: {exc}", {}

    try:
        data = resp.json()
    except ValueError:
        data = {"_raw": resp.text[:300]}

    remark = ""
    for key in ("remark", "msg", "message", "returnMsg", "error"):
        if isinstance(data, dict) and data.get(key):
            remark = str(data[key])
            break
    return resp.status_code, remark, data


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="字段边界探测（用服务端拒绝原因反推规则）")
    parser.add_argument("config", type=Path, help="探测配置 JSON")
    parser.add_argument("-o", "--output", type=Path, default=Path("probe_result.csv"))
    parser.add_argument("--sign-cmd", help="外部签名命令（stdin/stdout 传 JSON）")
    parser.add_argument("--dry-run", action="store_true", help="只打印将要发送的组合，不发请求")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    base = dict(cfg["base_params"])
    fields: dict[str, list[Any]] = cfg["fields"]

    combos: list[tuple[str, Any]] = []
    for field, values in fields.items():
        for v in values:
            combos.append((field, v))

    print(f"接口: {cfg['method']} {cfg['url']}")
    print(f"基准参数: {len(base)} 个   待测字段: {len(fields)}   组合: {len(combos)}\n")

    if args.dry_run:
        for field, value in combos:
            print(f"  {field} = {value}")
        return 0

    rows = []
    with httpx.Client(timeout=20.0, follow_redirects=True) as client:
        for idx, (field, value) in enumerate(combos, 1):
            params = dict(base)
            params[field] = value
            status, remark, data = send(client, cfg, params, sign_cmd=args.sign_cmd)
            verdict = "?"
            if isinstance(data, dict):
                if str(data.get("code")) == "0" or str(data.get("returnCode")) == "200":
                    verdict = "ACCEPT"
                elif status == 200:
                    verdict = "REJECT"
            rows.append(
                {
                    "field": field,
                    "value": value,
                    "status": status,
                    "verdict": verdict,
                    "remark": remark,
                }
            )
            print(f"  [{idx}/{len(combos)}] {field}={value!r:<20} {status} {verdict:<7} {remark[:60]}")
            time.sleep(float(cfg["delay_s"]))

    with args.output.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=["field", "value", "status", "verdict", "remark"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n结果已写入 {args.output}")
    print("下一步: python -m tools.probe.rule_miner " + str(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
