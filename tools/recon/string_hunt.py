#!/usr/bin/env python3
"""字符串定位：手上只有一句日志，找出它来自哪个 .so / dex.

真实场景：
    logcat 里看到 `E/lishang: start detect`，然后秒退。
    这时候你只知道一个 tag 和一个消息，需要立刻定位到具体的库。

做法是字节级搜索 —— 不要去 grep 文本，二进制里的字符串是连续 ASCII，
逐字节扫最可靠。

用法：
    recon-hunt lib/arm64-v8a/*.so --string lishang
    recon-hunt ./libs --string "start  detect" --string "ret --"
    recon-hunt app.apk --string lishang          # 支持直接扫 zip 内的条目
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

MIN_STRING_LEN = 4


@dataclass(slots=True)
class Hit:
    where: str
    needle: str
    count: int
    first_offset: int


def search_bytes(data: bytes, needle: bytes) -> tuple[int, int]:
    """返回 (命中次数, 首次偏移)；-1 表示未命中."""
    count = 0
    first = -1
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            break
        count += 1
        if first < 0:
            first = idx
        start = idx + 1
    return count, first


def iter_targets(path: Path):
    """产出 (显示名, 字节内容)."""
    if path.is_file() and path.suffix.lower() in (".apk", ".zip", ".jar", ".aar"):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if not name.endswith((".so", ".dex")):
                    continue
                try:
                    yield f"{path.name}!{name}", zf.read(name)
                except (KeyError, RuntimeError):
                    continue
        return

    files = [path] if path.is_file() else sorted(path.rglob("*"))
    for f in files:
        if not f.is_file():
            continue
        if f.suffix.lower() not in (".so", ".dex", ".bin", ".elf", ""):
            continue
        try:
            yield str(f), f.read_bytes()
        except OSError:
            continue


def extract_strings(data: bytes, min_len: int = MIN_STRING_LEN, limit: int = 400) -> list[str]:
    """提取可打印 ASCII 串，用于人工过一眼."""
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "replace"))
                if len(out) >= limit:
                    return out
            cur.clear()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", "replace"))
    return out[:limit]


def hunt(path: Path, needles: list[str], *, dump_strings: bool = False) -> list[Hit]:
    encoded = [(n, n.encode("utf-8")) for n in needles]
    hits: list[Hit] = []

    for where, data in iter_targets(path):
        matched_here: list[str] = []
        for text, needle in encoded:
            count, first = search_bytes(data, needle)
            if count:
                hits.append(Hit(where=where, needle=text, count=count, first_offset=first))
                matched_here.append(text)

        if dump_strings and matched_here:
            print(f"\n--- {where} 的字符串（命中 {', '.join(matched_here)}）---")
            for s in extract_strings(data)[:200]:
                print(f"  {s}")

    hits.sort(key=lambda h: (-h.count, h.where, h.needle))
    return hits


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="在 .so/.dex/APK 中做字节级字符串搜索")
    parser.add_argument("path", type=Path, help="文件、目录或 APK")
    parser.add_argument("--string", "-s", action="append", required=True, help="要搜索的字符串，可多次指定")
    parser.add_argument("--dump-strings", action="store_true", help="命中后打印该文件的可打印字符串")
    args = parser.parse_args(argv)

    if not args.path.exists():
        print(f"路径不存在: {args.path}", file=sys.stderr)
        return 1

    hits = hunt(args.path, args.string, dump_strings=args.dump_strings)
    if not hits:
        print("未命中任何目标")
        return 1

    print(f"\n{'文件':<70}{'字符串':<20}{'次数':>6}{'首个偏移':>12}")
    print("-" * 110)
    for h in hits:
        where = h.where if len(h.where) <= 68 else "..." + h.where[-65:]
        print(f"{where:<70}{h.needle:<20}{h.count:>6}{hex(h.first_offset):>12}")

    print(f"\n命中 {len(hits)} 处。下一步：用 recon-elf 分析导出符号")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
