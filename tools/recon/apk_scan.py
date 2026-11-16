#!/usr/bin/env python3
"""APK 侦察：这个包用了什么加固、有哪些检测库、集成了什么 SDK.

不依赖 apktool/aapt，直接读 zip 目录。目标是把「打开 APK 后先看什么」
这个动作标准化，避免每次都要人工翻 lib 目录。

用法：
    recon-scan app.apk
    recon-scan app.apk --json
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# ───────────────  特征库  ───────────────
# 只列「看到文件名就能定性」的，不做语义分析。宁缺毋滥。

PACKERS: dict[str, str] = {
    "libSecShell.so": "腾讯御安全 / 乐固 (SecShell)",
    "libshell.so": "腾讯御安全",
    "libjiagu.so": "360 加固",
    "libjiagu_x86.so": "360 加固 (x86)",
    "libDexHelper.so": "梆梆加固",
    "libDexHelper-x86.so": "梆梆加固 (x86)",
    "libsecexe.so": "梆梆企业版",
    "libnesec.so": "网易易盾",
    "libnqshield.so": "网易易盾 (新版)",
    "libmobisec.so": "阿里聚安全",
    "libsgmain.so": "阿里安全",
    "libexec.so": "爱加密",
    "libexecmain.so": "爱加密",
    "libkwscmm.so": "几维安全",
    "libkwscr.so": "几维安全",
    "libbaiduprotect.so": "百度加固",
    "libprotectClass.so": "百度加固",
}

DETECTORS: dict[str, str] = {
    "libemulator_check.so": "模拟器检测",
    "libantiemulator.so": "模拟器检测",
    "libfrida.so": "Frida 检测",
    "libfrida-gadget.so": "Frida gadget（调试用）",
    "librootcheck.so": "Root 检测",
    "libhookcheck.so": "Hook 检测",
    "libmsaoaidsec.so": "OAID/设备标识安全",
    "libdevInfo.so": "设备指纹采集",
    "libcommonV2DevInfo.so": "设备指纹采集",
    "libti-monitor.so": "设备风险监控",
    "libadscope_security.so": "广告安全",
    "libxeno_native.so": "Xeno 加固/校验",
    "libproperty_get.so": "属性读取（常配合检测）",
}

SDK_HINTS: dict[str, str] = {
    "libAMapSDK": "高德地图/定位",
    "libbdface_sdk.so": "百度人脸",
    "libavmdl_lite.so": "人脸/人脸模型",
    "libEasyAR.so": "EasyAR 增强现实",
    "libpaddle_light_api_shared.so": "PaddleLite 推理",
    "libBugly.so": "腾讯 Bugly",
    "libBugly_Native.so": "腾讯 Bugly Native",
    "libpanglearmor.so": "穿山甲广告加固",
    "libpangleflipped.so": "穿山甲广告",
    "libijkplayer.so": "B 站 ijkplayer",
    "libmmkv.so": "腾讯 MMKV",
    "libsqlcipher.so": "SQLCipher",
    "libjniPdfium.so": "PDF 渲染",
    "libhoudini.so": "ARM 转译层（x86 模拟器）",
    "libnb.so": "NativeBridge 转译",
}

# 一个包同时出现 2 个以上检测库，说明它的反作弊投入不低
HEAVY_DETECTION_THRESHOLD = 2


@dataclass(slots=True)
class ScanResult:
    apk: str
    size: int = 0
    abis: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    packers: dict[str, str] = field(default_factory=dict)
    detectors: dict[str, str] = field(default_factory=dict)
    sdks: dict[str, str] = field(default_factory=dict)
    dex_count: int = 0
    has_v1_sig: bool = False
    has_v2_sig: bool = False
    risk_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "apk": self.apk,
            "size_mb": round(self.size / 1024 / 1024, 2),
            "abis": self.abis,
            "native_lib_count": len(self.native_libs),
            "packers": self.packers,
            "detectors": self.detectors,
            "sdks": self.sdks,
            "dex_count": self.dex_count,
            "has_v1_sig": self.has_v1_sig,
            "has_v2_sig": self.has_v2_sig,
            "risk_notes": self.risk_notes,
        }


def scan(path: Path) -> ScanResult:
    result = ScanResult(apk=str(path), size=path.stat().st_size)

    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()

        result.dex_count = sum(1 for n in names if n.startswith("classes") and n.endswith(".dex"))
        result.has_v1_sig = any(n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC")) for n in names)
        # v2/v3 签名块不在 zip 目录里，这条只是启发式提示
        result.has_v2_sig = not result.has_v1_sig

        abis: set[str] = set()
        for name in names:
            if not name.startswith("lib/") or not name.endswith(".so"):
                continue
            parts = name.split("/")
            if len(parts) >= 3:
                abis.add(parts[1])
            result.native_libs.append(parts[-1])

        result.abis = sorted(abis)
        result.native_libs = sorted(set(result.native_libs))

        for lib in result.native_libs:
            if lib in PACKERS:
                result.packers[lib] = PACKERS[lib]
            if lib in DETECTORS:
                result.detectors[lib] = DETECTORS[lib]
            for prefix, label in SDK_HINTS.items():
                if lib.startswith(prefix.rstrip(".so")) or lib == prefix:
                    result.sdks[lib] = label
                    break

    # 结论性提示
    if result.detectors:
        result.risk_notes.append(f"发现 {len(result.detectors)} 个检测相关库")
    if len(result.detectors) >= HEAVY_DETECTION_THRESHOLD:
        result.risk_notes.append("反作弊投入较重：建议走协议级，不要硬 hook 运行时")
    if result.packers:
        result.risk_notes.append("存在加固：" + "、".join(set(result.packers.values())))
    if "x86" in result.abis or "x86_64" in result.abis:
        result.risk_notes.append("包含 x86 ABI：模拟器里跑的是转译层，动态代码校验容易失败")
    if result.dex_count > 1:
        result.risk_notes.append(f"多 dex（{result.dex_count} 个）：可能有壳或插件化")

    return result


def render(result: ScanResult) -> None:
    print(f"\nAPK : {result.apk}")
    print(f"大小: {result.size / 1024 / 1024:.1f} MB   dex: {result.dex_count}   ABI: {', '.join(result.abis) or '无'}")
    print(f"签名: {'v1' if result.has_v1_sig else 'v2+'} 原生库: {len(result.native_libs)} 个")

    def section(title: str, items: dict[str, str]) -> None:
        if not items:
            return
        print(f"\n[{title}]")
        for k, v in sorted(items.items()):
            print(f"  {k:<34} {v}")

    section("加固", result.packers)
    section("检测", result.detectors)
    section("SDK", result.sdks)

    if result.risk_notes:
        print("\n[结论]")
        for note in result.risk_notes:
            print(f"  · {note}")
    print()


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="APK 加固/检测库/SDK 侦察")
    parser.add_argument("apk", type=Path, help="APK 文件路径")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    if not args.apk.exists():
        print(f"文件不存在: {args.apk}", file=sys.stderr)
        return 1

    try:
        result = scan(args.apk)
    except zipfile.BadZipFile:
        print(f"不是有效的 APK(zip): {args.apk}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        render(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
