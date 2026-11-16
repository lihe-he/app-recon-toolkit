#!/usr/bin/env python3
"""ELF 分析：导出符号、反汇编目标函数、标注可疑 patch 点.

为什么需要这个：`nm` / `readelf` 在 Windows 上不一定有，而 Android 的 .so
经常是 strip 过的 —— 但 JNI 入口必然在 .dynsym 里。

流程通常是：
    string_hunt 找到库
    → elf_sym 看导出符号，认出 JNI 入口
    → 反汇编看返回逻辑，找到「返回「异常」的那个分支」

用法：
    recon-elf libemulator_check.so
    recon-elf lib.so --symbol Java_com_x_y_detect --disasm
    recon-elf lib.so --disasm 0xc18 --len 0x240
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import capstone
except ImportError:  # pragma: no cover
    capstone = None


EM_ARM = 40
EM_AARCH64 = 183

SHN_UNDEF = 0
STT_FUNC = 2


@dataclass(slots=True)
class Section:
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int


@dataclass(slots=True)
class Symbol:
    name: str
    value: int
    size: int
    info: int

    @property
    def kind(self) -> str:
        return {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION"}.get(self.info & 0xF, f"0x{self.info & 0xF:x}")

    @property
    def is_func(self) -> bool:
        return (self.info & 0xF) == STT_FUNC


@dataclass(slots=True)
class ELF:
    data: bytes
    bits: int = 64
    machine: int = EM_AARCH64
    little_endian: bool = True
    sections: list[Section] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> ELF:
        data = path.read_bytes()
        if data[:4] != b"\x7fELF":
            raise ValueError(f"不是 ELF 文件: {path}")
        bits = 64 if data[4] == 2 else 32
        little = data[5] == 1
        endian = "<" if little else ">"
        machine = struct.unpack_from(f"{endian}H", data, 18)[0]

        elf = cls(data=data, bits=bits, machine=machine, little_endian=little)
        elf._parse_sections(endian)
        elf._parse_dynsym(endian)
        return elf

    # ── 解析 ──

    def _parse_sections(self, endian: str) -> None:
        if self.bits == 64:
            e_shoff = struct.unpack_from(f"{endian}Q", self.data, 0x28)[0]
            e_shentsize = struct.unpack_from(f"{endian}H", self.data, 0x3A)[0]
            e_shnum = struct.unpack_from(f"{endian}H", self.data, 0x3C)[0]
            e_shstrndx = struct.unpack_from(f"{endian}H", self.data, 0x3E)[0]
            fmt = f"{endian}IIQQQQIIQQ"
        else:
            e_shoff = struct.unpack_from(f"{endian}I", self.data, 0x20)[0]
            e_shentsize = struct.unpack_from(f"{endian}H", self.data, 0x2E)[0]
            e_shnum = struct.unpack_from(f"{endian}H", self.data, 0x30)[0]
            e_shstrndx = struct.unpack_from(f"{endian}H", self.data, 0x32)[0]
            fmt = f"{endian}IIIIIIIIII"

        raw_sections = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            vals = struct.unpack_from(fmt, self.data, off)
            raw_sections.append(vals)

        shstr = raw_sections[e_shstrndx] if e_shstrndx < len(raw_sections) else None
        shstr_off = shstr[4] if shstr else 0

        for vals in raw_sections:
            name_off = vals[0]
            self.sections.append(
                Section(
                    name=self._cstr(shstr_off + name_off) if shstr_off else "",
                    sh_type=vals[1],
                    flags=vals[2],
                    addr=vals[3],
                    offset=vals[4],
                    size=vals[5],
                    link=vals[6],
                    entsize=vals[9],
                )
            )

    def _parse_dynsym(self, endian: str) -> None:
        dynsym = next((s for s in self.sections if s.name == ".dynsym"), None)
        dynstr = next((s for s in self.sections if s.name == ".dynstr"), None)
        if dynsym is None or dynstr is None:
            return

        entsize = 24 if self.bits == 64 else 16
        count = dynsym.size // entsize
        for i in range(count):
            off = dynsym.offset + i * entsize
            if self.bits == 64:
                name_off, info, _other, _shndx, value, size = struct.unpack_from(f"{endian}IBBHQQ", self.data, off)
            else:
                name_off, value, size, info, _other, _shndx = struct.unpack_from(f"{endian}IIIBBH", self.data, off)
            if name_off == 0:
                continue
            self.symbols.append(
                Symbol(name=self._cstr(dynstr.offset + name_off), value=value, size=size, info=info)
            )

    def _cstr(self, offset: int) -> str:
        end = self.data.find(b"\x00", offset)
        if end < 0:
            end = len(self.data)
        return self.data[offset:end].decode("utf-8", "replace")

    # ── 查询 ──

    def vaddr_to_offset(self, vaddr: int) -> int | None:
        for s in self.sections:
            if s.addr and s.addr <= vaddr < s.addr + s.size:
                return s.offset + (vaddr - s.addr)
        return None

    def find_symbols(self, needle: str) -> list[Symbol]:
        return [s for s in self.symbols if needle in s.name]

    def arch_name(self) -> str:
        return {EM_AARCH64: "arm64", EM_ARM: "arm"}.get(self.machine, f"machine={self.machine}")

    # ── 反汇编 ──

    def disassemble(self, va: int, length: int = 256) -> list[str]:
        if capstone is None:
            return ["(未安装 capstone，跳过反汇编: pip install capstone)"]

        off = self.vaddr_to_offset(va)
        if off is None:
            return [f"地址 0x{va:x} 不在任何 section 内"]

        code = self.data[off : off + length]
        if self.machine == EM_AARCH64:
            md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        elif self.machine == EM_ARM:
            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_THUMB)
        else:
            return [f"不支持的反汇编架构: {self.arch_name()}"]

        return [
            f"0x{ins.address:08x}: {ins.mnemonic:<8} {ins.op_str}" for ins in md.disasm(code, va)
        ]


def _print_report(elf: ELF, path: Path) -> None:
    print(f"\n文件   : {path}")
    print(f"架构   : {elf.arch_name()}  {'64' if elf.bits == 64 else '32'} 位  {'小端' if elf.little_endian else '大端'}")
    print(f"大小   : {len(elf.data)} 字节  导出符号: {len(elf.symbols)}")

    # value == 0 的是未定义（导入）符号，只说明依赖了什么，不是本库的函数
    funcs = [s for s in elf.symbols if s.is_func and s.name and s.value]
    imported = [s for s in elf.symbols if s.is_func and s.name and not s.value]

    if funcs:
        print(f"\n[本库函数符号 {len(funcs)} 个]")
        for s in funcs:
            print(f"  0x{s.value:08x}  size={s.size:<6} {s.name}")

    if imported:
        print(f"\n[导入的函数 {len(imported)} 个]")
        print("  " + ", ".join(s.name for s in imported))

    jni = [s for s in elf.symbols if s.name.startswith("Java_") and s.value]
    if jni:
        print("\n[JNI 入口]")
        for s in jni:
            short = s.name.replace("Java_", "").replace("_", ".")
            print(f"  0x{s.value:08x}  {short}")


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="ELF 符号分析与反汇编")
    parser.add_argument("elf", type=Path, help=".so 文件")
    parser.add_argument("--symbol", "-s", help="只看名字包含该子串的符号")
    parser.add_argument("--disasm", nargs="?", const="", help="反汇编：给符号名，或 --disasm 0x1234 直接给地址")
    parser.add_argument("--len", type=lambda x: int(x, 0), default=0x200, help="反汇编字节数，默认 0x200")
    parser.add_argument("--sections", action="store_true", help="列出所有 section")
    args = parser.parse_args(argv)

    if not args.elf.exists():
        print(f"文件不存在: {args.elf}", file=sys.stderr)
        return 1

    try:
        elf = ELF.load(args.elf)
    except (ValueError, struct.error) as exc:
        print(f"解析失败: {exc}", file=sys.stderr)
        return 1

    _print_report(elf, args.elf)

    if args.sections:
        print("\n[section]")
        for s in elf.sections:
            if s.addr or s.size:
                print(f"  {s.name:<22} addr=0x{s.addr:08x} off=0x{s.offset:06x} size=0x{s.size:06x}")

    if args.symbol:
        matched = elf.find_symbols(args.symbol)
        print(f"\n[匹配 '{args.symbol}' 的符号: {len(matched)}]")
        for s in matched:
            print(f"  0x{s.value:08x}  {s.kind:<8} size={s.size:<6} {s.name}")

    if args.disasm is not None:
        target = args.disasm.strip()
        if not target:
            # 没给参数时，默认反汇编第一个 JNI 入口
            jni = [s for s in elf.symbols if s.name.startswith("Java_")]
            if not jni:
                print("\n没有 JNI 入口可反汇编，请用 --disasm 0xADDR 指定地址")
                return 0
            va, label = jni[0].value, jni[0].name
        elif target.lower().startswith("0x"):
            va, label = int(target, 16), target
        else:
            matched = elf.find_symbols(target)
            if not matched:
                print(f"\n找不到符号: {target}", file=sys.stderr)
                return 1
            va, label = matched[0].value, matched[0].name

        print(f"\n[反汇编 {label} @ 0x{va:x}]")
        for line in elf.disassemble(va, args.len):
            print("  " + line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
