#!/usr/bin/env python3
"""断言产物没有强链接 iOS 17 独有的库。

原 app 1.0.2 之所以绑死在 iOS 17，就是因为它对 SwiftData / TipKit / Symbols /
libswiftObservation 用的是 LC_LOAD_DYLIB（`LC_LOAD_WEAK_DYLIB`）——dyld 直接拒绝加载。
本脚本用同一套判据检查我们自己的产物，防止回归。

用法: python3 Scripts/check_ios16_links.py <path-to-macho-binary>
退出码: 0 = 通过, 1 = 发现强链接的 iOS 17 独有库
"""
import struct
import sys

LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x80000018

# iOS 16.3 上不存在的库 / 框架
FORBIDDEN = (
    "SwiftData",
    "TipKit",
    "Symbols.framework",
    "swiftObservation",
    "swiftSynchronization",
    "swiftRegexBuilder",
)


def load_commands(buf):
    magic = struct.unpack_from("<I", buf, 0)[0]
    if magic not in (0xFEEDFACF, 0xFEEDFACE):
        raise SystemExit(f"不是 Mach-O (magic=0x{magic:08x})")
    hdr = 32 if magic == 0xFEEDFACF else 28
    ncmds = struct.unpack_from("<I", buf, 16)[0]
    off = hdr
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
            nameoff = struct.unpack_from("<I", buf, off + 8)[0]
            name = buf[off + nameoff: off + cmdsize].split(b"\0")[0].decode("utf-8", "replace")
            yield cmd == LC_LOAD_WEAK_DYLIB, name
        off += cmdsize


def main():
    if len(sys.argv) != 2:
        raise SystemExit("用法: check_ios16_links.py <binary>")

    with open(sys.argv[1], "rb") as fh:
        buf = fh.read()

    strong, weak = [], []
    for is_weak, name in load_commands(buf):
        (weak if is_weak else strong).append(name)

    print(f"  strong={len(strong)}  weak={len(weak)}")
    for name in sorted(weak):
        print("    WEAK  ", name)

    offenders = [
        name for name in strong
        if any(bad.lower() in name.lower() for bad in FORBIDDEN)
    ]
    if offenders:
        print("::error::强链接了 iOS 17 独有库，iOS 16 设备上 dyld 会直接拒绝加载：")
        for name in offenders:
            print("      ", name)
        return 1

    print("  ok: 无 iOS 17 独有库的强链接")
    return 0


if __name__ == "__main__":
    sys.exit(main())
