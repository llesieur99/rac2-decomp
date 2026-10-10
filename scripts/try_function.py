#!/usr/bin/env python3
"""Compile one C function with the GNU EE chain and compare it with the retail bytes.

The C file must define the function (named like the symbol or given by --symbol).
Only the function's own instruction words are compared; relocated fields (calls,
globals) differ by design, so use leaf functions or read the diff accordingly.
Needs the chain via scripts/wsl_chain.py (on Linux: tools/linux/sitecustomize.py).

    python scripts/try_function.py src/try/IntToFloat.c --address 0x284690 --size 16
"""
from __future__ import annotations

import argparse
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import function_size_rank as rank  # noqa: E402
import wsl_chain  # noqa: E402


def object_text(path: Path, section_hint: str) -> bytes:
    b = path.read_bytes()
    shoff, = struct.unpack_from("<I", b, 0x20)
    entsize, num, strndx = struct.unpack_from("<HHH", b, 0x2E)
    rows = [struct.unpack_from("<10I", b, shoff + i * entsize) for i in range(num)]
    names = rows[strndx][4]
    found = {b[names + r[0]:b.index(b"\0", names + r[0])].decode(): b[r[4]:r[4] + r[5]] for r in rows}
    for key in (f".text.{section_hint}", ".text"):
        if key in found:
            return found[key]
    raise SystemExit(f"no code section in object; sections: {sorted(found)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", type=Path)
    ap.add_argument("--address", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--size", type=int, required=True)
    ap.add_argument("--symbol")
    ap.add_argument("--elf", type=Path, default=rank.DEFAULT_ELF)
    ap.add_argument("--flags", default="-O2 -G0 -ffunction-sections")
    args = ap.parse_args()
    symbol = args.symbol or args.source.stem
    data = args.elf.read_bytes()
    reference = None
    for base, words in rank.load_code_ranges(data):
        if base <= args.address < base + len(words) * 4:
            i = (args.address - base) // 4
            reference = words[i:i + args.size // 4]
    if reference is None:
        raise SystemExit("address is outside the code sections")
    with tempfile.TemporaryDirectory(dir=Path.home() / "rac2-private") as tmp:
        obj, asm = Path(tmp) / "f.o", Path(tmp) / "f.s"
        wsl_chain.compile_c(args.source, args.flags.split(), obj, asm, Path(tmp) / "log.txt")
        raw = object_text(obj, symbol)
        print(asm.read_text())
    ours = list(struct.unpack(f"<{len(raw) // 4}I", raw))
    print(f"reference {len(reference)} words, ours {len(ours)} words")
    ok = ours == reference
    for i in range(max(len(ours), len(reference))):
        a = reference[i] if i < len(reference) else None
        c = ours[i] if i < len(ours) else None
        print(f"{'  ' if a == c else '!!'} +{i * 4:02X} ref {a if a is None else f'{a:08X}'} ours {c if c is None else f'{c:08X}'}")
    print("MATCH" if ok else "DIFFERENT")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
