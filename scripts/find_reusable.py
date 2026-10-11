#!/usr/bin/env python3
"""Find already decompiled v1.01 bodies that also exist in the USA v2.00 executable.

Compiles a maintained translation unit (default ``candidates/boot.c``) with the GNU EE chain, then looks for each
function in the v2.00 code with the same length and the same words, ignoring the fields the linker fills in
(calls, global addresses). A body counts only if it occurs at exactly one v2.00 address and has at least
``--min-size`` bytes, because tiny leaves occur many times. Only names, addresses and sizes are written.

Needs the chain environment of docs/V2-SETUP.md (tools/linux on PYTHONPATH, RAC2_WSL_TOOLS, ...).

    python scripts/find_reusable.py --output progress/v2/reused.json
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import function_size_rank as rank  # noqa: E402
import wsl_chain  # noqa: E402

MASK = {4: 0xFC000000, 5: 0xFFFF0000, 6: 0xFFFF0000, 7: 0xFFFF0000}  # JMP26, HI16, LO16, GPREL16


def object_functions(obj: Path) -> dict[str, tuple[list[int], list[tuple[int, int]]]]:
    b = obj.read_bytes()
    shoff, = struct.unpack_from("<I", b, 0x20)
    entsize, num, strndx = struct.unpack_from("<HHH", b, 0x2E)
    rows = [struct.unpack_from("<10I", b, shoff + i * entsize) for i in range(num)]
    names = rows[strndx][4]
    sec = {b[names + r[0]:b.index(b"\0", names + r[0])].decode(): b[r[4]:r[4] + r[5]] for r in rows}
    out = {}
    for name, data in sec.items():
        if not name.startswith(".text."):
            continue
        words = list(struct.unpack(f"<{len(data) // 4}I", data[:len(data) // 4 * 4]))
        positions = []
        rel = sec.get(".rel" + name, b"")
        for i in range(0, len(rel), 8):
            offset, info = struct.unpack_from("<II", rel, i)
            if info & 0xFF in MASK and offset // 4 < len(words):
                positions.append((offset // 4, MASK[info & 0xFF]))
        while len(words) > 2 and words[-1] == 0:  # alignment padding
            words.pop()
        out[name[6:]] = (words, positions)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", default="candidates/boot.c")
    ap.add_argument("--flags", default="-O2 -G0 -ffunction-sections")
    ap.add_argument("--elf", type=Path, default=rank.DEFAULT_ELF)
    ap.add_argument("--min-size", type=int, default=16)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(dir=Path.home() / "rac2-private") as tmp:
        obj = Path(tmp) / "unit.o"
        wsl_chain.compile_c(ROOT / args.source, args.flags.split(), obj, None, Path(tmp) / "log.txt")
        functions = object_functions(obj)
    data = args.elf.read_bytes()
    ranges = rank.load_code_ranges(data)

    def words(address: int, count: int):
        for base, ws in ranges:
            if base <= address < base + len(ws) * 4:
                return ws[(address - base) // 4:(address - base) // 4 + count]
        return None

    by_words = collections.defaultdict(list)
    for f in rank.build(args.elf, "ntsc-u-v2"):
        by_words[f.size // 4].append(f)
    found = {}
    for name, (own, positions) in functions.items():
        hits = []
        for f in by_words.get(len(own), []) + by_words.get(len(own) + 1, []):
            ref = words(f.address, len(own))
            if ref is None or len(ref) != len(own):
                continue
            a, r = list(own), list(ref)
            for i, mask in positions:
                a[i] &= mask
                r[i] &= mask
            if a == r:
                hits.append(f)
        if len(hits) == 1 and hits[0].size >= args.min_size:
            found[name] = hits[0]
    doc = {"schema": 1, "target": "SCUS_972.68", "version": "2.00", "source": args.source,
           "source_sha256": hashlib.sha256((ROOT / args.source).read_bytes()).hexdigest(), "flags": args.flags,
           "relocs_masked": True, "matches": sorted(
               ({"symbol": name, "v2_name": f.name, "address": f.address, "size": f.size} for name, f in found.items()),
               key=lambda m: m["address"])}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(f"{len(functions)} object functions, {len(found)} unique v2.00 matches, "
          f"{sum(f.size for f in found.values())} bytes -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
