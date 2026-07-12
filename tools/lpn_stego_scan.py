#!/usr/bin/env python3
"""Scan the public LPN corpus for simple non-cryptographic covert channels."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

MARKERS = (b"oct", b"private", b"mnemonic", b"seed", b"flag", b"wallet", b"key")


def pack_bits(bits: list[int], msb_first: bool) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        shift = 7 - index % 8 if msb_first else index % 8
        out[index // 8] |= (bit & 1) << shift
    return bytes(out)


def longest_printable(data: bytes) -> tuple[int, str]:
    best = bytearray()
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126 or byte in (9, 10, 13):
            current.append(byte)
            if len(current) > len(best):
                best = current.copy()
        else:
            current.clear()
    return len(best), best[:96].decode("ascii", "replace")


def inspect(name: str, bits: list[int]) -> dict:
    ones = sum(bits)
    n = len(bits)
    z = abs(ones - n / 2) / math.sqrt(n / 4) if n else 0.0
    views = []
    for msb_first in (False, True):
        raw = pack_bits(bits, msb_first)
        lower = raw.lower()
        run, preview = longest_printable(raw)
        views.append({
            "bit_order": "msb" if msb_first else "lsb",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "marker_hits": [marker.decode() for marker in MARKERS if marker in lower],
            "longest_printable_run": run,
            "printable_preview": preview,
        })
    return {
        "name": name,
        "bits": n,
        "ones": ones,
        "one_rate": ones / n if n else 0.0,
        "monobit_abs_z": z,
        "views": views,
    }


def self_check() -> None:
    expected = b"OCTRA"
    bits = [(byte >> bit) & 1 for byte in expected for bit in range(8)]
    assert pack_bits(bits, False) == expected
    assert b"oct" in pack_bits(bits, False).lower()
    assert longest_printable(b"\x00ABC\nDEF\xff")[0] == 7


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--out", type=Path, default=Path(__file__).with_name("lpn_stego_scan.json"))
    args = parser.parse_args()
    self_check()

    files = sorted(args.corpus.glob("*.jsonl"))
    if len(files) != 44:
        raise ValueError(f"expected 44 JSONL files, got {len(files)}")

    channels = {name: [] for name in ("y", "row_parity", "first_lsb", "last_msb", "row_hash_lsb")}
    per_file_y: list[list[int]] = []
    headers = []
    for path in files:
        y_bits = []
        with path.open("rb") as stream:
            header = json.loads(stream.readline())
            headers.append(header)
            rows = 0
            for raw in stream:
                row = json.loads(raw)
                if row["i"] != rows or row["y"] not in (0, 1):
                    raise ValueError(f"bad row {path.name}:{rows}")
                a = bytes.fromhex(row["a"])
                channels["y"].append(row["y"])
                channels["row_parity"].append(sum(byte.bit_count() for byte in a) & 1)
                channels["first_lsb"].append(a[0] & 1)
                channels["last_msb"].append(a[-1] >> 7)
                channels["row_hash_lsb"].append(hashlib.sha256(a).digest()[0] & 1)
                y_bits.append(row["y"])
                rows += 1
        if rows != 16384:
            raise ValueError(f"bad row count {path.name}: {rows}")
        per_file_y.append(y_bits)

    channels["y_row_major"] = [per_file_y[file][row] for row in range(16384) for file in range(44)]
    channels["y_xor_all_files"] = [sum(per_file_y[file][row] for file in range(44)) & 1 for row in range(16384)]
    channels["y_xor_layer_pairs"] = [
        per_file_y[cipher * 2][row] ^ per_file_y[cipher * 2 + 1][row]
        for cipher in range(22) for row in range(16384)
    ]

    header_bytes = bytearray()
    for header in headers:
        header_bytes.extend(header["seed_ztag"].to_bytes(8, "little"))
        header_bytes.extend(int(header["nonce_lo_hex"], 16).to_bytes(8, "little"))
        header_bytes.extend(int(header["nonce_hi_hex"], 16).to_bytes(8, "little"))
        header_bytes.extend(bytes.fromhex(header["public_T_hex"]))
    header_run, header_preview = longest_printable(bytes(header_bytes))

    reports = [inspect(name, bits) for name, bits in channels.items()]
    promoted = [
        {"channel": report["name"], "view": view}
        for report in reports for view in report["views"]
        if any(len(marker) >= 4 for marker in view["marker_hits"])
        or view["longest_printable_run"] >= 16
    ]
    total_view_bytes = sum((report["bits"] + 7) // 8 for report in reports) * 2
    expected_casefold_key_hits = total_view_bytes / (1 << 21)
    probability_two_or_more_key_hits = 1 - math.exp(-expected_casefold_key_hits) * (
        1 + expected_casefold_key_hits
    )
    result = {
        "input": {"files": len(files), "rows": sum(len(bits) for bits in per_file_y)},
        "channels": reports,
        "header_stream": {
            "bytes": len(header_bytes),
            "sha256": hashlib.sha256(header_bytes).hexdigest(),
            "marker_hits": [marker.decode() for marker in MARKERS if marker in header_bytes.lower()],
            "longest_printable_run": header_run,
            "printable_preview": header_preview,
        },
        "promoted_candidates": promoted,
        "multiple_testing": {
            "total_view_bytes": total_view_bytes,
            "observed_casefold_key_hits": sum(
                "key" in view["marker_hits"] for report in reports for view in report["views"]
            ),
            "expected_casefold_key_hits_uniform": expected_casefold_key_hits,
            "poisson_probability_at_least_two": probability_two_or_more_key_hits,
            "interpretation": "Three-byte case-folded markers are reported but not promoted.",
        },
        "verdict": "REVIEW_CANDIDATES" if promoted else "NO_SIMPLE_COVERT_CHANNEL_FOUND",
        "limitations": "Covers direct bit packing and simple parity/hash channels, not arbitrary keyed steganography.",
    }
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "verdict": result["verdict"],
        "promoted_candidates": len(promoted),
        "max_abs_z": max(report["monobit_abs_z"] for report in reports),
        "max_printable_run": max(view["longest_printable_run"] for report in reports for view in report["views"]),
        "header_printable_run": header_run,
    }, indent=2))


if __name__ == "__main__":
    main()
