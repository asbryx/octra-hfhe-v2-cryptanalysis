#!/usr/bin/env python3
"""Check the finite evidence-derived PRF-key family against one public R1 row."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANDIDATES = ROOT / "archive" / "legacy-probes" / "np03_wallet_candidates.py"
ROWS = ROOT / "archive" / "legacy-probes" / "qp-03" / "qp03_lpn_rank.py"
DEFAULT_OUT = ROOT / "results" / "finite_prf_candidates.json"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def plausible_layouts(raw: bytes) -> dict[str, bytes]:
    words = [raw[offset : offset + 8] for offset in range(0, len(raw), 8)]
    return {
        "raw": raw,
        "reverse_all": raw[::-1],
        "reverse_each_u64": b"".join(word[::-1] for word in words),
        "reverse_word_order": b"".join(reversed(words)),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("sample", type=Path, help="canonical R1 JSONL file")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    candidates = load("np03", CANDIDATES)
    rows = load("qp03", ROWS)
    with args.sample.open("rb") as stream:
        header = json.loads(stream.readline())
        target = bytes.fromhex(json.loads(stream.readline())["a"])
    seed = (
        header["seed_ztag"],
        int(header["nonce_lo_hex"], 16),
        int(header["nonce_hi_hex"], 16),
    )
    layouts = plausible_layouts(target)
    assert len(target) == 512 and len(set(layouts.values())) == 4

    hits = []
    family = candidates.candidates()
    for label, candidate in family:
        master = hashlib.sha256(b"OCTRA_PVAC_MASTER_V1" + candidate).digest()
        seeded_key = rows.AesCtr(hashlib.sha256(b"OCTRA_PVAC_SK" + master).digest(), 0)
        routes = {
            "direct_le": list(struct.unpack("<4Q", candidate)),
            "direct_be": list(struct.unpack(">4Q", candidate)),
            "keygen_from_seed": [seeded_key.next_u64() for _ in range(4)],
        }
        for route, key in routes.items():
            generated = rows.rows_for_seed_domain(key, seed, "pvac.prf.r.1", 1)[0].to_bytes(512, "little")
            for layout, expected in layouts.items():
                if generated == expected:
                    hits.append({"label": label, "route": route, "layout": layout})

    result = {
        "sample": args.sample.name,
        "candidates": len(family),
        "routes_per_candidate": 3,
        "layouts_checked": sorted(layouts),
        "checks": len(family) * 3 * len(layouts),
        "hits": hits,
    }
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(json.dumps(result, indent=2))
    assert not hits


if __name__ == "__main__":
    main()
