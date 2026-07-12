#!/usr/bin/env python3
"""Measure whether 44 SHA-derived AES transcripts beat exhaustive candidate search."""

from __future__ import annotations

import argparse
import importlib.util
import json
import struct
import time
from pathlib import Path

from Crypto.Cipher import AES

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_QP03 = ROOT / "archive" / "legacy-probes" / "qp-03" / "qp03_lpn_rank.py"
DEFAULT_META = ROOT / "results" / "lpn_corpus_validation.json"


def load_qp03(path: Path):
    spec = importlib.util.spec_from_file_location("qp03", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def seeds(path: Path) -> list[tuple[int, int, int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [
        (
            item["header"]["seed_ztag"],
            int(item["header"]["nonce_lo_hex"], 16),
            int(item["header"]["nonce_hi_hex"], 16),
        )
        for item in data["files"]
    ]


def candidate_key(value: int) -> list[int]:
    # ponytail: vary one prefix only; enough to measure search exponent, not claim key recovery.
    return [value, 0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xA5A5A5A55A5A5A5A]


def transcript(qp03, value: int, seed: tuple[int, int, int]) -> bytes:
    key, nonce = qp03.derive_aes_key(candidate_key(value), seed, "pvac.prf.r.1")
    return AES.new(key, AES.MODE_ECB).encrypt(struct.pack("<QQ", nonce, 0))


def run_width(qp03, active_seeds: list[tuple[int, int, int]], bits: int) -> dict:
    true_value = (1 << bits) - 17
    targets = [transcript(qp03, true_value, seed) for seed in active_seeds]

    started = time.perf_counter()
    one_hit = next(value for value in range(1 << bits) if transcript(qp03, value, active_seeds[0]) == targets[0])
    one_seconds = time.perf_counter() - started

    evaluations = 0
    started = time.perf_counter()
    multi_hit = None
    for value in range(1 << bits):
        for seed, expected in zip(active_seeds, targets):
            evaluations += 1
            if transcript(qp03, value, seed) != expected:
                break
        else:
            multi_hit = value
            break
    multi_seconds = time.perf_counter() - started

    assert one_hit == multi_hit == true_value
    candidates = true_value + 1
    assert evaluations == candidates + len(active_seeds) - 1
    return {
        "bits": bits,
        "candidates_tested": candidates,
        "true_value": true_value,
        "one_transcript": {"seconds": one_seconds, "evaluations": candidates},
        "forty_four_early_reject": {"seconds": multi_seconds, "evaluations": evaluations},
        "extra_evaluations_over_one": evaluations - candidates,
        "log2_candidates": (candidates).bit_length() - 1,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bits", default="10,12,14,16")
    parser.add_argument("--qp03", type=Path, default=DEFAULT_QP03)
    parser.add_argument("--metadata", type=Path, default=DEFAULT_META)
    parser.add_argument("--out", type=Path, default=Path(__file__).with_name("shared_midstate_scaling.json"))
    args = parser.parse_args()

    qp03 = load_qp03(args.qp03)
    active_seeds = seeds(args.metadata)
    assert len(active_seeds) == len(set(active_seeds)) == 44
    widths = [int(value) for value in args.bits.split(",")]
    runs = [run_width(qp03, active_seeds, bits) for bits in widths]

    # Candidate counts must double asymptotically; 44 targets add only 43 checks for the true key.
    ratios = [runs[i + 1]["candidates_tested"] / runs[i]["candidates_tested"] for i in range(len(runs) - 1)]
    assert all(ratio > 3.9 for ratio in ratios)  # widths increase by two bits
    assert all(run["extra_evaluations_over_one"] == 43 for run in runs)

    result = {
        "model": "real SHA-256 KDF and AES-256 first block; truncated candidate family",
        "active_transcripts": 44,
        "runs": runs,
        "candidate_growth_ratios": ratios,
        "verdict": "MULTI_TARGET_IMPROVES_VERIFICATION_CONSTANT_NOT_SEARCH_EXPONENT",
        "target_implication": "One R1 transcript already rejects wrong candidates; 43 more transcripts do not generate candidates or reduce the 256-bit candidate space.",
    }
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
