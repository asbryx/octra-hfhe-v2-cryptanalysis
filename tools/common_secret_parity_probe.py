#!/usr/bin/env python3
"""S-free parity-check probe for the pinned 44-file LPN corpus."""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import urllib.request
from pathlib import Path

COMMIT = "019380c97543620091409b0fbf73a8a773a9a0da"
BASE = f"https://raw.githubusercontent.com/octra-labs/hfhe-challenge/{COMMIT}/"
HERE = Path(__file__).resolve().parent
META = HERE.parent / "results" / "lpn_corpus_validation.json"
OUT = HERE.parent / "results" / "common_secret_parity_probe.json"
N = 4096
TAU = 1 / 8
RHO = 1 - 2 * TAU


def fetch_prefix(path: str, count: int) -> tuple[dict, list[tuple[int, int]]]:
    request = urllib.request.Request(BASE + path, headers={"User-Agent": "octra-parity-audit"})
    with urllib.request.urlopen(request, timeout=180) as response:
        header = json.loads(response.readline())
        rows = []
        for _ in range(count):
            row = json.loads(response.readline())
            rows.append((int(row["a"], 16), int(row["y"])))
    return header, rows


def dependencies(rows: list[tuple[int, int, int]], seed: int) -> tuple[int, list[tuple[int, int, int]]]:
    basis: list[tuple[int, int] | None] = [None] * N
    order = list(range(len(rows)))
    random.Random(seed).shuffle(order)
    checks = []
    rank = 0
    for index in order:
        value, _, _ = rows[index]
        combination = 1 << index
        while value:
            pivot = value.bit_length() - 1
            current = basis[pivot]
            if current is None:
                basis[pivot] = value, combination
                rank += 1
                break
            value ^= current[0]
            combination ^= current[1]
        if not value:
            syndrome = sum(rows[i][1] for i in range(len(rows)) if (combination >> i) & 1) & 1
            files = {rows[i][2] for i in range(len(rows)) if (combination >> i) & 1}
            checks.append((combination.bit_count(), syndrome, len(files)))
    assert rank + len(checks) == len(rows)
    return rank, checks


def self_check() -> None:
    toy = [(1, 0, 0), (2, 1, 0), (3, 0, 1)]
    assert dependencies(toy, 0) == (2, [(3, 1, 2)])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows-per-file", type=int, default=100)
    parser.add_argument("--output", type=Path, default=OUT)
    args = parser.parse_args()
    self_check()

    paths = [entry["path"] for entry in json.loads(META.read_text())["files"]]
    assert len(paths) == 44
    rows: list[tuple[int, int, int]] = []
    for file_id, path in enumerate(paths):
        header, sample = fetch_prefix(path, args.rows_per_file)
        assert header["n"] == N and header["tau_num"] == 1 and header["tau_den"] == 8
        rows.extend((a, y, file_id) for a, y in sample)
        print(f"[{file_id + 1:02d}/44] {path}", flush=True)

    rank, checks = dependencies(rows, 0)
    weights = [check[0] for check in checks]
    syndromes = [check[1] for check in checks]
    file_counts = [check[2] for check in checks]
    expected_ones = sum((1 - RHO**weight) / 2 for weight in weights)
    variance = sum(((1 - RHO**weight) / 2) * ((1 + RHO**weight) / 2) for weight in weights)
    best_log2_gap = -1 + min(weights) * math.log2(RHO)
    result = {
        "commit": COMMIT,
        "files_sampled": len(paths),
        "rows_per_file": args.rows_per_file,
        "rows_total": len(rows),
        "rank": rank,
        "dependency_checks": len(checks),
        "dependency_weight": {
            "min": min(weights),
            "median": statistics.median(weights),
            "max": max(weights),
        },
        "files_touched_per_check": {
            "min": min(file_counts),
            "median": statistics.median(file_counts),
            "max": max(file_counts),
        },
        "syndrome_ones": sum(syndromes),
        "syndrome_rate": sum(syndromes) / len(syndromes),
        "expected_ones_common_S_tau_1_8": expected_ones,
        "z_independence_reference_only": (sum(syndromes) - expected_ones) / math.sqrt(variance),
        "best_log2_probability_gap_vs_uniform_per_check": best_log2_gap,
        "interpretation": {
            "sample_parity_probe_feasible": True,
            "decisive_common_S_test_feasible": False,
            "reason": "All found dependencies are dense; parity-noise bias is negligible, so common-S and unrelated labels both predict uniform syndromes.",
            "statistics_limit": "Elimination checks overlap, so the displayed z-score is descriptive and is not a calibrated p-value.",
            "additional_equations_for_S": False,
            "equation_reason": "A dependency has XOR(A_i)=0, so its syndrome contains only XOR(error_i), not a coefficient of S.",
        },
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
