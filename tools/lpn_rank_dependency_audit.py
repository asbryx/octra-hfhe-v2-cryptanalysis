#!/usr/bin/env python3
"""Small exact GF(2) rank and low-row-dependency audit for one LPN JSONL."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CORPUS = HERE / "ct00_l0_s0_pvac_prf_r_1.jsonl"
DEFAULT_META = HERE.parent / "results" / "lpn_corpus_validation.json"
DEFAULT_OUT = HERE.parent / "results" / "lpn_rank_dependency_audit.json"


def add_basis(row: int, basis: list[int]) -> bool:
    while row:
        pivot = row.bit_length() - 1
        if basis[pivot]:
            row ^= basis[pivot]
        else:
            basis[pivot] = row
            return True
    return False


def exact_weight_2(rows: list[int]) -> list[list[int]]:
    seen: dict[int, int] = {}
    found = []
    for i, row in enumerate(rows):
        if row in seen:
            found.append([seen[row], i])
        else:
            seen[row] = i
    return found


def exact_weight_3(rows: list[int], projection_bits: int = 128) -> tuple[list[list[int]], int]:
    """Exact search: every full XOR relation also survives this linear projection."""
    mask = (1 << projection_bits) - 1
    projected = [row & mask for row in rows]
    buckets: dict[int, list[int]] = {}
    for i, value in enumerate(projected):
        buckets.setdefault(value, []).append(i)

    found: set[tuple[int, int, int]] = set()
    pair_checks = 0
    for i in range(len(rows) - 1):
        left = projected[i]
        for j in range(i + 1, len(rows)):
            pair_checks += 1
            for k in buckets.get(left ^ projected[j], ()):
                if k != i and k != j and rows[i] ^ rows[j] == rows[k]:
                    found.add(tuple(sorted((i, j, k))))
    return [list(item) for item in sorted(found)], pair_checks


def projection_collisions(
    rows: list[int], ys: list[int], offsets: tuple[int, ...], width: int
) -> list[dict]:
    mask = (1 << width) - 1
    reports = []
    for offset in offsets:
        buckets: dict[int, list[int]] = {}
        collisions = []
        for i, row in enumerate(rows):
            key = (row >> offset) & mask
            for j in buckets.get(key, ()):
                collisions.append(
                    {
                        "rows": [j, i],
                        "xor_weight": (rows[j] ^ row).bit_count(),
                        "y_xor": ys[j] ^ ys[i],
                    }
                )
            buckets.setdefault(key, []).append(i)
        collisions.sort(key=lambda item: (item["xor_weight"], item["rows"]))
        reports.append(
            {
                "offset": offset,
                "width": width,
                "pair_collisions": len(collisions),
                "same_y": sum(item["y_xor"] == 0 for item in collisions),
                "best_low_xor_weight": collisions[:5],
            }
        )
    return reports


def load(corpus_path: Path, meta_path: Path) -> tuple[dict, list[int], list[int], dict]:
    digest = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    expected = next(
        (entry for entry in metadata["files"] if Path(entry["path"]).name == corpus_path.name),
        None,
    )
    if expected is None or digest != expected["sha256"]:
        raise ValueError("corpus does not match metadata SHA-256")

    rows, ys = [], []
    with corpus_path.open("r", encoding="ascii") as source:
        header = json.loads(next(source))
        if header != expected["header"]:
            raise ValueError("corpus header does not match metadata")
        n, t = header["n"], header["t"]
        for wanted_i, line in enumerate(source):
            item = json.loads(line)
            raw = bytes.fromhex(item["a"])
            if item.get("i") != wanted_i or item.get("y") not in (0, 1) or len(raw) * 8 != n:
                raise ValueError(f"invalid row at index {wanted_i}")
            rows.append(int.from_bytes(raw, "little"))
            ys.append(item["y"])
    if len(rows) != t:
        raise ValueError(f"row count {len(rows)} != t={t}")
    return header, rows, ys, {"sha256": digest, "metadata_entry": expected["path"]}


def audit(corpus_path: Path, meta_path: Path) -> dict:
    started = time.perf_counter()
    header, rows, ys, validation = load(corpus_path, meta_path)
    loaded_at = time.perf_counter()
    n = header["n"]
    basis_a = [0] * n
    basis_ay = [0] * (n + 1)
    rank_a = rank_ay = 0
    trace = []
    full_rank_at = None

    for count, (row, y) in enumerate(zip(rows, ys), 1):
        if rank_a < n and add_basis(row, basis_a):
            rank_a += 1
            if rank_a == n:
                full_rank_at = count
        if rank_ay < n + 1 and add_basis(row | (y << n), basis_ay):
            rank_ay += 1
        if count % 1024 == 0:
            trace.append({"rows": count, "rank_A": rank_a, "rank_Ay": rank_ay})
    ranked_at = time.perf_counter()

    dep2 = exact_weight_2(rows)
    dep2_at = time.perf_counter()
    dep3, pair_checks = exact_weight_3(rows)
    dep3_at = time.perf_counter()
    projected = projection_collisions(rows, ys, (0, 1024, 2048, 3072), 24)
    projection_pairs = sum(item["pair_collisions"] for item in projected)
    projection_same_y = sum(item["same_y"] for item in projected)
    projection_expected = len(projected) * len(rows) * (len(rows) - 1) / 2 / (1 << 24)
    finished = time.perf_counter()

    tau = header["tau_num"] / header["tau_den"]
    pair_noise = 2 * tau * (1 - tau)
    return {
        "input": {
            "corpus": str(corpus_path.resolve()),
            "metadata": str(meta_path.resolve()),
            **validation,
            "rows": len(rows),
            "columns": n,
        },
        "rank": {
            "rank_A": rank_a,
            "nullity_rows_A": len(rows) - rank_a,
            "first_full_rank_at_row_count": full_rank_at,
            "rank_A_with_y_column": rank_ay,
            "y_in_column_span_of_A": rank_ay == rank_a,
            "trace_every_1024_rows": trace,
        },
        "low_weight_dependencies": {
            "weight_2_exact": dep2,
            "weight_3_exact": dep3,
            "weight_3_pair_checks": pair_checks,
            "weight_4_exact": None,
            "weight_4_note": "not executed: full meet-in-the-middle requires C(16384,2)=134209536 pair key",
        },
        "projection_collisions": {
            "bit_numbering": "little-endian integer from the 512-byte a field",
            "windows": projected,
            "observed_pair_collisions": projection_pairs,
            "expected_pair_collisions_uniform": projection_expected,
            "observed_same_y": projection_same_y,
            "xor_2_independent_noise_rate": pair_noise,
            "noise_note": "projection removes 24 A coordinates, but XORing two samples raises tau from 0.125 to 0.21875",
        },
        "seconds": {
            "load_and_validate": loaded_at - started,
            "rank": ranked_at - loaded_at,
            "weight_2": dep2_at - ranked_at,
            "weight_3": dep3_at - dep2_at,
            "projection": finished - dep3_at,
            "total": finished - started,
        },
    }


def self_check() -> None:
    rows = [0b011, 0b101, 0b110, 0b011]
    basis = [0] * 3
    assert sum(add_basis(row, basis) for row in rows) == 2
    assert exact_weight_2(rows) == [[0, 3]]
    triples, checks = exact_weight_3(rows[:3], 3)
    assert triples == [[0, 1, 2]] and checks == 3


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--metadata", type=Path, default=DEFAULT_META)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    self_check()
    result = audit(args.corpus, args.metadata)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
