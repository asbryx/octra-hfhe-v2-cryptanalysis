#!/usr/bin/env python3
"""Run three pivot-per-bucket LF2 rounds on the public OCTRA R1 corpus."""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import math
import time
from pathlib import Path

import numpy as np

N = 4096
WORDS = N // 64
TAU = 1 / 8
RHO = 1 - 2 * TAU


def h2(value: float) -> float:
    if value in (0.0, 1.0):
        return 0.0
    return -value * math.log2(value) - (1 - value) * math.log2(1 - value)


def load_corpus(root: Path) -> tuple[np.ndarray, np.ndarray, list[str]]:
    paths = sorted(root.glob("*.jsonl"))
    if len(paths) != 44:
        raise ValueError(f"expected 44 JSONL files, found {len(paths)}")

    total = 44 * 16_384
    rows = np.empty((total, WORDS), dtype=np.uint64)
    labels = np.empty(total, dtype=np.uint8)
    cursor = 0
    names = []

    for path in paths:
        names.append(path.name)
        batch_raw: list[bytes] = []
        batch_y: list[int] = []
        with path.open("r", encoding="ascii") as source:
            header = json.loads(next(source))
            if (
                header.get("n") != N
                or header.get("t") != 16_384
                or header.get("dom") != "pvac.prf.r.1"
                or header.get("tau_num") != 1
                or header.get("tau_den") != 8
            ):
                raise ValueError(f"unexpected header in {path.name}")
            for expected, line in enumerate(source):
                item = json.loads(line)
                raw = bytes.fromhex(item["a"])
                if item.get("i") != expected or item.get("y") not in (0, 1) or len(raw) != 512:
                    raise ValueError(f"invalid row {expected} in {path.name}")
                batch_raw.append(raw)
                batch_y.append(item["y"])
                if len(batch_raw) == 2048:
                    count = len(batch_raw)
                    rows[cursor : cursor + count] = np.frombuffer(b"".join(batch_raw), dtype="<u8").reshape(count, WORDS)
                    labels[cursor : cursor + count] = batch_y
                    cursor += count
                    batch_raw.clear()
                    batch_y.clear()
        if batch_raw:
            count = len(batch_raw)
            rows[cursor : cursor + count] = np.frombuffer(b"".join(batch_raw), dtype="<u8").reshape(count, WORDS)
            labels[cursor : cursor + count] = batch_y
            cursor += count

    if cursor != total:
        raise ValueError(f"expected {total} rows, loaded {cursor}")
    return rows, labels, names


def block_keys(rows: np.ndarray, offset: int, width: int) -> np.ndarray:
    word, shift = divmod(offset, 64)
    mask = np.uint64((1 << width) - 1)
    keys = rows[:, word] >> np.uint64(shift)
    if shift + width > 64:
        keys |= rows[:, word + 1] << np.uint64(64 - shift)
    return keys & mask


def lf2_round(rows: np.ndarray, labels: np.ndarray, offset: int, width: int) -> tuple[np.ndarray, np.ndarray, dict]:
    started = time.perf_counter()
    keys = block_keys(rows, offset, width)
    counts = np.bincount(keys.astype(np.int64), minlength=1 << width)
    occupied = int(np.count_nonzero(counts))
    expected_occupied = (1 << width) * (1 - (1 - 1 / (1 << width)) ** len(rows))

    order = np.argsort(keys, kind="stable")
    ordered_keys = keys[order]
    starts = np.r_[0, np.flatnonzero(ordered_keys[1:] != ordered_keys[:-1]) + 1]
    is_pivot = np.zeros(len(rows), dtype=bool)
    is_pivot[starts] = True
    group = np.cumsum(is_pivot, dtype=np.int64) - 1
    positions = np.flatnonzero(~is_pivot)
    left = order[positions]
    right = order[starts[group[positions]]]

    output_rows = np.empty((len(left), rows.shape[1]), dtype=np.uint64)
    output_labels = labels[left] ^ labels[right]
    for begin in range(0, len(left), 16_384):
        end = min(begin + 16_384, len(left))
        output_rows[begin:end] = rows[left[begin:end]] ^ rows[right[begin:end]]

    if np.any(block_keys(output_rows, offset, width)):
        raise AssertionError("LF2 round did not eliminate its block")

    report = {
        "input_rows": len(rows),
        "output_rows": len(output_rows),
        "occupied_buckets": occupied,
        "expected_occupied_uniform": expected_occupied,
        "empty_buckets": (1 << width) - occupied,
        "max_bucket": int(counts.max()),
        "mean_nonempty_bucket": float(counts[counts > 0].mean()),
        "y_rate": float(output_labels.mean()),
        "seconds": time.perf_counter() - started,
    }
    return output_rows, output_labels, report


def lf2_all_pairs_round(
    rows: np.ndarray, labels: np.ndarray, offset: int, width: int, max_rows: int
) -> tuple[np.ndarray, np.ndarray, dict]:
    keys = block_keys(rows, offset, width)
    order = np.argsort(keys, kind="stable")
    ordered_keys = keys[order]
    starts = np.r_[0, np.flatnonzero(ordered_keys[1:] != ordered_keys[:-1]) + 1]
    ends = np.r_[starts[1:], len(rows)]
    sizes = ends - starts
    total = int(np.sum(sizes * (sizes - 1) // 2, dtype=np.int64))
    if total > max_rows:
        raise MemoryError(f"all-pairs round needs {total} rows; limit is {max_rows}")

    started = time.perf_counter()
    output_rows = np.empty((total, rows.shape[1]), dtype=np.uint64)
    output_labels = np.empty(total, dtype=np.uint8)
    cursor = 0
    for start, end in zip(starts, ends):
        group = order[start:end]
        for right_pos in range(1, len(group)):
            count = right_pos
            right = group[right_pos]
            output_rows[cursor : cursor + count] = rows[group[:right_pos]] ^ rows[right]
            output_labels[cursor : cursor + count] = labels[group[:right_pos]] ^ labels[right]
            cursor += count
    assert cursor == total
    if np.any(block_keys(output_rows, offset, width)):
        raise AssertionError("all-pairs LF2 round did not eliminate its block")
    return output_rows, output_labels, {
        "input_rows": len(rows),
        "output_rows": total,
        "occupied_buckets": len(starts),
        "empty_buckets": (1 << width) - len(starts),
        "max_bucket": int(sizes.max()),
        "mean_nonempty_bucket": float(sizes.mean()),
        "y_rate": float(output_labels.mean()),
        "seconds": time.perf_counter() - started,
    }


def exact_rank_prefix(rows: np.ndarray, labels: np.ndarray, eliminated: int) -> dict:
    residual = N - eliminated
    basis_a = [0] * residual
    basis_ay = [0] * (residual + 1)
    rank_a = rank_ay = 0
    full_a_at = full_ay_at = None

    def add(row: int, basis: list[int]) -> bool:
        while row:
            pivot = row.bit_length() - 1
            if basis[pivot]:
                row ^= basis[pivot]
            else:
                basis[pivot] = row
                return True
        return False

    for index, (words, label) in enumerate(zip(rows, labels), 1):
        value = int.from_bytes(words.tobytes(), "little") >> eliminated
        if rank_a < residual and add(value, basis_a):
            rank_a += 1
            if rank_a == residual:
                full_a_at = index
        if rank_ay < residual + 1 and add(value | (int(label) << residual), basis_ay):
            rank_ay += 1
            if rank_ay == residual + 1:
                full_ay_at = index
        if rank_a == residual and rank_ay == residual + 1:
            break

    return {
        "residual_columns": residual,
        "rank_A": rank_a,
        "rank_Ay": rank_ay,
        "first_full_rank_A_at": full_a_at,
        "first_full_rank_Ay_at": full_ay_at,
        "y_in_column_span_of_A": rank_ay == rank_a,
        "rows_scanned": index,
    }


def fingerprint_duplicates(rows: np.ndarray, labels: np.ndarray) -> dict:
    constants = (np.arange(WORDS, dtype=np.uint64) * np.uint64(0x9E3779B97F4A7C15)) | np.uint64(1)
    fingerprints = np.empty(len(rows), dtype=np.uint64)
    for begin in range(0, len(rows), 16_384):
        end = min(begin + 16_384, len(rows))
        fingerprints[begin:end] = np.bitwise_xor.reduce(rows[begin:end] * constants, axis=1)
    order = np.argsort(fingerprints)
    ordered = fingerprints[order]
    starts = np.r_[0, np.flatnonzero(ordered[1:] != ordered[:-1]) + 1]
    ends = np.r_[starts[1:], len(rows)]

    groups = pair_count = conflicting_pairs = 0
    max_multiplicity = 1
    details = []
    for start, end in zip(starts, ends):
        if end - start < 2:
            continue
        exact: dict[bytes, list[int]] = {}
        for index in order[start:end]:
            exact.setdefault(rows[index].tobytes(), []).append(int(index))
        for raw, indices in exact.items():
            count = len(indices)
            if count < 2:
                continue
            groups += 1
            max_multiplicity = max(max_multiplicity, count)
            pair_count += count * (count - 1) // 2
            ones = int(labels[indices].sum())
            conflicting_pairs += ones * (count - ones)
            details.append(
                {
                    "multiplicity": count,
                    "y_zeros": count - ones,
                    "y_ones": ones,
                    "is_zero_row": not any(raw),
                    "row_sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
    details.sort(key=lambda item: (-item["multiplicity"], item["row_sha256"]))
    duplicate_excess = sum(item["multiplicity"] - 1 for item in details)
    return {
        "unique_rows": len(rows) - duplicate_excess,
        "duplicate_excess_rows": duplicate_excess,
        "fingerprint_adjacent_collisions": int(np.sum(ordered[1:] == ordered[:-1])),
        "exact_duplicate_groups": groups,
        "exact_duplicate_pairs": pair_count,
        "duplicate_pairs_with_conflicting_y": conflicting_pairs,
        "max_exact_multiplicity": max_multiplicity,
        "duplicate_group_details": details,
    }


def self_check() -> None:
    rows = np.zeros((5, WORDS), dtype=np.uint64)
    rows[:, 0] = [1, 1, 2, 2, 3]
    rows[:, 1] = [4, 5, 6, 7, 8]
    labels = np.array([0, 1, 1, 0, 1], dtype=np.uint8)
    reduced, y, report = lf2_round(rows, labels, 0, 2)
    assert report["output_rows"] == 2
    assert not np.any(reduced[:, 0] & np.uint64(3))
    assert sorted(y.tolist()) == [1, 1]
    reduced, y, report = lf2_all_pairs_round(rows, labels, 0, 2, 10)
    assert report["output_rows"] == 2
    assert not np.any(reduced[:, 0] & np.uint64(3))
    assert sorted(y.tolist()) == [1, 1]
    duplicate_rows = np.vstack([rows[:1], rows[:1], rows[2:3]])
    duplicate_labels = np.array([0, 1, 0], dtype=np.uint8)
    duplicates = fingerprint_duplicates(duplicate_rows, duplicate_labels)
    assert duplicates["exact_duplicate_pairs"] == 1
    assert duplicates["duplicate_pairs_with_conflicting_y"] == 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--block", type=int, default=15)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--schedule", help="comma-separated block widths; overrides --block/--rounds")
    parser.add_argument("--mode", choices=("pivot", "all-pairs"), default="pivot")
    parser.add_argument("--max-rows", type=int, default=2_000_000)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent / "results" / "lf2_real_corpus.json")
    args = parser.parse_args()
    schedule = [int(value) for value in args.schedule.split(",")] if args.schedule else [args.block] * args.rounds
    if not schedule or any(width <= 0 for width in schedule) or sum(schedule) >= N:
        raise ValueError("invalid LF2 dimensions")

    self_check()
    started = time.perf_counter()
    rows, labels, files = load_corpus(args.corpus)
    loaded = time.perf_counter()
    stages = []
    eliminated = 0
    for level, width in enumerate(schedule):
        if args.mode == "pivot":
            next_rows, next_labels, report = lf2_round(rows, labels, eliminated, width)
        else:
            next_rows, next_labels, report = lf2_all_pairs_round(
                rows, labels, eliminated, width, args.max_rows
            )
        eliminated += width
        report.update(
            {
                "level": level + 1,
                "block_width": width,
                "eliminated_columns": eliminated,
                "residual_columns": N - eliminated,
                "ideal_independent_bias": RHO ** (1 << (level + 1)),
            }
        )
        q = (1 - report["ideal_independent_bias"]) / 2
        report["optimistic_capacity_bits"] = len(next_rows) * (1 - h2(q))
        stages.append(report)
        del rows, labels
        gc.collect()
        rows, labels = next_rows, next_labels

    rank = exact_rank_prefix(rows, labels, eliminated)
    duplicates = fingerprint_duplicates(rows, labels)
    result = {
        "input": {"files": len(files), "rows": 44 * 16_384, "columns": N, "tau": TAU},
        "method": {"name": f"LF2 {args.mode}", "schedule": schedule, "max_rows": args.max_rows},
        "stages": stages,
        "final": {**rank, **duplicates, "y_rate": float(labels.mean())},
        "seconds": {"load": loaded - started, "total": time.perf_counter() - started},
        "interpretation": "Prefix reduction only; no exhaustive final decoder is attempted.",
    }
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
