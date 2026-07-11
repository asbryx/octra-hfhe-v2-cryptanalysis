#!/usr/bin/env python3
"""Stream-validate the live Octra R1 LPN corpus without storing the JSONLs."""

from __future__ import annotations

import hashlib
import json
import time
import urllib.request
from pathlib import Path

COMMIT = "019380c97543620091409b0fbf73a8a773a9a0da"
BASE = f"https://raw.githubusercontent.com/octra-labs/hfhe-challenge/{COMMIT}/"
OUT = Path(__file__).resolve().parent.parent / "results" / "lpn_corpus_validation.json"


def fetch(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "octra-public-corpus-audit"})
    return urllib.request.urlopen(req, timeout=180)


def expected_files() -> dict[str, str]:
    with fetch(BASE + "SHA256SUMS") as response:
        lines = response.read().decode("ascii").splitlines()
    return {
        path: digest
        for digest, path in (line.split("  ", 1) for line in lines)
        if path.startswith("lpn_samples/")
    }


def save(result: dict) -> None:
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


def main() -> None:
    expected = expected_files()
    assert len(expected) == 44
    seen_rows: set[bytes] = set()
    result = {
        "commit": COMMIT,
        "expected_files": len(expected),
        "files": [],
        "complete": False,
    }

    for number, (path, wanted_hash) in enumerate(sorted(expected.items()), 1):
        started = time.time()
        digest = hashlib.sha256()
        row_ids_ok = True
        y_ones = 0
        duplicates_in_file = 0
        duplicates_cross_file = 0
        local_rows: set[bytes] = set()
        weight_min = 4097
        weight_max = -1
        weight_sum = 0
        rows = 0

        with fetch(BASE + path) as response:
            raw = response.readline()
            digest.update(raw)
            header = json.loads(raw)
            for raw in response:
                digest.update(raw)
                row = json.loads(raw)
                row_ids_ok &= row.get("i") == rows
                if row.get("y") not in (0, 1):
                    raise ValueError(f"invalid y in {path} row {rows}")
                a_hex = row.get("a", "")
                if len(a_hex) != 1024 or a_hex != a_hex.lower():
                    raise ValueError(f"invalid A encoding in {path} row {rows}")
                a = bytes.fromhex(a_hex)
                row_hash = hashlib.sha256(a).digest()
                if row_hash in local_rows:
                    duplicates_in_file += 1
                elif row_hash in seen_rows:
                    duplicates_cross_file += 1
                local_rows.add(row_hash)
                seen_rows.add(row_hash)
                weight = sum(byte.bit_count() for byte in a)
                weight_min = min(weight_min, weight)
                weight_max = max(weight_max, weight)
                weight_sum += weight
                y_ones += row["y"]
                rows += 1

        actual_hash = digest.hexdigest()
        entry = {
            "path": path,
            "sha256": actual_hash,
            "sha256_ok": actual_hash == wanted_hash,
            "header": header,
            "rows": rows,
            "row_ids_sequential": row_ids_ok,
            "y_ones": y_ones,
            "y_rate": y_ones / rows,
            "duplicate_rows_in_file": duplicates_in_file,
            "duplicate_rows_cross_file": duplicates_cross_file,
            "weight_min": weight_min,
            "weight_max": weight_max,
            "weight_mean": weight_sum / rows,
            "seconds": round(time.time() - started, 3),
        }
        if not entry["sha256_ok"] or rows != 16384 or not row_ids_ok:
            raise ValueError(f"validation failed: {entry}")
        result["files"].append(entry)
        result["unique_rows"] = len(seen_rows)
        save(result)
        print(f"[{number:02d}/44] {path} rows={rows} unique_total={len(seen_rows)}")

    headers = [entry["header"] for entry in result["files"]]
    result["summary"] = {
        "rows_total": sum(entry["rows"] for entry in result["files"]),
        "unique_rows": len(seen_rows),
        "duplicate_rows_total": sum(
            entry["duplicate_rows_in_file"] + entry["duplicate_rows_cross_file"]
            for entry in result["files"]
        ),
        "all_sha256_ok": all(entry["sha256_ok"] for entry in result["files"]),
        "all_row_ids_sequential": all(entry["row_ids_sequential"] for entry in result["files"]),
        "domains": sorted({header["dom"] for header in headers}),
        "formats": sorted({header["format"] for header in headers}),
        "cipher_indexes": sorted({header["cipher_index"] for header in headers}),
        "layer_ids": sorted({header["layer_id"] for header in headers}),
        "slots": sorted({header["slot"] for header in headers}),
        "unique_seed_tuples": len({
            (header["seed_ztag"], header["nonce_lo_hex"], header["nonce_hi_hex"])
            for header in headers
        }),
        "unique_public_T": len({header["public_T_hex"] for header in headers}),
    }
    result["complete"] = True
    save(result)
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
