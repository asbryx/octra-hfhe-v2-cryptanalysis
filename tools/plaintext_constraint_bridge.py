#!/usr/bin/env python3
"""Constructively test whether plaintext constraints determine active layer inverses."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

P = (1 << 127) - 1
TARGET = b"octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ"


def pack15(block: bytes) -> int:
    if len(block) > 15:
        raise ValueError("block too long")
    return int.from_bytes(block.ljust(15, b"\0"), "little")


def representative_payload(length: int) -> bytes:
    prefix = b"address=" + TARGET + b"\nprivate_key="
    alphabet = b"0123456789abcdef"
    out = bytearray(prefix)
    while len(out) < length:
        out.append(alphabet[(len(out) * 13 + 7) % len(alphabet)])
    return bytes(out[:length])


def solve_pair(t0: int, t1: int, value: int) -> tuple[int, int]:
    if not (0 < t0 < P and 0 < t1 < P and 0 <= value < P):
        raise ValueError("invalid field input")
    inverse_t1 = pow(t1, -1, P)
    for x0 in (1, 2):
        x1 = ((value - t0 * x0) * inverse_t1) % P
        if x1:
            assert (t0 * x0 + t1 * x1) % P == value
            return x0, x1
    raise AssertionError("two probes must avoid the single forbidden x0")


def choices_for_value(value: int) -> int:
    # x0 ranges over Fp*. Exactly one x0 makes x1 zero when value != 0.
    return P - 1 if value == 0 else P - 2


def audit(equation_map: Path) -> dict:
    data = json.loads(equation_map.read_text(encoding="utf-8"))
    objects = data["objects"]
    if len(objects) != 22 or any(len(obj["layers"]) != 2 for obj in objects):
        raise ValueError("unexpected active equation shape")

    t_pairs = [tuple(int(layer["T_hex"], 16) for layer in obj["layers"]) for obj in objects]
    if any(not (0 < t < P) for pair in t_pairs for t in pair):
        raise AssertionError("active numerator is zero or noncanonical")

    runs = []
    for length in range(301, 316):
        payload = representative_payload(length)
        chunks = [payload[offset : offset + 15] for offset in range(0, len(payload), 15)]
        if len(chunks) != 21:
            raise AssertionError("unexpected text block count")
        values = [length] + [pack15(chunk) for chunk in chunks]
        witnesses = [solve_pair(t0, t1, value) for (t0, t1), value in zip(t_pairs, values)]
        if any((t0 * x0 + t1 * x1) % P != value for (t0, t1), (x0, x1), value in zip(t_pairs, witnesses, values)):
            raise AssertionError("constructed witness failed")

        free_choices = [choices_for_value(value) for value in values]
        runs.append(
            {
                "length": length,
                "payload_has_target_address": TARGET in payload,
                "text_blocks": len(chunks),
                "last_block_data_bytes": length - 300,
                "last_block_zero_suffix_bytes": 15 - (length - 300),
                "all_22_equations_satisfied": True,
                "all_44_inverse_witnesses_nonzero": all(x0 and x1 for x0, x1 in witnesses),
                "minimum_log2_inverse_assignments_for_fixed_plaintext": sum(math.log2(count) for count in free_choices),
            }
        )

    minimum = min(run["minimum_log2_inverse_assignments_for_fixed_plaintext"] for run in runs)
    assert all(run["payload_has_target_address"] for run in runs)
    assert all(run["all_22_equations_satisfied"] for run in runs)
    assert minimum > 2793

    return {
        "input": {
            "equation_map": equation_map.as_posix(),
            "active_objects": len(objects),
            "active_layers": 44,
            "target_address": TARGET.decode("ascii"),
        },
        "packing": {
            "length_cipher": 1,
            "text_ciphers": 21,
            "bytes_per_text_cipher": 15,
            "possible_lengths": [301, 315],
        },
        "constructive_runs": runs,
        "result": {
            "minimum_log2_inverse_assignments_even_if_plaintext_fully_known": minimum,
            "independent_field_degrees_remaining": 22,
            "address_constraint_generates_R_candidates": False,
            "plaintext_constraints_eliminate_any_layer_inverse_degree": False,
            "verdict": "PLAINTEXT_AND_ADDRESS_CONSTRAINTS_DO_NOT_BRIDGE_TO_R",
            "reason": "Each object contributes one equation in two independent nonzero layer inverses. For fixed plaintext, each object retains at least p-2 valid inverse pairs.",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("equation_map", type=Path)
    parser.add_argument("--out", type=Path, default=Path(__file__).with_name("plaintext_constraint_bridge.json"))
    args = parser.parse_args()
    result = audit(args.equation_map)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
