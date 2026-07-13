#!/usr/bin/env python3
"""Optimistic low-weight-dual gate for the fixed public LPN corpus."""

import argparse
import json
import math
from pathlib import Path


def log2_choose(n: int, k: int) -> float:
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2)


def estimate(m: int = 720_896, n: int = 4_096, rho: float = 0.75, security: int = 64) -> dict:
    selected = {1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2000}
    rows = []
    first_expected = None
    first_feasible = None
    for weight in range(1, 2001):
        available = log2_choose(m, weight) - n
        required = math.log2(2 * math.log(2**security)) - 2 * weight * math.log2(rho)
        if first_expected is None and available >= 0:
            first_expected = weight
        if first_feasible is None and available >= required:
            first_feasible = weight
        if weight in selected or weight in (first_expected, first_feasible):
            rows.append({
                "weight": weight,
                "log2_expected_target_checks": available,
                "log2_checks_required": required,
            })
    result = {
        "model": "random dense A; finding dual checks is free; checks are independent",
        "m": m,
        "n": n,
        "rho": rho,
        "security_bits": security,
        "first_weight_with_one_expected_target_check": first_expected,
        "first_optimistic_distinguishing_weight": first_feasible,
        "rows": rows,
        "verdict": "not practical: even the free-check model first needs about 2^301 checks",
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = estimate()
    assert result["first_optimistic_distinguishing_weight"] == 355
    text = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.write_text(text, encoding="ascii", newline="\n")
    print(text, end="")


if __name__ == "__main__":
    main()
