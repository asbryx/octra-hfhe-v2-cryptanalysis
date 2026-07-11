#!/usr/bin/env python3
"""QP-03 phase C keys 3..7 only (keys 0..2 already observed)."""
from __future__ import annotations

import json
import time
from pathlib import Path

# reuse module
import importlib.util
spec = importlib.util.spec_from_file_location(
    "qp03", Path(r"archive/legacy-probes/qp-03/qp03_lpn_rank.py")
)
qp03 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qp03)

OUT = Path(r"archive/legacy-probes/qp-03/qp03_phase_c_rest.json")


def main() -> None:
    seeds = qp03.parse_seeds(qp03.SEEDS_PATH)
    assert len(seeds) == 44
    results = []
    for ki in range(3, 8):
        t = time.time()
        pk = qp03.dummy_prf_k(ki)
        g = qp03.GF2Rank()
        cor = 0
        groups_to_full = None
        gi = 0
        for seed in seeds:
            for dom in qp03.R_DOMAINS:
                rows = qp03.rows_for_seed_domain(pk, seed, dom, qp03.EFF)
                for row in rows:
                    g.add(row)
                    cor |= row
                gi += 1
                if groups_to_full is None and g.rank() >= qp03.LPN_N:
                    groups_to_full = gi
                    # can stop early for rank; still need cor for zero-influence
        # finish remaining groups only if needed for cor completeness — always finish for zero count
        # If we early-broke rank, continue for cor
        if gi < 44 * 3:
            pass  # we didn't break outer loops
        zero = sum(1 for j in range(qp03.LPN_N) if ((cor >> j) & 1) == 0)
        entry = {
            "prf_k_index": ki,
            "combined_rank": g.rank(),
            "groups_to_full_rank": groups_to_full,
            "zero_row_influence_bits": zero,
            "seconds": round(time.time() - t, 3),
        }
        results.append(entry)
        print(entry, flush=True)
    OUT.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
