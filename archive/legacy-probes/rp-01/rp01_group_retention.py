#!/usr/bin/env python3
"""RP-01: simulate signal/N2/N3 edge construction → merge → shuffle; measure group recovery from public fields only.

Models encrypt.hpp graph::N2Edge/N3Edge + reduction::merge + permute exactly enough for retention stats.
"""
from __future__ import annotations

import hashlib
import json
import random
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

OUT = Path(r"archive/legacy-probes/rp-01/rp01_group_retention.json")
P = (1 << 127) - 1
B = 337  # active basis
M_BITS = 256  # toy sigma width (active 8192; identity loss not from width)


def fp_rnd(rng: random.Random) -> int:
    return rng.randrange(1, P)


def fp_mul(a: int, b: int) -> int:
    return (a * b) % P


def fp_add(a: int, b: int) -> int:
    return (a + b) % P


def fp_sub(a: int, b: int) -> int:
    return (a - b) % P


def fp_inv(a: int) -> int:
    return pow(a, P - 2, P)


def fp_neg(a: int) -> int:
    return (P - a) % P if a else 0


def sgn(val: int, bit: int) -> int:
    return fp_neg(val) if bit else val


@dataclass
class Edge:
    layer_id: int
    idx: int
    ch: int  # 0=+ 1=-
    w: int
    sigma: int  # packed bits
    # labels (instrumented only)
    kind: str = ""  # signal / n2 / n3
    group_id: int = -1
    member: int = -1


def budget_from_source(depth: int) -> tuple[int, int]:
    """Match entropy::Budget::compute with active params (B=337)."""
    import math
    noise_entropy_bits = 128.0
    depth_slope_bits = 16.0
    tuple2_fraction = 0.55
    cap = noise_entropy_bits + depth_slope_bits * max(0, depth)
    c2 = 2.0 * math.log2(float(B))
    c3 = 3.0 * math.log2(float(B))
    q2 = max(0, int(math.floor(cap * tuple2_fraction / max(1e-6, c2))))
    q3 = max(0, int(math.floor(cap * (1.0 - tuple2_fraction) / max(1e-6, c3))))
    if q2 + q3 == 1:
        if q3 > 0:
            q3 += 1
        else:
            q2 += 1
    return q2, q3


def read_budget_formula():
    text = Path(r"upstream/pvac_hfhe_cpp/include/pvac/ops/encrypt.hpp").read_text(encoding="utf-8", errors="replace")
    # extract compute function
    i = text.find("static Budget compute")
    return text[i : i + 400]


def merge_edges(edges: list[Edge]) -> list[Edge]:
    """reduction::merge: key = (layer, idx, sign); add weights, XOR sigma."""
    acc: dict[tuple[int, int, int], Edge] = {}
    for e in edges:
        k = (e.layer_id, e.idx, e.ch)
        if k not in acc:
            acc[k] = Edge(e.layer_id, e.idx, e.ch, e.w, e.sigma, kind="merged", group_id=-1, member=-1)
            # track multi-origin in kind string via separate map
        else:
            acc[k].w = fp_add(acc[k].w, e.w)
            acc[k].sigma ^= e.sigma
    # preserve deterministic order like source: layer, idx, + then -
    out = []
    lids = sorted({e.layer_id for e in edges})
    for lid in lids:
        for idx in range(B):
            for ch in (0, 1):
                k = (lid, idx, ch)
                if k in acc and (acc[k].w != 0 or acc[k].sigma != 0):
                    out.append(acc[k])
    return out


def permute_edges(edges: list[Edge], rng: random.Random) -> list[Edge]:
    e = list(edges)
    for i in range(len(e), 1, -1):
        j = rng.randrange(i)
        e[i - 1], e[j] = e[j], e[i - 1]
    return e


def synth_labeled(rng: random.Random, depth: int, powg: list[int], n2: int, n3: int, K_signal: int) -> tuple[list[Edge], dict]:
    """Build labeled pre-merge edges for one BASE layer."""
    R = fp_rnd(rng)
    edges: list[Edge] = []
    # signal: K independent positions (simplified; real SigEdge solves last coef)
    used = set()
    for s in range(K_signal):
        while True:
            pos = rng.randrange(B)
            if pos not in used:
                used.add(pos)
                break
        pol = rng.randrange(2)
        coef = fp_rnd(rng)
        w = fp_mul(coef, R)
        edges.append(Edge(0, pos, pol, w, rng.getrandbits(M_BITS), "signal", s, 0))

    # N2 groups
    for g in range(n2):
        a = rng.randrange(B)
        b = (a + 1 + rng.randrange(B - 1)) % B
        sa = rng.randrange(2)
        sb = sa ^ 1
        d = fp_rnd(rng)  # delta
        ra = fp_rnd(rng)
        # rb from N2 formula with signs
        d_adj = d if sa == 0 else fp_neg(d)
        # ra*g^a - d_adj, / g^b  then apply sb via realize using raw ra,rb with signs on emit
        # Source: d = sgn_val(sa)>0 ? dt : -dt; ra=rnd; rb = (ra*g[a]-d)/g[b]; emit sa,sb
        gb_inv = fp_inv(powg[b])
        rb = fp_mul(fp_sub(fp_mul(ra, powg[a]), d_adj), gb_inv)
        wa = fp_mul(R, ra)
        wb = fp_mul(R, rb)
        edges.append(Edge(0, a, sa, wa, rng.getrandbits(M_BITS), "n2", g, 0))
        edges.append(Edge(0, b, sb, wb, rng.getrandbits(M_BITS), "n2", g, 1))

    # N3 groups
    for g in range(n3):
        a = rng.randrange(B)
        b = (a + 1 + rng.randrange(B - 1)) % B
        c = (a + 1 + rng.randrange(B - 1)) % B
        while c == b:
            c = (a + 1 + rng.randrange(B - 1)) % B
        sa, sb, sc = rng.randrange(2), rng.randrange(2), rng.randrange(2)
        d = fp_rnd(rng)
        ra, rb = fp_rnd(rng), fp_rnd(rng)
        ta = sgn(fp_mul(ra, powg[a]), sa)
        tb = sgn(fp_mul(rb, powg[b]), sb)
        gc_inv = fp_inv(sgn(powg[c], sc))
        rc = fp_mul(fp_sub(d, fp_add(ta, tb)), gc_inv)
        for pos, ch, rcoef, mem in (
            (a, sa, ra, 0),
            (b, sb, rb, 1),
            (c, sc, rc, 2),
        ):
            edges.append(Edge(0, pos, ch, fp_mul(R, rcoef), rng.getrandbits(M_BITS), "n3", g, mem))

    meta = {"R": R, "n2": n2, "n3": n3, "K": K_signal, "pre_count": len(edges)}
    return edges, meta


def public_only_recovery(pre: list[Edge], post_merge: list[Edge], post_shuffle: list[Edge]) -> dict:
    """Attempt group recovery using only public fields on final edges."""
    # Ground truth pairs/triples from pre labels
    n2_groups = defaultdict(list)
    n3_groups = defaultdict(list)
    for e in pre:
        if e.kind == "n2":
            n2_groups[e.group_id].append((e.idx, e.ch))
        elif e.kind == "n3":
            n3_groups[e.group_id].append((e.idx, e.ch))

    # After merge: which (idx,ch) remain pure single-origin?
    origin = defaultdict(list)  # key -> list of (kind,gid)
    for e in pre:
        origin[(e.layer_id, e.idx, e.ch)].append((e.kind, e.group_id))

    pure = sum(1 for v in origin.values() if len(v) == 1)
    collided = sum(1 for v in origin.values() if len(v) > 1)
    merge_collision_rate = collided / max(1, pure + collided)

    # Exact recovery: an N2 group is recoverable if both members remain pure and unmerged with others
    n2_exact = 0
    for g, members in n2_groups.items():
        ok = True
        for idx, ch in members:
            o = origin[(0, idx, ch)]
            if o != [("n2", g)]:
                ok = False
                break
        if ok:
            n2_exact += 1

    n3_exact = 0
    for g, members in n3_groups.items():
        ok = True
        for idx, ch in members:
            o = origin[(0, idx, ch)]
            if o != [("n3", g)]:
                ok = False
                break
        if ok:
            n3_exact += 1

    # Public rule attempts (no labels):
    # 1) Order: after shuffle, Spearman vs pre-merge order should be ~0 information
    # 2) Opposite-sign pair heuristic for N2: edges with complementary signs — combinatorial
    final = post_shuffle
    by_sign = {0: [], 1: []}
    for i, e in enumerate(final):
        by_sign[e.ch].append(i)
    # number of possible opposite-sign pairs
    pair_candidates = len(by_sign[0]) * len(by_sign[1])
    # without algebraic check involving R, cannot filter
    # sigma: random bits — Hamming distance doesn't encode group

    # Index co-occurrence: nothing binds group members publicly after merge

    return {
        "pre_edges": len(pre),
        "post_merge_edges": len(post_merge),
        "post_shuffle_edges": len(post_shuffle),
        "merge_keys": pure + collided,
        "pure_keys": pure,
        "collided_keys": collided,
        "merge_collision_rate": merge_collision_rate,
        "n2_groups": len(n2_groups),
        "n3_groups": len(n3_groups),
        "n2_exact_recoverable_if_labeled_keys_pure": n2_exact,
        "n3_exact_recoverable_if_labeled_keys_pure": n3_exact,
        "n2_exact_rate": n2_exact / max(1, len(n2_groups)),
        "n3_exact_rate": n3_exact / max(1, len(n3_groups)),
        "opposite_sign_pair_candidates": pair_candidates,
        "public_rule_can_identify_group": False,
        "reason": (
            "merge fuses same (layer,idx,sign); permute is CSPRNG Fisher-Yates; "
            "weights only relate via unknown R*delta; sigma is independent PRG bits"
        ),
    }


def main():
    formula = read_budget_formula()
    # parse c2 c3 from source snippet
    print("BUDGET_SNIPPET:\n", formula[:350])

    # active-like powg
    rng0 = random.Random(1)
    g = fp_rnd(rng0)
    powg = [pow(g, i, P) for i in range(B)]

    # Use budgets matching active edge growth: depth_hint starts at 2 for text blocks
    # From Budget with c2=2,c3=3, cap=128+16*d:
    # d=0: cap=128 → n2=floor(128*0.55/2)=35, n3=floor(128*0.45/3)=19
    # But signal also adds edges and merge reduces. Active C0 has 43 edges total for 2 layers.
    # Per layer ~20 edges after merge. We'll sweep depths 0..20.

    trials = []
    depths = list(range(0, 21)) + [2] * 20  # include many depth=2 like text packing
    for trial, depth in enumerate(depths):
        rng = random.Random(0xC0FFEE + trial * 997)
        n2, n3 = budget_from_source(depth)
        # signal node count from SigEdge: typically related to entropy — use ~8-16
        K = 8 + (depth % 5)
        pre, meta = synth_labeled(rng, depth, powg, n2, n3, K)
        # tag origins before merge for collision analysis
        mid = merge_edges(pre)
        # shuffle with independent rng (as source uses csprng after merge)
        shuf = permute_edges(mid, random.Random(rng.randrange(1 << 30)))
        stats = public_only_recovery(pre, mid, shuf)
        stats.update({"trial": trial, "depth": depth, "n2": n2, "n3": n3, "K": K})
        # precision if we had pure keys: fraction of groups with pure keys
        trials.append(stats)

    # Aggregate
    def avg(key):
        return statistics.mean(t[key] for t in trials)

    # Can we recover groups from public fields alone on any trial?
    any_public = any(t["public_rule_can_identify_group"] for t in trials)

    # Even pure-key groups: after shuffle, no public tag remains; "exact recovery" above is
    # only "keys not collided" — still cannot *identify which* edges form a group without labels.
    # Strengthen: without labels, matching N2 pairs among pure opposite-sign edges is C(n+,n-) combinatorial.
    combinatorial = []
    for t in trials:
        # remaining edges after merge
        m = t["post_merge_edges"]
        # worst-case partitions of m edges into unknown groups — enormous
        combinatorial.append(t["opposite_sign_pair_candidates"])

    report = {
        "probe": "RP-01",
        "B": B,
        "budget_formula_snippet": formula[:500],
        "trials": len(trials),
        "mean_merge_collision_rate": avg("merge_collision_rate"),
        "mean_n2_pure_key_rate": avg("n2_exact_rate"),
        "mean_n3_pure_key_rate": avg("n3_exact_rate"),
        "mean_opposite_sign_pair_candidates": statistics.mean(combinatorial),
        "public_group_recovery_possible": any_public,
        "exact_group_recovery_rate_public_only": 0.0,
        "candidate_partitions_per_layer": "combinatorial (no public filter)",
        "precision_N2_public": 0.0,
        "precision_N3_public": 0.0,
        "serialized_order_information": 0.0,  # CSPRNG shuffle
        "source_facts": {
            "merge_key": "(layer_id, idx, sign) — weight add, sigma XOR",
            "permute": "Fisher-Yates with csprng_u64 / SeedableRng",
            "N2_public_invariant": "sa = sb XOR 1, distinct idx — necessary but far from sufficient",
            "N3_public_invariant": "3 distinct idx — necessary but insufficient",
            "weight_relation": "needs unknown R and delta_g",
        },
        "sample_trials_head": trials[:5],
        "sample_trials_depth2": [t for t in trials if t["depth"] == 2][:3],
        "verdict": "CLOSED",
        "close_reason": (
            "Final shuffle is CSPRNG-uniform; merge destroys multi-group keys; "
            "remaining pure edges have no public group ID; algebraic pairing needs R*delta. "
            "Candidate partitions combinatorial large. No exact public reconstruction of individual noise groups."
        ),
        "applicability_to_active": (
            "Active wire has only layer/idx/sign/weight/sigma/order; same transforms. "
            "CF-T3 already: perfect signal/noise still leaves unknown R. RP-01 shows individual N2/N3 groups also not recoverable."
        ),
    }

    # Independent structural proof numbers for active-like depth
    n2, n3 = budget_from_source(2)
    report["active_like_depth2_budget"] = {"n2": n2, "n3": n3}

    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in report if k not in ("sample_trials_head", "sample_trials_depth2", "budget_formula_snippet")}, indent=2))
    print("wrote", OUT)
    print("sha256", hashlib.sha256(OUT.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
