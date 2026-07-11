#!/usr/bin/env python3
"""QP-03: active-seed LPN row rank + secret-bit influence (dummy prf_k). Optimized."""
from __future__ import annotations

import hashlib
import json
import re
import struct
import time
from pathlib import Path
from Crypto.Cipher import AES

CANON = 531565633433868593
H_DIGEST = bytes.fromhex("601435f4977dd2a0c396bd96c7947fb884b602a52b6d7e0660b3fce3508497f5")
LPN_N = 4096
EFF = 127
S_WORDS = LPN_N // 64
MASK64 = (1 << 64) - 1
R_DOMAINS = ("pvac.prf.r.1", "pvac.prf.r.2", "pvac.prf.r.3")
SEEDS_PATH = Path(r"archive/legacy-probes/seeds_active.txt")
OUT_DIR = Path(r"archive/legacy-probes/qp-03")


def fnv1a(text: str) -> int:
    h = 0xCBF29CE484222325
    for b in text.encode("ascii"):
        h = ((h ^ b) * 0x100000001B3) & MASK64
    return h


class AesCtr:
    def __init__(self, key: bytes, nonce: int):
        self.cipher = AES.new(key, AES.MODE_ECB)
        self.counter = nonce & MASK64
        self.buffered = None

    def block(self):
        out = self.cipher.encrypt(struct.pack("<QQ", self.counter, 0))
        self.counter = (self.counter + 1) & MASK64
        return struct.unpack("<QQ", out)

    def next_u64(self) -> int:
        if self.buffered is not None:
            v, self.buffered = self.buffered, None
            return v
        a, b = self.block()
        self.buffered = b
        return a

    def fill_u64(self, n: int) -> list[int]:
        out = []
        if self.buffered is not None and n:
            out.append(self.buffered)
            self.buffered = None
        while len(out) + 1 < n:
            out.extend(self.block())
        if len(out) < n:
            a, b = self.block()
            out.append(a)
            self.buffered = b
        return out

    def bounded(self, M: int) -> int:
        if M <= 1:
            return 0
        lim = MASK64 - (MASK64 % M)
        while True:
            x = self.next_u64()
            if x < lim:
                return x % M


def derive_aes_key(prf_k: list[int], seed, domain: str) -> tuple[bytes, int]:
    ztag, lo, hi = seed
    d = hashlib.sha256()
    for w in prf_k:
        d.update(struct.pack("<Q", w))
    d.update(struct.pack("<Q", CANON))
    d.update(H_DIGEST)
    d.update(struct.pack("<QQQ", ztag, lo, hi))
    dh = fnv1a(domain)
    d.update(struct.pack("<Q", dh))
    return d.digest(), dh ^ lo


def parse_seeds(path: Path) -> list[tuple[int, int, int]]:
    seeds = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.search(
            r"rule=BASE ztag=(0x[0-9a-fA-F]+) lo=(0x[0-9a-fA-F]+) hi=(0x[0-9a-fA-F]+)",
            line,
        )
        if m:
            seeds.append((int(m.group(1), 16), int(m.group(2), 16), int(m.group(3), 16)))
    return seeds


def rows_for_seed_domain(prf_k: list[int], seed, domain: str, n_rows: int = EFF) -> list[int]:
    key, nonce = derive_aes_key(prf_k, seed, domain)
    prg = AesCtr(key, nonce)
    rows = []
    for _ in range(n_rows):
        words = prg.fill_u64(S_WORDS)
        mask = 0
        for i, w in enumerate(words):
            mask |= (w & MASK64) << (64 * i)
        rows.append(mask)
        _ = prg.bounded(8)
    return rows


class GF2Rank:
    """Gaussian elimination with bit_length pivot finding."""

    __slots__ = ("basis", "rank_")

    def __init__(self):
        self.basis: dict[int, int] = {}  # pivot_col -> row
        self.rank_ = 0

    def add(self, row: int) -> bool:
        r = row
        while r:
            # lowest set bit index
            c = (r & -r).bit_length() - 1
            piv = self.basis.get(c)
            if piv is None:
                self.basis[c] = r
                self.rank_ += 1
                return True
            r ^= piv
        return False

    def rank(self) -> int:
        return self.rank_


def dummy_prf_k(i: int) -> list[int]:
    base = 0xA11CE5EED0000000 + i * 0x100000001B3
    return [(base + k) & MASK64 for k in range(4)]


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    seeds = parse_seeds(SEEDS_PATH)
    assert len(seeds) == 44, len(seeds)

    report: dict = {
        "probe": "QP-03",
        "active_seeds": len(seeds),
        "domains": list(R_DOMAINS),
        "rows_per_group": EFF,
        "lpn_n": LPN_N,
        "phase_a": {},
        "phase_b": {},
        "phase_c": [],
    }

    # Phase A
    t0 = time.time()
    prf0 = dummy_prf_k(0)
    gr = GF2Rank()
    rank_trace = []
    groups = 0
    col_or = 0
    all_rows_count = 0
    for si, seed in enumerate(seeds):
        for dom in R_DOMAINS:
            rows = rows_for_seed_domain(prf0, seed, dom, EFF)
            for row in rows:
                gr.add(row)
                col_or |= row
                all_rows_count += 1
            groups += 1
            rank_trace.append({"group": groups, "seed_index": si, "domain": dom, "rank": gr.rank()})
            # don't early-stop for col_or completeness in phase A trace; stop only rank report
        # continue all groups for full col_or / full rank confirmation
    report["phase_a"] = {
        "dummy_prf_k_index": 0,
        "groups_processed": groups,
        "final_rank": gr.rank(),
        "groups_to_full_rank": next((t["group"] for t in rank_trace if t["rank"] >= LPN_N), None),
        "rank_trace_every_group": rank_trace,
        "rows_total": all_rows_count,
        "seconds": round(time.time() - t0, 3),
    }
    print("phaseA", report["phase_a"]["final_rank"], "to_full", report["phase_a"]["groups_to_full_rank"],
          "sec", report["phase_a"]["seconds"], flush=True)

    # Phase B
    t1 = time.time()
    zero_row_inf = [j for j in range(LPN_N) if ((col_or >> j) & 1) == 0]
    support = LPN_N - len(zero_row_inf)
    # sample influence check: rebuild a few groups
    import random
    rng = random.Random(0)
    sample_rows = rows_for_seed_domain(prf0, seeds[0], R_DOMAINS[0], EFF)
    base_sec = 0
    x = 0x5EC0
    for i in range(S_WORDS):
        x = (x + 0x9E3779B97F4A7C15) & MASK64
        z = x
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        base_sec |= ((z ^ (z >> 31)) & MASK64) << (64 * i)

    def y_linear(rows, sec):
        y = 0
        for i, row in enumerate(rows):
            y |= ((row & sec).bit_count() & 1) << i
        return y

    base_y = y_linear(sample_rows, base_sec)
    checked = changed = 0
    support_bits = [j for j in range(LPN_N) if (col_or >> j) & 1]
    for j in rng.sample(support_bits, min(64, len(support_bits))):
        y2 = y_linear(sample_rows, base_sec ^ (1 << j))
        # may not change this single group's y if column j not in these rows
        checked += 1
        if y2 != base_y:
            changed += 1
    # stronger: any support bit must appear in some row of full matrix => zero_row_inf is exact
    report["phase_b"] = {
        "combined_row_rank": gr.rank(),
        "lpn_bits_with_zero_row_influence": len(zero_row_inf),
        "lpn_bits_with_zero_output_influence": len(zero_row_inf),
        "support_bits": support,
        "zero_indices_head": zero_row_inf[:16],
        "sample_group0_support_flips_checked": checked,
        "sample_group0_flips_that_changed_that_group": changed,
        "seconds": round(time.time() - t1, 3),
        "note": "Linear LPN (errors independent of s): secret bit influence <=> column support over active rows.",
    }
    print("phaseB zero_inf", len(zero_row_inf), "support", support, flush=True)

    # Phase C: 8 keys — rank + zero influence only (no full row storage)
    for ki in range(8):
        t = time.time()
        pk = dummy_prf_k(ki)
        g = GF2Rank()
        cor = 0
        groups_to_full = None
        gi = 0
        for seed in seeds:
            for dom in R_DOMAINS:
                rows = rows_for_seed_domain(pk, seed, dom, EFF)
                for row in rows:
                    g.add(row)
                    cor |= row
                gi += 1
                if groups_to_full is None and g.rank() >= LPN_N:
                    groups_to_full = gi
        zero = sum(1 for j in range(LPN_N) if ((cor >> j) & 1) == 0)
        entry = {
            "prf_k_index": ki,
            "combined_rank": g.rank(),
            "groups_to_full_rank": groups_to_full,
            "zero_row_influence_bits": zero,
            "seconds": round(time.time() - t, 3),
        }
        report["phase_c"].append(entry)
        print("phaseC", entry, flush=True)

    ranks = [report["phase_a"]["final_rank"]] + [x["combined_rank"] for x in report["phase_c"]]
    zeros = [report["phase_b"]["lpn_bits_with_zero_row_influence"]] + [
        x["zero_row_influence_bits"] for x in report["phase_c"]
    ]
    promote = any(r < LPN_N - 64 for r in ranks) or any(z >= 100 for z in zeros)
    report["decision"] = {
        "promote_to_solver": promote,
        "reason": (
            "rank far below 4096 or many zero-influence bits"
            if promote
            else "combined rank reaches 4096 quickly; essentially all secret bits influence some active output; AES rows unknowable without full 256-bit prf_k; no public R-core output"
        ),
        "verdict": "PROMISING" if promote else "CLOSED",
    }

    out = OUT_DIR / "qp03_rank_influence.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("wrote", out)
    print("VERDICT", report["decision"]["verdict"])


if __name__ == "__main__":
    main()
