#!/usr/bin/env python3
"""QP-02: prove toep_127 output depends only on bits 0..126 of top and ybits.

Implements the same GF(2) polynomial convolution + 0..126 extract as
pvac/crypto/toeplitz.hpp toep_127_scalar.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import random
from typing import List, Tuple

OUT = pathlib.Path(r"archive/legacy-probes/qp-02")
OUT.mkdir(parents=True, exist_ok=True)

LPN_T = 16384


def words_for_bits(nbits: int) -> int:
    return (nbits + 63) // 64


def zero_bits_above(v: List[int], max_bit_inclusive: int) -> List[int]:
    out = list(v)
    for wi in range(len(out)):
        keep = 0
        for b in range(64):
            g = wi * 64 + b
            if g <= max_bit_inclusive:
                keep |= 1 << b
        out[wi] &= keep
    return out


def gf2_conv_scalar(A: List[int], B: List[int]) -> List[int]:
    Wa, Wb = len(A), len(B)
    R = [0] * (Wa + Wb)
    for i, a in enumerate(A):
        aa = a
        while aa:
            bmask = aa & -aa
            k = (bmask.bit_length() - 1)
            for j, b in enumerate(B):
                if k == 0:
                    R[i + j] ^= b
                else:
                    R[i + j] ^= (b << k) & ((1 << 64) - 1)
                    R[i + j + 1] ^= (b >> (64 - k))
            aa ^= bmask
    # mask to 64-bit words
    return [x & ((1 << 64) - 1) for x in R]


def toep_127_scalar(top: List[int], ybits: List[int]) -> Tuple[int, int]:
    R = gf2_conv_scalar(ybits, top)
    out_lo = 0
    out_hi = 0
    for j in range(127):
        wi = j >> 6
        sh = j & 63
        bit = (R[wi] >> sh) & 1
        if j < 64:
            out_lo |= bit << j
        else:
            out_hi |= bit << (j - 64)
    return out_lo, out_hi


def rand_words(n: int, rng: random.Random) -> List[int]:
    return [rng.getrandbits(64) for _ in range(n)]


def influence_count(flip_top: bool) -> int:
    """How many bit positions change output when flipped (dense base)."""
    rng = random.Random(0xC0FFEE)
    y_words = words_for_bits(LPN_T)
    top_words = (LPN_T + 127 + 63) // 64
    top = rand_words(top_words, rng)
    y = rand_words(y_words, rng)
    base = toep_127_scalar(top, y)
    count = 0
    limit = top_words * 64 if flip_top else y_words * 64
    # only scan first LPN_T+200 for top, LPN_T for y
    if flip_top:
        limit = min(limit, LPN_T + 200)
    else:
        limit = min(limit, LPN_T)
    for b in range(limit):
        if flip_top:
            t2 = list(top)
            t2[b >> 6] ^= 1 << (b & 63)
            cur = toep_127_scalar(t2, y)
        else:
            y2 = list(y)
            y2[b >> 6] ^= 1 << (b & 63)
            cur = toep_127_scalar(top, y2)
        if cur != base:
            count += 1
    return count


def main() -> None:
    rng = random.Random(0x5151515151515151)
    y_words = words_for_bits(LPN_T)
    top_words = (LPN_T + 127 + 63) // 64
    N = 256
    match = 0
    for _ in range(N):
        top = rand_words(top_words, rng)
        y = rand_words(y_words, rng)
        full = toep_127_scalar(top, y)
        t1 = toep_127_scalar(zero_bits_above(top, 126), y)
        t2 = toep_127_scalar(top, zero_bits_above(y, 126))
        t3 = toep_127_scalar(zero_bits_above(top, 126), zero_bits_above(y, 126))
        if full == t1 == t2 == t3:
            match += 1

    # For effective bits: theoretical GF(2) poly multiply: out[j] = sum_{i=0..j} y[i]*top[j-i]
    # for j in 0..126, so only bits 0..126 of each operand matter.
    # Empirical influence with dense vectors should be 127 if all those positions matter.
    eff_top = influence_count(True)
    eff_y = influence_count(False)

    result = {
        "lpn_t": LPN_T,
        "vectors_tested": N,
        "full_vs_truncated_match_count": match,
        "full_vs_truncated_match_total": N,
        "effective_top_bits_empirical": eff_top,
        "effective_y_bits_empirical": eff_y,
        "theory": {
            "out_bits": 127,
            "depends_on_top_bits": "0..126",
            "depends_on_y_bits": "0..126",
            "note": (
                "Ordinary GF(2) poly convolution: coefficient j depends only on "
                "operand bits 0..j. Extracting j=0..126 => only bits 0..126 matter."
            ),
        },
        "prf_core_implication": (
            "If toep_127 is the only consumer of ybits and top inside prf_R_core, "
            "then only the first 127 LPN samples (ybits[0..126]) and first 127 "
            "Toeplitz stream bits affect R-core. Full prf equivalence still needs "
            "instrumented prf_R_core comparison (AES row generation cost)."
        ),
        "verdict_window": "PROVEN" if match == N else "FAILED",
    }

    outp = OUT / "toeplitz_window_result.json"
    outp.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    print("wrote", outp)
    print("sha256", hashlib.sha256(outp.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
