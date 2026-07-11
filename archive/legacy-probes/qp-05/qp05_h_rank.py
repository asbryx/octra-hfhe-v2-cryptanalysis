#!/usr/bin/env python3
"""QP-05: one-pass GF(2) rank of active public H (8192 x 16384) from pk.raw."""
from __future__ import annotations

import hashlib
import json
import struct
import time
from pathlib import Path

PK_RAW = Path(r"local-corpus/pk.raw")
OUT = Path(r"archive/legacy-probes/qp-05/qp05_h_rank.json")
EXPECTED_PK_RAW_SHA = "67e8538a2a47dfc1539d2777aa36488654b1c92265be08ed941f251a08c2ce28"
EXPECTED_H_DIGEST = "601435f4977dd2a0c396bd96c7947fb884b602a52b6d7e0660b3fce3508497f5"
M = 8192
N = 16384


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "little")

    def i32(self) -> int:
        return struct.unpack("<i", self.take(4))[0]

    def f64(self) -> float:
        return struct.unpack("<d", self.take(8))[0]


def parse_h_columns(raw: bytes) -> tuple[list[int], dict]:
    r = Reader(raw)
    assert r.take(6) == b"PVAC\x03\x01"
    params = {
        "B": r.i32(),
        "m_bits": r.i32(),
        "n_bits": r.i32(),
        "h_col_wt": r.i32(),
        "x_col_wt": r.i32(),
        "err_wt": r.i32(),
        "noise_entropy_bits": r.f64(),
        "tuple2_fraction": r.f64(),
        "depth_slope_bits": r.f64(),
        "edge_budget": r.u64(),
        "lpn_n": r.i32(),
        "lpn_t": r.i32(),
        "lpn_tau_num": r.i32(),
        "lpn_tau_den": r.i32(),
    }
    canon = r.u64()
    ncol = r.u64()
    cols = []
    for _ in range(ncol):
        nbits = r.u64()
        nw = r.u64()
        words = [r.u64() for _ in range(nw)]
        v = 0
        for i, w in enumerate(words):
            v |= w << (64 * i)
        # mask to nbits
        if nbits < 64 * nw:
            v &= (1 << nbits) - 1
        cols.append(v)
    return cols, {"params": params, "canon_tag": canon, "ncol": ncol, "pos_after_H": r.pos}


def gf2_rank_columns(cols: list[int], m: int = M) -> tuple[int, list[int]]:
    """Column-style Gaussian elimination over GF(2); returns rank and basis rows for left-kernel later.
    We treat each column as an m-bit vector. Rank of matrix with these columns.
    """
    # Work on a copy of columns; eliminate by row pivots using bit ops on column ints
    # Standard: build row-major is heavy; do column reduction:
    # For each row pivot position, find a column with that bit, swap into place, eliminate.
    work = cols[:]  # length N
    pivots = [-1] * m  # column index used as pivot for each row, else -1
    rank = 0
    col_used = [False] * len(work)

    for row in range(m):
        bit = 1 << row
        # find pivot column
        piv = -1
        for j in range(len(work)):
            if not col_used[j] and (work[j] & bit):
                piv = j
                break
        if piv < 0:
            continue
        col_used[piv] = True
        pivots[row] = piv
        rank += 1
        # eliminate this bit from all other columns
        for j in range(len(work)):
            if j != piv and (work[j] & bit):
                work[j] ^= work[piv]
    return rank, pivots


def left_kernel_vector(cols: list[int], pivots: list[int], m: int = M) -> int | None:
    """If rank < m, construct one nonzero left-kernel row-vector k (m bits) with k·H = 0.
    For free rows (no pivot), set that free bit and back-substitute.
    """
    free = [i for i in range(m) if pivots[i] < 0]
    if not free:
        return None
    # Build reduced row picture is expensive; use: solve H^T k = 0.
    # Since we have column-reduced form hard to invert, do fresh row-Gaussian on H^T:
    # H is m x n; left kernel is vectors k in F2^m with k^T H = 0.
    # Equiv: H^T k = 0, H^T is n x m.
    # Build matrix with m columns each of length n? Memory: n bits * m = 16384*8192/8 = 16MB OK.

    # Represent each of m columns of H^T (= rows of H) as n-bit int... wait rows of H are m, cols n.
    # H[r,c] = bit r of cols[c]
    # We need k such that for all c: sum_r k[r]*H[r,c] = 0
    # i.e. for each column c, parity of bits of col_c at positions where k=1 is 0.
    # So k is in left nullspace of columns.
    # Gaussian on rows: start with identity augmented? m equations? actually n equations on m vars.
    # System: A k = 0 where A is n x m, A[c,r] = H[r,c].

    # Use bit-packed rows of A (each row is m bits)
    rows = []
    for c in range(len(cols)):
        # build m-bit row: bits of this column vector already are H[*,c]
        rows.append(cols[c] & ((1 << m) - 1))

    basis = [0] * m
    for row in rows:
        r = row
        for col in range(m):
            bit = 1 << col
            if not (r & bit):
                continue
            if basis[col] == 0:
                basis[col] = r
                break
            r ^= basis[col]
    # free vars: columns without basis
    free_vars = [j for j in range(m) if basis[j] == 0]
    if not free_vars:
        return None
    # set one free var = 1, back-sub
    k = 1 << free_vars[0]
    # For each pivot col from high to low, enforce basis
    for col in range(m - 1, -1, -1):
        if basis[col] == 0:
            continue
        # if current k has this col bit? we need (basis[col] · k_extended) ...
        # Actually after RREF-ish: basis[col] has pivot at col and maybe higher free.
        # Standard nullspace: for free f, set x_f=1; for each pivot p, x_p = sum of basis[p] bits on free.
        b = basis[col]
        # parity of free bits in b that are set in k
        acc = 0
        for f in free_vars:
            if (b >> f) & 1:
                acc ^= (k >> f) & 1
        # also other pivots? if basis is not fully reduced this is approximate.
        # Reduce basis fully first.
        pass

    # Full RREF nullspace extraction
    # Convert basis list into RREF
    piv_cols = [j for j in range(m) if basis[j]]
    # forward already roughly echelon; reduce up
    for j in piv_cols:
        for i in range(m):
            if i != j and basis[i] and ((basis[i] >> j) & 1):
                basis[i] ^= basis[j]

    free_vars = [j for j in range(m) if basis[j] == 0]
    if not free_vars:
        return None
    f0 = free_vars[0]
    k = 1 << f0
    for j in range(m):
        if basis[j] == 0:
            continue
        if (basis[j] >> f0) & 1:
            k |= 1 << j
    return k


def main() -> None:
    raw = PK_RAW.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    assert sha == EXPECTED_PK_RAW_SHA, sha

    t0 = time.time()
    cols, meta = parse_h_columns(raw)
    assert meta["params"]["m_bits"] == M and meta["params"]["n_bits"] == N
    assert len(cols) == N

    # recompute H digest
    h = hashlib.sha256()
    h.update(b"H|v2")
    for name in ("m_bits", "n_bits", "h_col_wt"):
        h.update(meta["params"][name].to_bytes(8, "little", signed=True))
    # need original byte packing — re-parse for digest from deep_wire style
    # Use same as deep_wire_audit: col bytes from words
    r = Reader(raw)
    r.take(6)
    for _ in range(4):
        r.i32()
    for _ in range(2):
        r.i32()
    r.f64(); r.f64(); r.f64(); r.u64()
    for _ in range(4):
        r.i32()
    r.u64()  # canon
    ncol = r.u64()
    h2 = hashlib.sha256()
    h2.update(b"H|v2")
    for name in ("m_bits", "n_bits", "h_col_wt"):
        h2.update(int(meta["params"][name]).to_bytes(8, "little", signed=True))
    for _ in range(ncol):
        nbits = r.u64()
        nw = r.u64()
        words = [r.u64() for __ in range(nw)]
        colb = b"".join(x.to_bytes(8, "little") for x in words)
        h2.update(colb[: (nbits + 7) // 8])
    h_digest = h2.hexdigest()

    t1 = time.time()
    rank, pivots = gf2_rank_columns(cols, M)
    t2 = time.time()
    kernel_dim = M - rank
    kvec = left_kernel_vector(cols, pivots, M) if kernel_dim else None

    # Project active sigmas if kernel exists — load from secret.ct via deep parse optional
    projected = None
    if kvec is not None:
        # sample: project all columns of H onto k should be 0
        bad = sum(1 for c in cols if (c & kvec).bit_count() & 1)
        projected = {"kernel_dot_H_nonzero_cols": bad}

    report = {
        "probe": "QP-05",
        "pk_raw_sha256": sha,
        "H_digest_recomputed": h_digest,
        "H_digest_expected": EXPECTED_H_DIGEST,
        "H_digest_ok": h_digest == EXPECTED_H_DIGEST,
        "m_bits": M,
        "n_bits": N,
        "active_H_rank": rank,
        "left_kernel_dimension": kernel_dim,
        "left_kernel_vector_hex": format(kvec, "x") if kvec is not None else None,
        "projected_sigma_bias": projected,
        "parse_seconds": round(t1 - t0, 3),
        "rank_seconds": round(t2 - t1, 3),
        "canon_tag": meta["canon_tag"],
        "verdict": "CLOSED" if rank == M else "PROMISING",
        "close_reason": (
            "rank is full 8192; no left kernel; sigma-only structure already closed by CF-T3"
            if rank == M
            else "rank-deficient; inspect kernel vs decryption quantities"
        ),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in report if k != "left_kernel_vector_hex"}, indent=2))
    print("wrote", OUT)


if __name__ == "__main__":
    main()
