#!/usr/bin/env python3
"""Model the target LPN instance and run deliberately non-extrapolated small probes."""

import argparse
import math
import time

import numpy as np

N_TARGET = 4096
M_TARGET = 720_896
TAU = 1 / 8
RATIO = M_TARGET // N_TARGET
RHO = 1 - 2 * TAU
PARITY8 = np.array([i.bit_count() & 1 for i in range(256)], dtype=np.uint8)


def log2_choose(n, k):
    if k < 0 or k > n:
        return -math.inf
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2)


def h2(p):
    if p in (0, 1):
        return 0.0
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)


def parity64(values):
    raw = np.ascontiguousarray(values, dtype=np.uint64).view(np.uint8).reshape(-1, 8)
    return np.bitwise_xor.reduce(PARITY8[raw], axis=1)


def make_instance(n, rng):
    m = RATIO * n
    rows = rng.integers(0, 1 << n, size=m, dtype=np.uint64)
    secret = int(rng.integers(0, 1 << n, dtype=np.uint64))
    # Conditioning on fixed weight makes the hypergeometric model exact.
    error = np.zeros(m, dtype=np.uint8)
    error[rng.choice(m, m // 8, replace=False)] = 1
    labels = parity64(rows & np.uint64(secret)) ^ error
    return rows, labels, secret


def residual_bias(rows, labels, secret):
    error = labels ^ parity64(rows & np.uint64(secret))
    return float(np.sum(1 - 2 * error.astype(np.int16))), len(error)


def bkw_disjoint(rows, labels, secret, n, block, rounds):
    result = [residual_bias(rows, labels, secret)]
    for level in range(rounds):
        shift = level * block
        if shift + block > n or len(rows) < 2:
            break
        keys = (rows >> shift) & ((1 << block) - 1)
        order = np.argsort(keys, kind="stable")
        cuts = np.flatnonzero(keys[order][1:] != keys[order][:-1]) + 1
        groups = np.split(order, cuts)
        left, right = [], []
        for group in groups:
            paired = len(group) // 2 * 2
            if paired:
                left.append(group[:paired:2])
                right.append(group[1:paired:2])
        if not left:
            break
        left = np.concatenate(left)
        right = np.concatenate(right)
        rows = rows[left] ^ rows[right]
        labels = labels[left] ^ labels[right]
        result.append(residual_bias(rows, labels, secret))
    return result


def fwht(values):
    width = 1
    while width < len(values):
        view = values.reshape(-1, 2 * width)
        left = view[:, :width].copy()
        right = view[:, width:].copy()
        view[:, :width] = left + right
        view[:, width:] = left - right
        width *= 2
    return values


def walsh_recover(rows, labels, n):
    scores = np.bincount(
        rows.astype(np.int64),
        weights=1.0 - 2.0 * labels.astype(np.float64),
        minlength=1 << n,
    )
    return int(np.argmax(fwht(scores))), scores.nbytes


def solve_square(rows, labels, n):
    matrix = [int(a) | (int(b) << n) for a, b in zip(rows, labels)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if (matrix[r] >> col) & 1), None)
        if pivot is None:
            return None
        matrix[col], matrix[pivot] = matrix[pivot], matrix[col]
        for row in range(n):
            if row != col and ((matrix[row] >> col) & 1):
                matrix[row] ^= matrix[col]
    return sum(((matrix[col] >> n) & 1) << col for col in range(n))


def prange_attempts(rows, labels, secret, n, rng, limit=100_000):
    for attempt in range(1, limit + 1):
        chosen = rng.choice(len(rows), n, replace=False)
        candidate = solve_square(rows[chosen], labels[chosen], n)
        if candidate == secret:
            return attempt
    return None


def stern_model(p, item_bytes=32):
    """Two-list Stern model conditioned on W=M/8."""
    n, k, w = M_TARGET, N_TARGET, M_TARGET // 8
    log_l = log2_choose(k // 2, p // 2)
    best = None
    for ell in range(max(0, math.floor(log_l) - 2), math.ceil(log_l) + 3):
        log_p = 2 * log_l + log2_choose(n - k - ell, w - p) - log2_choose(n, w)
        log_pass = max(log_l, 2 * log_l - ell)
        candidate = (log_pass - log_p, ell, log_l, -log_p, log_pass)
        if best is None or candidate < best:
            best = candidate
    total, ell, log_l, neg_log_p, log_pass = best
    return {
        "p": p,
        "ell": ell,
        "log2_list": log_l,
        "log2_memory_bytes": log_l + math.log2(item_bytes),
        "log2_success_inverse": neg_log_p,
        "log2_list_work": total,
        "log2_pass_work": log_pass,
    }


def print_target_model(bkw_block=15):
    n, m, w = N_TARGET, M_TARGET, M_TARGET // 8
    log_prange_fixed = log2_choose(m, w) - log2_choose(m - n, w)
    log_prange_iid = -n * math.log2(1 - TAU)
    capacity = 1 - h2(TAU)
    print("MODEL TARGET (analytic; not a toy benchmark result)")
    print(f"n={n}, M={m}=176n, W=M/8={w}, rho={RHO:.2f}")
    print(f"matrix-packed={m * n / 8 / 2**20:.1f} MiB; capacity={capacity:.9f}; n/C={n/capacity:.1f}")
    print(f"Prange log2(E): iid={log_prange_iid:.3f}; fixed-W={log_prange_fixed:.3f}")
    print(f"Walsh: memory=2^{n + 3} byte; work~2^{n + math.log2(n):.1f} butterfly-op")

    print(f"BKW LF2 optimistic, block={bkw_block} (capacity bound ignores correlation):")
    remaining = float(m)
    bins = 1 << bkw_block
    for level in range(5):
        bias = RHO ** (1 << level)
        q = (1 - bias) / 2
        dimension = n - level * bkw_block
        info = remaining * (1 - h2(q))
        print(f"  t={level}: N~{remaining:.0f}, d={dimension}, bias={bias:.6g}, info_upper~{info:.1f} bit")
        occupied = bins * (1 - math.exp(-remaining / bins))
        remaining -= occupied

    print("Stern two-list fixed-W (32 byte/item; elimination cost not included):")
    for p in (4, 6, 32):
        model = stern_model(p)
        print(
            "  p={p:2d}, l={ell:3d}: list=2^{log2_list:.2f}, memory=2^{log2_memory_bytes:.2f} byte, "
            "1/P=2^{log2_success_inverse:.2f}, list-work=2^{log2_list_work:.2f}".format(**model)
        )
    print()


def toy_run(sizes, repetitions, block, rounds, seed):
    print("PROBE TOY fixed-W (checks local laws only; do not fit a security exponent)")
    rank_probability = math.prod(1 - 2 ** (-j) for j in range(1, 80))
    for n in sizes:
        if not 4 <= n <= 22:
            raise ValueError("toy size must be 4..22 so the Walsh table stays bounded")
        rng = np.random.default_rng(seed + n)
        bias_sums = [0] * (rounds + 1)
        bias_counts = [0] * (rounds + 1)
        attempts = []
        first = None
        for _ in range(repetitions):
            rows, labels, secret = make_instance(n, rng)
            if first is None:
                first = rows.copy(), labels.copy(), secret
            for level, (signed_sum, count) in enumerate(
                bkw_disjoint(rows, labels, secret, n, block, rounds)
            ):
                bias_sums[level] += signed_sum
                bias_counts[level] += count
            attempt = prange_attempts(rows, labels, secret, n, rng)
            if attempt is None:
                raise RuntimeError("toy Prange limit is too small")
            attempts.append(attempt)

        rows, labels, secret = first
        started = time.perf_counter()
        recovered, table_bytes = walsh_recover(rows, labels, n)
        seconds = time.perf_counter() - started
        assert recovered == secret

        m, w = len(rows), len(rows) // 8
        p_clean = 2 ** (log2_choose(m - w, n) - log2_choose(m, n))
        expected_draws = 1 / (p_clean * rank_probability)
        duplicate_rate = 1 - len(np.unique(rows)) / m
        observed = sum(attempts) / len(attempts)
        print(
            f"n={n:2d} M={m:4d}: Walsh={seconds:.4f}s/{table_bytes/2**20:.1f}MiB, "
            f"Prange mean={observed:.1f} vs theory-draw={expected_draws:.1f}, dup={duplicate_rate:.3%}"
        )
        measured = ", ".join(
            f"t={level}:{bias_sums[level]/bias_counts[level]:+.4f}/{RHO ** (1 << level):.4f}"
            for level in range(len(bias_counts))
            if bias_counts[level]
        )
        print(f"  measured/theoretical BKW bias: {measured}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", default="18,20,22")
    parser.add_argument("--repetitions", type=int, default=24)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--bkw-block", type=int, default=4)
    parser.add_argument("--bkw-rounds", type=int, default=3)
    parser.add_argument("--model-only", action="store_true")
    args = parser.parse_args()

    print_target_model()
    if not args.model_only:
        sizes = [int(value) for value in args.sizes.split(",")]
        toy_run(sizes, args.repetitions, args.bkw_block, args.bkw_rounds, args.seed)


if __name__ == "__main__":
    main()
