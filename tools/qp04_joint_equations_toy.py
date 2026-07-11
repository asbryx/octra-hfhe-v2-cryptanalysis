#!/usr/bin/env python3
"""Toy check for the same-key PC/R coupling exposed by public R1 labels."""

import hashlib

P = 127                 # toy Fp analogue of 2^127-1
L = 65537               # toy prime-order group, represented by exponents of G
H = 23456                # toy discrete log of the public H point; code only uses rho*H
KEYS = 1 << 16
TRUE_K = 0xBEEF
S = 0b1011011
SEEDS = (b"layer-0", b"layer-1")


def h(tag: bytes, *parts: object) -> int:
    d = hashlib.sha256(tag)
    for part in parts:
        if isinstance(part, int):
            d.update(part.to_bytes(4, "little"))
        else:
            d.update(part)
    return int.from_bytes(d.digest(), "little")


def core(k: int, seed: bytes, domain: bytes, y: int) -> int:
    top = h(b"toep", k, seed, domain) & P
    out = 0
    for j in range(7):
        bit = 0
        for i in range(j + 1):
            bit ^= ((y >> i) & 1) & ((top >> (j - i)) & 1)
        out |= bit << j
    return out if 0 < out < P else 1


def hidden_y(k: int, seed: bytes, domain: bytes, secret: int = S) -> int:
    y = 0
    for row in range(7):
        a = h(b"row", k, seed, domain, row) & P
        e = h(b"noise", k, seed, domain, row) & 1
        y |= (((a & secret).bit_count() & 1) ^ e) << row
    return y


def rho(k: int, seed: bytes) -> int:
    return h(b"pvac.prf.rho", k, seed, 0) % L


def center(x: int) -> int:
    return x if x <= P // 2 else x - P


def in_centered_fp(q: int) -> bool:
    return q <= P // 2 or q >= L - P // 2


def decode_centered_fp(q: int) -> int:
    assert in_centered_fp(q)
    return q if q <= P // 2 else P - (L - q)


def layer(k: int, seed: bytes, public_y1: int):
    c1 = core(k, seed, b"R1", public_y1)
    c2 = core(k, seed, b"R2", hidden_y(k, seed, b"R2"))
    c3 = core(k, seed, b"R3", hidden_y(k, seed, b"R3"))
    r = c1 * c2 * c3 % P
    x = pow(r, -1, P)
    pc = (center(x) + rho(k, seed) * H) % L
    return c1, c2, c3, r, x, pc


def main() -> None:
    public_y1 = (0b1100101, 0b0111010)
    truth = [layer(TRUE_K, seed, y) for seed, y in zip(SEEDS, public_y1)]

    survivors = []
    for count in (1, 2):
        hits = []
        for k in range(KEYS):
            if all(in_centered_fp((truth[i][5] - rho(k, SEEDS[i]) * H) % L)
                   for i in range(count)):
                hits.append(k)
        survivors.append(hits)
        assert TRUE_K in hits

    # Once k is known, a bounded DLP opens x and public y_R1 gives c1.
    # Only c2*c3 follows; every nonzero c2 has one matching c3.
    c1, c2, c3, r, x, pc = truth[0]
    q = (pc - rho(TRUE_K, SEEDS[0]) * H) % L
    opened_x = decode_centered_fp(q)
    product23 = pow(opened_x, -1, P) * pow(c1, -1, P) % P
    factors = [(a, product23 * pow(a, -1, P) % P) for a in range(1, P)]
    assert opened_x == x and (c2, c3) in factors and len(factors) == P - 1

    # If k is known, the PC opening also verifies the remaining toy LPN secret.
    secret_hits = []
    for secret in range(1 << 7):
        z2 = core(TRUE_K, SEEDS[0], b"R2", hidden_y(TRUE_K, SEEDS[0], b"R2", secret))
        z3 = core(TRUE_K, SEEDS[0], b"R3", hidden_y(TRUE_K, SEEDS[0], b"R3", secret))
        if z2 * z3 % P == product23:
            secret_hits.append(secret)
    assert S in secret_hits

    # Public numerators form a second range equation only after rho(k) is removed.
    r0, x0, pc0 = truth[0][3], truth[0][4], truth[0][5]
    r1, x1, pc1 = truth[1][3], truth[1][4], truth[1][5]
    value, mask = 19, 37
    n0 = r0 * (value + mask) % P
    n1 = r1 * (-mask) % P
    assert (n0 * x0 + n1 * x1) % P == value
    carry = (n0 * center(x0) + n1 * center(x1) - center(value)) // P
    residual = (n0 * pc0 + n1 * pc1 - center(value)
                - (n0 * rho(TRUE_K, SEEDS[0]) + n1 * rho(TRUE_K, SEEDS[1])) * H) % L
    assert residual == (carry * P) % L and abs(carry) < P

    print(f"one_PC_survivors={len(survivors[0])} expected~{KEYS * P / L:.1f}")
    print(f"two_PC_survivors={len(survivors[1])} keys={survivors[1]}")
    print(f"R23_product={product23} ordered_factor_pairs={len(factors)}")
    print(f"toy_secret_survivors_after_one_opened_PC={len(secret_hits)} keys={secret_hits}")
    print(f"numerator_unblinded_carry={carry} residual_is_carry_times_p=YES")
    print("verdict=NONTRIVIAL_BOUNDED_DLP_PREDICATE_NOT_A_PARTIAL_KEY_OR_FACTOR_SPLIT")


if __name__ == "__main__":
    main()
