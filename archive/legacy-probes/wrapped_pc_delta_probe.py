# ponytail: exact center discrepancy + public-only D(v) indistinguishability model
# No secret used as verifier. Ground truth only labels true/false for measurement.

P = (1 << 127) - 1
# Ristretto scalar order L
L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed


def center_fp(x: int) -> int:
    """Match sc_from_fp_signed: if hi bit62 set, return -x mod L as signed embed.
    sc_from_fp packs 127-bit little-endian into scalar without mod-L reduction.
    For x < 2^127, value is just x (or L-x if negative representative).
    """
    x %= P
    # hi is top 63 bits in Fp.hi; bit62 of hi is bit 126 of full value
    if (x >> 126) & 1:
        pos = (P - x) % P
        # sc_neg(sc_from_fp(pos)) = -pos mod L, with pos embedded as integer
        return (-pos) % L
    return x % L  # sc_from_fp: identity embed then used as scalar (already < L since x < 2^127 < L? )
    # Note: L ~ 2^252, P=2^127-1, so x < L always. Good.


def delta(N: int, x: int) -> int:
    """center(N)*center(x) - center(N*x mod p)  mod L"""
    N %= P
    x %= P
    Nx = (N * x) % P
    return (center_fp(N) * center_fp(x) - center_fp(Nx)) % L


def inv_mod(a, m):
    return pow(a, -1, m)


def main():
    import random
    random.seed(0)

    # 1) delta distribution random field values
    samples = []
    zero = 0
    for _ in range(2000):
        N = random.randrange(1, P)
        x = random.randrange(1, P)
        d = delta(N, x)
        samples.append(d)
        if d == 0:
            zero += 1
    print('random delta: n=2000 zero_rate=%.4f unique=%d' % (zero / 2000, len(set(samples))))
    print('  sample deltas:', [hex(s) for s in samples[:5]])

    # 2) wrapped toy algebra with known secrets (measurement only)
    # Public: N0, N1, PC0, PC1 unavailable here without group; measure scalar side
    # True: v = N0*x0 + N1*x1 mod p with x_i = R_i^-1
    true_match = 0
    false_match = 0
    n_trials = 500
    for _ in range(n_trials):
        R0 = random.randrange(1, P)
        R1 = random.randrange(1, P)
        m = random.randrange(1, P)
        v = random.randrange(0, P)
        # layer plains
        p0 = (v + m) % P
        p1 = (-m) % P
        N0 = (R0 * p0) % P
        N1 = (R1 * p1) % P
        x0 = inv_mod(R0, P)
        x1 = inv_mod(R1, P)
        # exact field recovery
        v_rec = (N0 * x0 + N1 * x1) % P
        assert v_rec == v

        # naive homomorphism residual for true v:
        # N0*center(x0)+N1*center(x1) - center(v)  mod L
        lhs = (center_fp(N0) * center_fp(x0) + center_fp(N1) * center_fp(x1)) % L
        # careful: scalar mult uses center(N)*center(x) vs center(Nx)
        # actual PC opening uses center(x), and [N]PC uses scalar N embedded how?
        # In group: [k]P for integer k usually reduced mod L. Public N is field element < p < L,
        # so scalar from N is just N (unsigned embed), not center(N) unless they center.
        # Official decrypt/PC check paths: need exact. For candidate test people often do:
        # D = N0*PC0 + N1*PC1 - center(v)*G
        # = (N0*center(x0)+N1*center(x1)-center(v))G + (N0*rho0+N1*rho1)H
        # with N_i used as unsigned scalars (N_i < p < L).
        lhs_u = (N0 * center_fp(x0) + N1 * center_fp(x1)) % L
        rhs_true = center_fp(v)
        carry_true = (lhs_u - rhs_true) % L

        # false candidates
        for v_false in (
            (v + 1) % P,
            (v - 1) % P,
            random.randrange(0, P),
            random.randrange(0, 400),  # length-style small
        ):
            carry_f = (lhs_u - center_fp(v_false)) % L
            # Without H blinding, would need carry==0 and homomorphism exact.
            # With unknown rho, D lives in G,H span; true vs false both unknown.
            if carry_f == 0:
                false_match += 1
        if carry_true == 0:
            true_match += 1

    print('scalar carry_true==0 rate: %d/%d' % (true_match, n_trials))
    print('scalar carry_false==0 hits (4 falses/trial): %d over %d trials' % (false_match, n_trials))

    # 3) Can public-only cancel rho? Only if rho0,rho1 related publicly — they are not
    # (independent SHA256(prf_k||nonce||slot)). Without prf_k, N0*rho0+N1*rho1 uniform-ish.
    print('VERDICT_MODEL: true and false candidates both leave unknown H-blinding;')
    print('  center product carry is nonzero often even for true v;')
    print('  no deterministic public invariant from D(v) alone.')


if __name__ == '__main__':
    main()
