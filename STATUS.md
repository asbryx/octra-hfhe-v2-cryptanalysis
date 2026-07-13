# Status

**Result:** NOT SOLVED — practical public path exhausted at challenge HEAD `019380c`.

## Exact blocker

For each wrapped plaintext value:

```text
v = N0 / R0 + N1 / R1 mod p
R  = core_R1(PRF key, S) * core_R2(PRF key, S) * core_R3(PRF key, S)
```

The public update exposes R1 `(A,y)` samples only. It does not expose the PRF key, keyed Toeplitz top, R2/R3 labels, or PC blindings.

## Completed checks

- Full 44-file corpus validation: 720,896 unique rows, all hashes valid.
- Exact GF(2) rank: 4,096 from the first file; `[A|y]` rank 4,097.
- No exact two-row or three-row dependency in the first file.
- No active stream collision, counter overlap, or effective PRF-key reduction.
- Fixed-sample BKW, Prange, Stern, Walsh, local search, and information-set boundaries measured.
- PC/R coupling tested; mathematically real, not a practical target verifier.
- Finite public candidate family checked: 1,188 comparisons, no match.
- Wire, generator, wallet schema, repository history, forks, and independent smoke-ui findings reviewed.
- Cross-object rho cancellation has zero left kernel; shared-midstate enumeration keeps the full exponent.
- Known plaintext still leaves about `2^2794` inverse assignments; no small `H` relation below `2^48`.
- R endpoint, simple LPN covert channels, and public LPN-producer/secret searches are closed.
- Public funding provenance links canceled v1 value to active v2, but exact v1/v2 HFHE fingerprints differ and share no nonce, tag, or PC point.
- Full target-adjacent program and discovered Circle histories expose no target-bound secret or verifier.
- Current producer/fork delta remains clean; exact artifact paths expose no candidate oracle.
- Optimistic low-weight-dual decoding needs about `2^301` independent checks even when check generation is free.
- Circle shared auth/HFHE guards are present at lite-node `e88600f`; official target blobs are monitored daily.

## Reopen conditions

Reopen only for one of:

1. R2/R3 samples or keyed Toeplitz material.
2. A bounded, evidence-derived PRF-key candidate family.
3. Target-bound secret or blinding reuse.
4. A practical PC opening or candidate-R predicate.
5. Changed target artifacts or producer provenance.
6. A concrete algorithm materially below the measured boundaries.

## Canonical reports

- [`research/reconstruction-audit.md`](research/reconstruction-audit.md)
- [`research/final-exhaustion.md`](research/final-exhaustion.md)
- [`research/moonshot-closures.md`](research/moonshot-closures.md)
- [`research/public-chain-provenance.md`](research/public-chain-provenance.md)
- [`research/five-path-continuation.md`](research/five-path-continuation.md)
- [`docs/smoke-ui-comparison.md`](docs/smoke-ui-comparison.md)

This is a negative result, not an impossibility proof.
