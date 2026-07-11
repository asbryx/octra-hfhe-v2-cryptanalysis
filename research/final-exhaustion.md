# Octra HFHE v2 — Final Exhaustion Addendum at 019380c

**Date:** 2026-07-11
**Status:** NOT SOLVED — PRACTICAL PUBLIC PATH EXHAUSTED
**Challenge HEAD:** `019380c97543620091409b0fbf73a8a773a9a0da`
**Pinned PVAC:** `071b0e909c119de815e284b347c4bd979cb59ef3`

## Final result

No plaintext, wallet key, `prf_k`, LPN secret `S`, complete `R`, or PC opening was recovered.

The July 11 corpus materially improves candidate verification but does not provide a practical candidate-generation method:

```text
published A_R1  -> exact verifier for a candidate prf_k
published y_R1  -> statistical verifier for a candidate S
prf_k alone     -> R1 core only; R2/R3 y-values still require S
S alone         -> no keyed rows, selector words, Toeplitz top, R1/R2/R3
prf_k + S       -> all R factors and normal decryption
```

The active secret components remain independent outputs of system CSPRNG:

```text
prf_k = 256 bits
S     = 4096 bits
```

## Full corpus validation

All 44 files were streamed from the canonical `019380c` tree and checked without retaining the 756 MB corpus locally.

```text
files                       44/44
SHA-256 against SHA256SUMS   44/44
rows                        720,896
unique A rows               720,896
intra/cross-file duplicates 0
sequential row IDs          all
A width                      4096 bits
cipher indexes               0..21
layer IDs                    0,1
slot                         0
unique seed tuples           44
unique public_T              44
domain                       pvac.prf.r.1 only
y=1                          360,224 / 720,896 = 0.4996892756
A row weight range           1,899..2,198
A row mean weight            2,047.9401
```

This closes repeated-row majority voting, duplicate-matrix reuse, malformed row ordering, incorrect committed hashes, and simple sparse-row shortcuts.

Artifacts:

```text
tools/validate_lpn_corpus.py
SHA-256 1e7b7639a38fa1bdfdf41a94d244aef94de3af3775a39b11b3310ce4199d5acc

tools/lpn_corpus_validation.json
SHA-256 73d9521beaaf734fd9ebe4fc3c24048cb12f57e982d858f95c5f22e18dcfd789
```

The official tool still validates only header metadata. Full-file SHA checks prove publication integrity, not machine-checkable common-`S` provenance.

## Exact dependency bridge

For each layer seed and PRF domain, pinned source derives an AES key from:

```text
prf_k || canon_tag || H_digest || ztag || nonce || domain
```

The R-domain stream emits 64 words for every 4096-bit `A` row and then a selector word for Bernoulli noise. A separate `Dom::TOEP` derivation emits the Toeplitz top.

### What a candidate prf_k enables

A candidate `prf_k` can be rejected from the first published R1 `A` row with about 4096 known output bits. No `S` is needed for that check.

If `prf_k` is correct:

- all R1 `A` rows and selector bits can be regenerated;
- keyed R1 Toeplitz top can be regenerated;
- published `y_R1` can be compressed into each R1 core;
- R2/R3 rows and selector bits can be generated, but their `y` values still require `S`.

Thus `prf_k` alone does not produce full `R = R1*R2*R3`.

### What a candidate S enables

A candidate `S` can be scored over all published equations by checking whether residuals have noise rate near `1/8`. With 720,896 equations, a correct candidate is easy to distinguish from a wrong candidate.

But `S` alone cannot generate:

- R-domain AES rows or selector words;
- Toeplitz top;
- R2/R3 transcripts;
- PC blinding `rho`.

Therefore recovering `S` alone does not decrypt the target.

### AES alignment result

Published `A` exposes only the AES output words used as rows. On alternating rows, one published half-block is adjacent to the hidden selector half-block. Knowing one 64-bit half of an AES-256 output block does not reveal the other half or key.

Toeplitz uses a fresh AES object and separately derived key/nonce. No R1/R2/R3 Toeplitz counter-range overlap was found for the 44 active seeds.

## Finite public candidate check

The existing 99 evidence-derived 32-byte candidates were retested against the new exact R1 row verifier through:

```text
direct little-endian prf_k
direct big-endian prf_k
keygen_from_seed derivation
```

Four plausible JSONL row layouts were checked:

```text
raw
full reverse
per-u64 reverse
u64-word-order reverse
```

Result:

```text
99 candidates * 3 routes * 4 layouts = 1,188 checks
matches = 0
```

Artifact:

```text
tools/check_finite_prf_candidates.py
SHA-256 d093d37d8089a7808bf68b6c4bec18bb07ee88a21d6faa29af06e2cf361e6eb3
```

This closes only the finite public family. It is not a generic 256-bit search.

## Feasibility boundary

Assuming all files honestly share one dense random `S` and independent noise `tau=1/8`:

```text
information floor       about 8,974 samples
available samples       720,896
optimistic BKW model    about 2^425 work, requiring impossible tables/data
Prange baseline         about 2^791.48 trials
clean-set + elimination about 2^823 bit operations
```

The corpus is information-rich but does not make recovery computationally practical. Tiny scaled estimator runs degenerated to small `p=0` regimes; larger runs exhausted resources. Those outputs were not extrapolated.

### Exact rank and low-weight dependency audit

The first public R1 file alone gives:

```text
A rank                       4096
[A|y] rank                   4097
row nullity                  12288
first full-rank prefix       4097 rows
2-row dependencies           0
3-row dependencies           0 across 134,209,536 pairs
lowest sampled pair XOR wt   1961
```

Because one file already has full column rank, additional files cannot raise rank. They add redundancy for noisy decoding only. A 4,400-row cross-file elimination found dense dependencies with median weight about 2,051; their residual bias is effectively zero, so they neither verify common `S` nor create equations for it.

### Restricted-sample promotion gate

The fixed corpus was modeled and checked with toy ladders that preserve `M=176n` and `tau=1/8` without fitting a target exponent:

```text
Prange fixed-weight                 2^791.48 trials
Stern p=4, ~64 MiB extra memory     2^785.74 list work
Stern p=6, ~42.5 GiB extra memory   2^783.87 list work
restricted BKW level 3              ~4509 optimistic information bits / 4051 dimensions
restricted BKW level 4              ~43 optimistic information bits / 4036 dimensions
```

Information-set experiments through `n=60` stopped using only the public all-row agreement score. Public accepts matched the planted secret in every accepted toy trial, but attempt growth matched the probability of selecting an error-free, full-rank subset. All theoretical per-attempt probabilities fell inside observed 95% intervals; no Bonferroni-corrected deviation was promoted.

This validates the implementation and public verifier, not a shortcut: at `n=4096`, the same method returns to the Prange exponent above.

### QP-04 final status

The PC/R relation is nontrivial but not a practical active-target verifier. For a full candidate `prf_k`, removing candidate `rho*H` leaves a point that should be a centered 127-bit multiple of `G`. Testing or opening that range requires a generic bounded group search of about `2^63.5` operations. The toy model represents group elements as known integer exponents and therefore gives that opening for free.

After such an opening, public R1 data determines only `core_R2*core_R3`, not either factor. This is weaker and more expensive than checking a candidate `prf_k` directly against one public R1 row.

## smoke-ui assessment audit

Reference repository:

```text
smoke-ui/octra-hfhe-v2-security-assessment
commit 827da3847f3044d255d45ddff994ed0ba9fe65de
```

Useful contributions:

- independent active-wire parsing;
- order-337 subgroup negative controls;
- generic wrapped-algebra controls;
- compiler/runtime engineering observations;
- historical RNG audit.

It does not narrow `prf_k`, `S`, R2/R3, PC opening, or plaintext. Its threat model is stale at `0d08e96`: statements that no explicit `(A,y)` exists are invalid after `d9d29d5`/`019380c`.

### Compiler-family serialization difference

The reported GCC/Clang seeded-byte difference has a source-level cause: seeded wrappers pass two calls that both consume the same `SeedableRng&` as arguments to one `combine_ciphers(...)` expression:

```text
enc_fp_depth_seeded(..., rng),
enc_fp_depth_seeded(..., rng)
```

C++ does not specify which function argument is evaluated first. Compiler families can therefore assign successive random-stream regions to opposite wrapper layers in different orders.

The non-seeded wrapper has the same ordering issue with global CSPRNG-consuming calls. This affects deterministic byte reproduction, not the fixed target's confidentiality:

- both layers still receive independent random material;
- active bytes are already fixed and canonical;
- no secret bit or candidate family is exposed;
- decryption still returns the same wrapped value.

References:

- `pvac_hfhe_cpp@071b0e9/include\pvac\ops\encrypt.hpp:981`
- `pvac_hfhe_cpp@071b0e9/include\pvac\ops\encrypt.hpp:1064`

### Toeplitz first-use race

The unsynchronized lazy dispatch race is a valid runtime defect, but the target producer path is not evidenced to have invoked first-use Toeplitz concurrently. A static public artifact cannot trigger the race retroactively. No target-bound wrong-R relation follows from it.

### Statistical experiments

The tensor and invariant experiments produced no held-out plaintext predictor. They should not be treated as universal closure:

- some raw datasets/logs are absent;
- the invariant tool's Benjamini-Hochberg calculation is incomplete;
- Phase II predates the R1 corpus;
- no positive active-target candidate resulted.

These limitations reopen methodology, not a recovery path.

## Remaining algebra

For every wrapped object:

```text
v = N0/R0 + N1/R1 mod p
```

There are 44 independently seeded BASE-layer factors. Structured plaintext constraints remain:

```text
length q0 = 301..315 under producer provenance
q1..q21 < 2^120
last block has a length-dependent zero suffix
```

Those constraints are useful only after a bounded candidate family for layer inverses, `prf_k`, or plaintext appears. They do not independently eliminate the 44 unknown factors.

## Closed paths

```text
repeated A rows / majority vote               CLOSED
malformed or incomplete committed corpus      CLOSED
finite public prf_k/seed candidates            CLOSED
known-A to selector/Toeplitz stream extension CLOSED
S alone to full R                              CLOSED by dependency
R1 samples to R2/R3                            CLOSED by domain separation
v1 R_com candidate verifier                    CLOSED on v3 wire
PC/rho cancellation from nonce reuse           CLOSED on fixed artifact
simple pair/triple public collisions           CLOSED
stock wallet export/schema match               CLOSED
smoke-ui runtime/compiler anomaly to target    CLOSED
current public forks/PRs containing recovery   CLOSED
```

## Reopen conditions

Do not spend more local compute unless at least one appears:

1. R2/R3 samples or Toeplitz material associated with the active layers.
2. A reduced or evidenced candidate family for `prf_k`.
3. A separately rewarded and concretely feasible route to `S`.
4. A target-bound reuse of `prf_k`, `S`, R, or PC blinding.
5. A public opening/predicate for candidate R or plaintext.
6. New fixed artifact bytes or producer provenance showing a different path.
7. A practical algorithm with a concrete estimate below available resources.

## Final verdict

```text
Mathematically impossible?       NO
Information-theoretically stuck? NO; the R1 corpus is information-rich
Practically solvable publicly?   NO KNOWN FEASIBLE METHOD
Cheap missed step remaining?     NONE FOUND
Current action                   STOP COMPUTE; WATCH PUBLIC DELTA
```

The challenge may depend on an undisclosed clue, additional artifact, or implementation property not present in the public package. With current evidence, further generic computation is not justified.
