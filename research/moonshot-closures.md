# Moonshot Closure Batch

**Date:** 2026-07-12

**Status:** NOT SOLVED — additional public-only edge cases closed

This batch records the final source-first probes run after the full LPN and PC/R exhaustion report. No plaintext, wallet credential, `prf_k`, LPN secret, complete `R`, or PC opening was recovered.

## Result table

| Hypothesis | Measured result | Verdict |
|---|---|---|
| Cross-object PC combination cancels `rho` | 22 rows, 44 disjoint nonzero `rho` coefficients, left kernel 0 | Closed |
| SHA layout of `rho` leaks/reduces `prf_k` | 44 unique first blocks; all 256 key bits affect digest/scalar | Closed |
| Shared SHA prefix plus 44 AES transcripts reduces search exponent | candidate work grows about 4x per +2 bits; only 43 extra checks | Closed for enumeration |
| Plaintext/address/padding determines layer inverses | fixed plaintext still leaves 22 field degrees, about `2^2794` assignments | Closed |
| Pedersen `H` has a signed small scalar relation to `G` | none for `|k| < 2^48`; self-check passed | Closed to measured bound |
| R endpoint collapses to zero/small family | zero folding, nonzero product, and inverse checks pass | Closed |
| Public sigma reconstructs noise groups | exact partition rate 0; rankings approximately random | Closed |
| Active wire fields are malformed or ignored in a useful way | canonical fields, exact lengths, valid references and points | Closed on fixed bytes |
| Producer CSPRNG has clonable user-space state | each `csprng_u64()` delegates to OS CSPRNG on supported platforms | Closed conditionally |
| LPN files contain a simple covert channel | no promoted marker/run; maximum monobit `|z|=2.7183` | Closed for tested channels |
| Public Git objects contain LPN producer or active secret | 8 refs, 140 unreachable objects, 124 blobs; no candidate | Closed |

## Cross-object rho cancellation

The active extractor maps all 22 wrapped objects and their 44 BASE layers. Each wrapped equation contains two keyed `rho` symbols not used by any other object. Since every public numerator is nonzero modulo the prime Ristretto order, any linear combination that cancels either symbol forces that object's coefficient to zero. Repeating this for every row leaves only the trivial combination.

Artifacts:

```text
tools/active_equation_map.cpp
results/active_equation_map.json
tools/rho_sha_layout.py
results/rho_sha_layout.json
```

## Shared SHA/AES candidate scaling

For each R1 transcript, the AES key is SHA-256-derived from the same 256-bit secret and a distinct public suffix. The reduced experiment reuses the exact SHA/AES derivation and enumerates 10-, 12-, 14-, and 16-bit candidate families.

```text
bits  candidates  one transcript evals  44-transcript evals
10         1,008                 1,008                  1,051
12         4,080                 4,080                  4,123
14        16,368                16,368                 16,411
16        65,520                65,520                 65,563
```

Wrong candidates die on transcript one; only the true candidate reaches the remaining 43. Multiple targets strengthen verification but do not generate candidates or alter the exponential search term.

Artifacts:

```text
tools/shared_midstate_scaling.py
results/shared_midstate_scaling.json
```

## Plaintext constraints

For every object, known plaintext gives one field equation in two nonzero layer inverses:

```text
T0*x0 + T1*x1 = v mod p
```

For each nonzero `x0`, at most one choice produces forbidden `x1=0`; therefore a fixed plaintext leaves at least `p-2` valid inverse pairs per object. Constructive witnesses were generated for all lengths 301 through 315 with the announced address embedded. Every run satisfies all 22 equations and leaves about 2,794 bits of inverse-assignment freedom.

Artifacts:

```text
tools/plaintext_constraint_bridge.py
results/plaintext_constraint_bridge.json
```

## Pedersen H and R endpoint

The official Ristretto implementation was searched with baby-step giant-step for both signs:

```text
|k| < 2^40  no relation  20.600713 s
|k| < 2^48  no relation  513.733273 s
```

Each run first recovers a built-in known scalar. This does not prove a large relation absent; it rules out the tested small-scalar range.

The R endpoint maps the 127-bit Toeplitz output into `Fp*`, folds only zero to one, multiplies three nonzero cores, and applies field inversion. Exact boundary checks show no public or small-family collapse downstream.

Artifacts:

```text
tools/rist_h_bsgs.cpp
results/rist_h_bsgs_2p40.json
results/rist_h_bsgs_2p48.json
tools/r_collapse_check.cpp
results/r_collapse_check.out
```

## Sigma, wire, and CSPRNG closures

Existing official-path labeled trials already test whether public edge fields recover N2/N3 origins. Across 200 ranking trials, exact partition recovery is zero; N2/N3 ranking is approximately random, while active candidate spaces remain combinatorial.

The active wire path was traced from bundle framing through deserialization, structure validation, compatibility validation, and decryption. The fixed bytes have canonical field and point encodings, valid edge/layer references, exact inner and outer lengths, and no useful ignored suffix.

`keygen()` calls `csprng_u64()` separately for `canon_tag`, four `prf_k` words, public generator candidates, `omega_B`, and 64 LPN-secret words. PVAC stores no user-space PRNG buffer. Linux, Windows, and Apple/BSD branches delegate to their OS CSPRNG APIs. The exact historical producer platform and binary remain unpublished, so this is a provenance condition rather than an unconditional statement about the historical run.

## LPN covert-channel scan

The 720,896 rows were scanned in both bit orders for direct `y` packing, row parity, endpoint bits, row-hash bits, row-major transposition, all-file XOR, layer-pair XOR, and concatenated header fields.

```text
promoted candidates     0
maximum monobit |z|     2.7183
maximum printable run   14 bytes
header printable run     8 bytes
```

Two case-folded three-byte `key` substrings were observed across all generated views. The promotion rule accounts for multiple testing and does not promote three-byte markers. No marker of at least four bytes or printable run of at least 16 bytes exists.

Artifacts:

```text
tools/lpn_stego_scan.py
results/lpn_stego_scan.json
```

## LPN producer provenance

The challenge publishes 44 JSONL files and a metadata-binding verifier, but not the sample generator. The verifier reads only the header and matches domain, seed, nonce, and public aggregate. It does not hash or recompute row-level `(A,y)` values from the active secret.

A Git-object scan covered main, `v2_fix`, PR heads 1 through 4, reachable history, and the local unreachable object cache. No sample producer, active `sk.bin`, plaintext, or generation log was found. GitHub code search found the public metadata fields only in the verifier. Independent recovery repositories contained structural audits or canceled-v1 material, not active recovery.

This does not imply the corpus is false. It means row-level common-secret provenance remains an organizer assertion rather than a machine-checkable public proof.

Artifacts:

```text
tools/scan_public_objects.py
results/public_object_scan.json
```

## Reopen conditions

Reopen this batch only if one of the following appears:

1. R2/R3 samples or keyed Toeplitz material for active layers.
2. A bounded evidence-derived `prf_k` family.
3. Target-bound secret, CSPRNG, `R`, or PC-blinding reuse.
4. An LPN producer, signed row manifest, or generation log.
5. Changed target bytes or a concrete algorithm below available resources.

The result remains a practical negative result, not a formal lower bound or impossibility proof.
