# Comparison with smoke-ui's Security Assessment

Reference: [`smoke-ui/octra-hfhe-v2-security-assessment`](https://github.com/smoke-ui/octra-hfhe-v2-security-assessment), assessed at commit `827da3847f3044d255d45ddff994ed0ba9fe65de`.

## Shared conclusions

Both assessments independently conclude that:

- the v1 candidate-checking commitment is absent from the active v2 wire;
- wrapped plaintext values use two independently randomized BASE layers;
- the active producer calls nondeterministic `keygen()`, not `keygen_from_seed()`;
- no historical RNG reuse, nonce reuse, public PC opening, subgroup shortcut, or practical plaintext predicate was found;
- the target artifact is canonical and contains 22 ciphertext objects, 44 BASE layers, and no PROD layers;
- no plaintext or wallet key was recovered.

## What smoke-ui does especially well

The smoke-ui repository provides a broad engineering assessment with:

- an independent Rust wire parser;
- structured mutation and fuzzing controls;
- compiler and architecture comparisons;
- runtime, timing, entropy-fault, and concurrency probes;
- subgroup and generic wrapped-algebra controls;
- a clear evidence ladder and disclosure posture.

Its Toeplitz lazy-initialization race and parser-hardening findings remain useful engineering results even though they do not recover the challenge plaintext.

## Snapshot difference

The smoke-ui assessment pins challenge commit `0d08e9622921e5930175a660df0061a65548972f`, the announcement snapshot. OCTRA later added 44 R1 LPN files in `d9d29d505e2840c0028d7a91a2a8ba59e163b9a4` and clarified their role in current HEAD `019380c97543620091409b0fbf73a8a773a9a0da`.

Accordingly, smoke-ui statements that explicit public `(A,y)` samples are unavailable were correct for its pinned snapshot but are stale for current HEAD. The target `pk.bin` and `secret.ct` bytes did not change.

## Additional work in this repository

This repository adds:

1. **Timeline reconstruction**
   - Distinguishes the target-byte commit, activation commit, announcement snapshot, and live HEAD.

2. **Complete live-corpus validation**
   - Streams all 44 JSONLs, verifies upstream SHA-256 values, and checks every row's shape, order, uniqueness, weight, and metadata.

3. **Exact active R1 algebra**
   - Computes exact GF(2) rank and low-weight dependency results from the published rows rather than dummy PRF keys.

4. **Restricted-sample modeling**
   - Separates unlimited-data BKW estimates from what the fixed 720,896-row corpus can support.

5. **Dependency bridge audit**
   - Traces what public R1 rows reveal about candidate PRF keys, the LPN secret, keyed Toeplitz extraction, R2/R3, PC openings, and decryption.

6. **Claim narrowing**
   - Treats heuristic-specific negative results as narrow evidence rather than universal closure.

## Differences in interpretation

| Topic | smoke-ui snapshot | This repository at `019380c` |
|---|---|---|
| Public LPN samples | Not available | 44 R1 files, 720,896 equations |
| Challenge commit naming | `0d08e96` as assessed challenge | Four separate timeline anchors |
| Length `301..315` | Metadata leakage | Producer-bound inference, not parser-only invariant |
| Active LPN rank | Reduced/dummy-key evidence | Exact rank 4,096 from the first public file |
| PC/R relation | No practical predicate | Nontrivial range relation, but it needs about `2^63.5` bounded group work after a full PRF-key guess |
| Statistical closure | Broad negative assessment | Probe-specific closure with explicit promotion gates |

## Bottom line

The repositories are complementary, not competing. smoke-ui is stronger on broad implementation assessment and engineering controls. This repository is narrower and deeper on the current R1 corpus, exact active algebra, fixed-sample decoding limits, and chronology.

Neither repository demonstrates plaintext recovery. The combined public evidence still leaves the keyed Toeplitz material, R2/R3 transcripts, and practical secret-generation step unresolved.
