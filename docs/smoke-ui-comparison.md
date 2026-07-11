# Our Results vs. smoke-ui's OCTRA HFHE v2 Assessment

This report compares:

- **Our repository:** [`asbryx/octra-hfhe-v2-cryptanalysis`](https://github.com/asbryx/octra-hfhe-v2-cryptanalysis)
- **Kubo/smoke-ui:** [`smoke-ui/octra-hfhe-v2-security-assessment`](https://github.com/smoke-ui/octra-hfhe-v2-security-assessment)
- **smoke-ui commit reviewed:** `827da3847f3044d255d45ddff994ed0ba9fe65de`
- **smoke-ui challenge pin:** `0d08e9622921e5930175a660df0061a65548972f`
- **Our challenge pin:** `019380c97543620091409b0fbf73a8a773a9a0da`
- **Shared PVAC source:** `071b0e909c119de815e284b347c4bd979cb59ef3`

## Executive conclusion

The two assessments are mostly complementary and reach the same practical conclusion: **neither recovered the plaintext, wallet key, HFHE secret, or a practical public-only recovery procedure.**

The apparent disagreements come primarily from different evidence snapshots and experimental scopes, not from incompatible mathematics:

1. smoke-ui assessed challenge commit `0d08e96`, before OCTRA published the R1 LPN corpus.
2. Our assessment continued through `d9d29d5` and `019380c`, where 44 target-associated R1 files became public.
3. smoke-ui emphasizes broad implementation engineering; our later work emphasizes chronology, exact active R1 algebra, fixed-sample decoding, and the dependency bridge from R1 data to full decryption.
4. Some smoke-ui compiler observations use deterministic seeded fixtures, while the active bounty producer uses nondeterministic `keygen()` and `enc_text()`.

The unchanged target bytes are important: `pk.bin` and `secret.ct` remain identical across these documentation/data updates. The public evidence changed; the encrypted target did not.

## Side-by-side result matrix

| Area | smoke-ui result | Our result | Why they differ |
|---|---|---|---|
| Final recovery | No plaintext or wallet key | No plaintext or wallet key | Agreement |
| Assessed challenge snapshot | `0d08e96` | `019380c` | OCTRA published LPN data after smoke-ui's snapshot |
| Target bytes | Active `pk.bin` and `secret.ct` | Same active bytes and hashes | Agreement |
| v1 `R_com` oracle | Closed on v2 wire | Closed on v2 wire | Agreement |
| Wrapped algebra | Independent masks leave candidates satisfiable | Same blocker; 44 unknown BASE-layer factors remain | Agreement |
| Public LPN instance | No explicit `(A,y)` in the pinned package | 44 R1 files, 720,896 equations | Upstream evidence changed in `d9d29d5`/`019380c` |
| LPN matrix rank | Reduced/dummy-key structural testing | Exact public R1 rank 4,096 from the first file | Real rows became available later |
| Low-weight dependencies | Not available on public rows | No exact weight-2 or weight-3 dependency in the first file | New corpus enabled an exact test |
| LPN feasibility | Generic attacks inapplicable without samples | Samples are sufficient for verification but fixed-sample decoding remains impractical | Availability changed; computational barrier remains |
| PRF-key dimension | Nominal 256-bit secret | All 256 input bits affect the derived key and first block | Agreement, with an added executable diffusion check |
| PC/R relation | No practical plaintext predicate | A nontrivial bounded-range relation exists, but evaluation costs about `2^63.5` group operations after a full PRF-key guess | Our later audit separates information content from runnable verification |
| Plaintext length | 301–315-byte metadata leakage | 301–315 under producer provenance, not a parser-only invariant | Difference in claim scope, not observed object count |
| Toeplitz first-use race | Confirmed C++ data race | Confirmed runtime defect; no target-production consequence established | Agreement on defect, narrower target-impact claim |
| Compiler differential | Seeded serialization differs across compiler families; two Clang variants were not repeatable | Cross-compiler ordering has a source-level explanation; same-binary non-repeatability remains unresolved | Different claims must not be conflated |
| Parser/canonicalization | Several hardening findings | Accepted as engineering findings; no fixed-target opening follows | Agreement |
| Statistical searches | No held-out predictor in tested feature families | Same; closures are stated probe-by-probe rather than universally | Difference in reporting precision |
| Historical entropy/reuse | No weak RNG or cross-generation reuse | Same after additional source/history checks | Agreement |

## Why the LPN conclusions changed

### What smoke-ui correctly concluded at `0d08e96`

At the announcement snapshot, the static challenge package did not expose conventional LPN samples. The implementation generated rows internally from a SHA-derived AES stream keyed by the secret PRF key, computed noisy labels, compressed them through keyed Toeplitz extraction, and retained no public `(A,y)` transcript.

Therefore smoke-ui's statement that ordinary BKW, LF/FWHT, covering-code, or ISD tooling had no public instance to consume was correct for its pinned commit.

### What OCTRA published later

Commit `d9d29d505e2840c0028d7a91a2a8ba59e163b9a4` added 44 JSONL files, and `019380c97543620091409b0fbf73a8a773a9a0da` clarified their role. The corpus contains:

```text
44 files
16,384 equations per file
720,896 equations total
n = 4,096
tau = 1/8
domain = pvac.prf.r.1
```

Our streaming audit found:

```text
44/44 upstream hashes valid
720,896 unique rows
one-file GF(2) rank = 4,096
rank [A|y] = 4,097
exact weight-2 dependencies = 0
exact weight-3 dependencies = 0
```

That invalidates only the time-dependent statement that no public samples exist. It does not invalidate smoke-ui's wider conclusion that no practical plaintext recovery was demonstrated.

### Why the new corpus still does not complete decryption

The masking factor is:

```text
R = core_R1(PRF key, S) * core_R2(PRF key, S) * core_R3(PRF key, S)
```

The new files cover R1 only. They make candidate checking much stronger:

```text
published A_R1 -> exact verifier for a candidate PRF key
published y_R1 -> statistical verifier for a candidate LPN secret S
```

They do not publish:

- the 256-bit PRF key;
- keyed Toeplitz top material;
- R2 or R3 labels;
- PC blinding scalars;
- a practical method to generate the correct candidate.

Recovering `S` alone therefore does not compute full `R`. Recovering a PRF-key candidate alone permits R1 reconstruction but still requires `S` for R2/R3 labels.

## Why the concrete complexity remains high

The corpus is information-rich: approximately 8,974 samples are sufficient at the binary symmetric channel capacity bound, and 720,896 are public. That is an information statement, not an efficient decoding algorithm.

Our fixed-sample models and bounded experiments produced:

| Method | Result |
|---|---:|
| Prange, fixed-weight | about `2^791.48` trials |
| Stern, about 64 MiB extra memory | about `2^785.74` list work |
| Stern, about 42.5 GiB extra memory | about `2^783.87` list work |
| Restricted BKW level 3 | optimistic information near the 4,051-dimensional residual, with correlated rows |
| Restricted BKW level 4 | about 43 optimistic information bits for 4,036 residual dimensions |
| Information-set ladder through `n=60` | matches clean-subset/full-rank theory; no promoted anomaly |

The later evidence changes the problem from “no public instance” to “public instance with no known practical fixed-sample decoder.”

## Compiler differential: what happened and why

smoke-ui's deterministic fixture uses:

```text
keygen_from_seed(...)
enc_value_seeded(...)
enc_value_depth_seeded(...)
enc_values_seeded(...)
ct_mul_seeded(...)
```

This is appropriate for reproducibility testing, but it is not the active producer path, which uses random `keygen()` followed by `enc_text()`.

### Cross-compiler byte differences

The pinned seeded wrappers pass two calls that both mutate the same `SeedableRng&` as arguments to one `combine_ciphers(...)` expression:

```cpp
return combine_ciphers(pk,
    enc_fp_depth_seeded(..., rng),
    enc_fp_depth_seeded(..., rng));
```

C++ does not specify which function argument is evaluated first. GCC and Clang may therefore assign successive RNG regions to opposite wrapper layers. Both results can remain valid and decrypt to the same value while producing different canonical bytes.

The non-seeded wrappers have the analogous ordering issue with two randomness-consuming calls. For the active challenge, however, bytes were generated once and published; cross-compiler reproducibility does not retroactively expose their hidden values.

### Same-binary non-repeatability

smoke-ui also reports that `clang-O2-aes` and `clang-O2-lto-aes` were not repeatable across two executions of the same binary. Unspecified argument evaluation order alone does **not** explain run-to-run variation within one compiled binary; it normally selects a compiler-dependent order that remains stable for that executable.

That observation should therefore remain classified as unresolved fixture-level nondeterminism or state dependence until independently minimized. It is evidence against strict deterministic-byte assumptions, but not evidence of plaintext leakage or an active-target recovery relation.

### Why our O0/O3 result does not contradict smoke-ui

Our narrower RR/FV probes compared selected official seeded outputs and serialized bytes under controlled compiler settings and obtained equality for those fixtures. smoke-ui exercised a broader GCC/Clang/LTO matrix and a different multi-operation fixture.

The proper combined conclusion is:

- tested O0/O3 fixtures can be byte-identical;
- the seeded wrapper API is not guaranteed cross-compiler byte-stable because of shared-state argument evaluation;
- smoke-ui observed additional same-binary nondeterminism that remains unexplained;
- none of these observations reveals the fixed target's secret randomness.

## Toeplitz race: real defect, limited target relevance

smoke-ui's ThreadSanitizer finding is source-grounded:

```text
g_toep = nullptr
if (!g_toep) select_toeplitz()
select_toeplitz() writes g_toep
concurrent toep_127() reads and calls g_toep
```

The global function pointer and implementation ID are published without synchronization. Concurrent first use is undefined behavior under the C++ memory model. `std::call_once`, a function-local static, or ordered atomics would fix it.

Why this does not currently open the challenge:

1. The ordinary stress run did not observe incorrect output.
2. The target is a fixed static artifact; it cannot trigger producer-side initialization after publication.
3. No evidence shows the bounty producer called first-use Toeplitz concurrently.
4. Even a historical wrong implementation choice would need a target-bound relation or reproducible wrong output before it helps recover plaintext.

The finding remains a valid implementation defect and remediation item, but not a demonstrated confidentiality break for `secret.ct`.

## PC/R interpretation

smoke-ui correctly found no cheap public plaintext predicate. Our later algebra identifies a relation without changing that practical conclusion.

For a full candidate PRF key `k`, remove the candidate blinding term from a public PC point:

```text
Q_i(k) = PC_i - rho_i(k) H
```

For the correct key, `Q_i(k)` should be a centered 127-bit multiple of `G`. A wrong key passes with very small probability, but evaluating membership requires a generic bounded discrete-log search of about `2^63.5` group operations.

If that opening were obtained, public R1 data determines only:

```text
core_R2 * core_R3
```

not the two factors separately. This is mathematically nontrivial but operationally weaker than checking the same candidate key against one published 4,096-bit R1 row.

Thus:

- smoke-ui is correct that no practical public predicate was available;
- our report refines “no relation” into “a relation exists, but its evaluation is impractical and does not split R2/R3.”

## Length claim: metadata vs. provenance

Both repositories observe 22 ciphertext objects: one encrypted length plus 21 packed text blocks of up to 15 bytes.

If the active artifact was produced by the pinned `enc_text()` path, the plaintext length is 301–315 bytes. The wire parser alone does not prove that producer provenance; it proves object count and shape. We therefore state the length interval as a producer-bound inference rather than a parser-only invariant.

This is a difference in epistemic scope, not a disagreement over bytes.

## Statistical and higher-order experiments

smoke-ui ran a wider engineering/statistical program:

- tensor and hypergraph sketches;
- subgroup and character projections;
- automated public-invariant synthesis;
- timing, fuzzing, sanitizers, and mutation testing;
- wallet derivation benchmarking.

Those experiments add valuable negative evidence. Their correct interpretation is bounded:

- no tested held-out feature predicted plaintext;
- no tested subgroup projection removed mask entropy;
- no tested invariant survived the stated statistical gates;
- sanitizer coverage applies only to executed paths;
- negative classifiers do not prove every possible invariant absent.

Our repository adopts the same caution and narrows closure wording to the specific feature family, fixture, and commit tested.

## Findings unique to each repository

### smoke-ui contributes more evidence on

- independent Rust wire parsing;
- malformed-input and canonicalization behavior;
- sanitizer and fuzzing coverage;
- entropy fault handling;
- runtime timing and concurrency;
- broad tensor/subgroup/invariant searches;
- disclosure and remediation guidance.

### Our repository contributes more evidence on

- the four-stage challenge chronology;
- current HEAD `019380c` rather than announcement snapshot `0d08e96`;
- complete streaming validation of all 44 LPN files;
- exact active R1 rank and low-weight dependency checks;
- common-secret parity-check limitations;
- effective 256-bit PRF-key input diffusion and stream geometry;
- fixed-sample decoding estimates and toy scaling gates;
- exact dependency boundaries among `S`, PRF key, Toeplitz, R1/R2/R3, PC, and plaintext;
- a portable finite-family check: 99 candidates, three derivation routes, four layouts, 1,188 misses.

## Combined verdict

The strongest defensible combined statement is:

```text
v2 removes the v1 offline plaintext-guess oracle.
The fixed target is canonical and uses 44 independently seeded BASE layers.
No weak RNG, nonce reuse, subgroup shortcut, parser discrepancy, or public plaintext predicate opens it.
The later R1 corpus supplies a real LPN instance and strong candidate verifiers.
That corpus still does not provide a practical decoder, the PRF key, keyed Toeplitz material, or R2/R3 labels.
No public-only plaintext recovery is currently demonstrated.
```

The smoke-ui assessment was not “wrong” about the package it pinned. Its LPN-availability statement became outdated because OCTRA later published new target-associated data. Our work updates that changed threat model and narrows several interpretations; smoke-ui remains the stronger broad implementation assessment.

## What would change this conclusion

Either repository should be revisited if any of the following appears:

1. R2/R3 samples or keyed Toeplitz material.
2. A reduced, evidence-derived PRF-key candidate family.
3. Target-bound reuse of the PRF key, LPN secret, mask, or PC blinding.
4. A practical PC opening or candidate-`R` predicate.
5. A minimized explanation connecting compiler nondeterminism to secret-dependent public output.
6. Evidence that the target producer used a path different from pinned `keygen()` plus `enc_text()`.
7. A concrete fixed-sample decoding algorithm materially below the measured boundaries.
8. Partial plaintext independently verified against the active target.
