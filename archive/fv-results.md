> **Historical snapshot.** This file preserves an earlier experiment record. Some commit labels, checkout hashes, local paths, and broad verdict wording were later corrected or narrowed. Use `../STATUS.md` and `../research/final-exhaustion.md` as authoritative.

# Executor Results After FV — FV-01..FV-03

**Date:** 2026-07-11
**Plan:** `../NEXT_VALIDATION_PLAN_AFTER_RR.md`
**RR baseline accepted:** report SHA `7911839227c0b4c7e513d1865c595ce51d84f56dca8c1e712cbb60d81c9df648`
**Role:** execution only; no new plan; no edits to STATUS/RESULTS/audit-log/NEXT_*/prior EXECUTOR_*

## Target lock

| Item | Expected | Observed |
|------|----------|----------|
| challenge HEAD | `0d08e962…` | match |
| pvac HEAD | `071b0e9…` | match |
| secret.ct / pk.bin | STATUS hashes | match |

## Summary

| ID | Verdict | One-line |
|----|---------|----------|
| FV-01 | **CLOSED** | Full sigma/weight/joint N2+N3 ranking ≈ random controls (200 trials) |
| FV-02 | **CLOSED** | O0 vs O3 full-byte digests identical (serializer + sigma words + deltas + PC + decrypt) |
| FV-03 | **SKIPPED** | Gate FV-01 CLOSED |

**NOT SOLVED.**

---

## FV-01 — Complete public-field ranking

### Exact target / source
- PVAC `071b0e9…`, active Params (B=337, m=8192, lpn 4096/16384, noise=128)
- Official: `keygen_from_seed`, `Budget`, `SigEdge`/`N2Edge`/`N3Edge`, labeled merge+permute (same as RR-01 path)
- 200 trials, depths 2..22, values 0/1/337/2^64-1/mixes
- Labels **excluded** from features (`labels_excluded_from_features=1`)

### Build
```text
clang++ -std=c++17 -O2 -maes -msse2 -mpclmul -rtlib=compiler-rt \
  -I upstream/pvac_hfhe_cpp/include \
  probes/fv-01/fv01_group_ranking.cpp -o probes/fv-01/fv01.exe
```

### Features used (public only)
- **Sigma:** full `BitVec.w` → xor_popcount, normalized Hamming, equality
- **Weight:** signed `term = sign * w[0] * powg[idx]`; magnitude-proxy heuristics (not claimed invariant)
- **Joint:** sigma + 0.01×weight
- **N2 cand:** opposite sign, distinct idx
- **N3 cand:** three distinct indices, all signs
- **Controls:** random scores, index/sign-only, permuted labels

### Proof labels not in inputs
Scorers take only public `Edge` fields + `powg_B`. Origins used only after ranking to mark `is_true` for metrics.

### Raw metrics (`fv01.out`)
```text
harness_perfect_feature_ok=1
trials=200 mean_pairs≈463.5 mean_triples≈13857

N2_joint   mean_true_rank≈260.2 mean_true_pct≈0.515  @1=0.35% @5=1.5% @10=2.3%
N2_random  mean_true_rank≈270.7 mean_true_pct≈0.499  @1=0.41% @5=1.5% @10=3.3%
N2_sigma / N2_weight / N2_idx_sign ≈ same band (~0.50–0.51 pct)

N3_joint   mean_true_pct≈0.4915
N3_random  mean_true_pct≈0.4917
N3 recall@1 = 0

effect_N2_joint_minus_random_pct=0.016140
effect_N3_joint_minus_random_pct=-0.000197
exact_partition_rate=0

wrapped_smoke_n=20 mean_edges≈83.8 mean_opp_sign_pair_ub≈927.5
verdict=CLOSED
```

### Control comparison
Joint N2 effect vs random **+1.6pp** percentile (below 2pp material threshold in driver; still ~random rank ~median). N3 effect **~0**. Permuted-label joint mean true rank ~73 on first sample (not top-heavy). Perfect-feature harness ranks true groups correctly (harness OK).

### Independent check
1. Synthetic perfect scores → harness OK
2. Random / idx controls co-reported
3. Wrapped official `enc_value_depth_seeded` smoke for edge/pair scale

### Applicability to active artifact
Active mean opposite-sign pairs ~460 (RR-01) matches trial mean_pairs ~463. Candidate spaces remain large; no scorer concentrates true groups at top.

### Verdict: **CLOSED**

### Artifacts
| Path | SHA-256 |
|------|---------|
| `probes/fv-01/fv01.out` | `see hashes section` |
| `probes/fv-01/fv01_group_ranking.cpp` | source |

---

## FV-02 — Canonical full-byte build comparison

### Exact target / source
- Same active Params + `keygen_from_seed` fixture
- `enc_value_depth_seeded`, `dec_value`, `prf_R_core`, **`prf_noise_delta(pk,sk,seed,gid,kind)`**
- Serializer: `hfhe-challenge@0d08e96/source\pvac_artifact_serialize.hpp` → `serialize_cipher`
- Full sigma: every `s.nbits`, `s.w.size()`, each `s.w[i]`
- Matrix: values {0,1,337,2^64-1, det 127-bit}; depths {0,2,10,22}; **3** encryption seeds → 60 cases

### Build
```text
clang++ -O0 -maes -msse2 -rtlib=compiler-rt -I$PV/include fv02_full_bytes.cpp -o fv02_O0.exe
clang++ -O3 -maes -msse2 -mpclmul -rtlib=compiler-rt -I$PV/include fv02_full_bytes.cpp -o fv02_O3.exe
```

### Raw
```text
serializer_self_check=1
O0 vs O3 stdout: byte_equal True (31392 bytes)
Per case digests present:
  serialized_ct_sha256
  full_sigma_sha256
  R_and_delta_sha256   # R1/R2/R3/R + seed fields + R_com + prf_noise_delta all N2/N3 gids
  layer_numerator_sha256
  PC_sha256
  dec_lo/hi
sk_fixture / pk_H_digest identical across builds
```

### Independent check
- Serialize→deserialize→serialize self-check decrypts 7
- Fixture key digests printed before cases
- Full file equality O0/O3

### Applicability
No semantic dual-build divergence on full public CT bytes and exact noise-delta list.

### Verdict: **CLOSED**

### Artifacts
| Path | SHA-256 |
|------|---------|
| `probes/fv-02/fv02_O0.out` | identical to O3 |
| `probes/fv-02/fv02_O3.out` | identical |
| `probes/fv-02/fv02_full_bytes.cpp` | source |

---

## FV-03 — Active ranking

**Verdict: SKIPPED**
`probes/fv-03/fv-03-skipped.json` — FV-01 did not beat controls.

---

## File hashes

| File | SHA-256 |
|------|---------|
| `probes/fv-01/fv01.out` | `f6dcc4328a63ae3d477f650d86e74c0d432730b68d2ec9d76b3c26ad2fb9a419` |
| `probes/fv-02/fv02_O0.out` | `0a86143c0b06630a52192ecf33c8d6a8e8c66666b54ab6236b0e1a6036173762` |
| `probes/fv-02/fv02_O3.out` | `0a86143c0b06630a52192ecf33c8d6a8e8c66666b54ab6236b0e1a6036173762` (identical) |
| `probes/fv-03/fv-03-skipped.json` | `011a94696700d22602b8affa07dcadc7ef8ebbe897ed294a19c948a48efa61df` |

## Bottom line

1. **FV-01 closes the RR-01 gap:** real N2/N3 ranking with full sigma + weight + joint + controls; true groups sit at **~median** percentile, not top-k.
2. **FV-02 closes the RR-03 gap:** full sigma words, official `serialize_cipher` bytes, exact `prf_noise_delta` per group, PC, numerators, decrypt — **O0≡O3**.
3. Still **NOT SOLVED**; no public group recovery handle; blocker remains keyed `R`.

Skipped: Toeplitz/H re-runs, FV-03, ML, mnemonic search.
