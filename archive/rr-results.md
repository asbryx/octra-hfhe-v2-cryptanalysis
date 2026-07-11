> **Historical snapshot.** This file preserves an earlier experiment record. Some commit labels, checkout hashes, local paths, and broad verdict wording were later corrected or narrowed. Use `../STATUS.md` and `../research/final-exhaustion.md` as authoritative.

# Executor Rerun Results After RP — RR-01..RR-04

**Date:** 2026-07-11
**Prompt:** `../EXECUTOR_RERUN_PROMPT_AFTER_RP.md`
**Prior report under correction:** `EXECUTOR_RESULTS_AFTER_QP.md` SHA `e6367b8b…c5f4`
**Role:** execution only; no plan; no edits to STATUS/RESULTS/audit-log/NEXT_*/EXECUTOR_RESULTS_*

## Target lock

| Item | Expected | Observed |
|------|----------|----------|
| challenge HEAD | `0d08e9622921e5930175a660df0061a65548972f` | match |
| pvac HEAD | `071b0e909c119de815e284b347c4bd979cb59ef3` | match |
| secret.ct | `5da7f827…fbab` | match |
| pk.bin | `1e788edf…9410` | match |

## Summary

| ID | Verdict | One-line |
|----|---------|----------|
| RR-01 | **CLOSED** | Official labeled synth_seeded path; public baselines ≈ random control; candidate space large |
| RR-02 | **SKIPPED** | Gate RR-01 CLOSED |
| RR-03 | **CLOSED** | O0 vs O3 full seeded digests + decrypt byte-identical (20 cases) |
| RR-04 | **CLOSED** | Official AES `top` path: 4224/4224 formula rank match (dummy keys × active seeds) |

Challenge remains **NOT SOLVED**.

---

## RR-01 — Official-pipeline group retention

### Exact input / commits
- PVAC pin `071b0e9…`
- Active-like Params: B=337, m=8192, n=16384, lpn_n=4096, lpn_t=16384, noise_entropy=128, slope=16, t2=0.55
- `keygen_from_seed` wallet fixture `0xA0..0xBF`
- 120 trials: depths 2..22 emphasis; values 0,1,42,337,2^64-1, deterministic mixes
- Single-layer labeled `synth_seeded` path (wrap uses same edge construction per BASE layer)

### Source functions actually called
`keygen_from_seed`, `entropy::Budget::compute`, `delta::Set::make`, `prf_R_slots`, `compute_layer_PC`, `idx::Selector`, `graph::SigEdge`, `graph::N2Edge`, `graph::N3Edge`, `graph::Emitter`, `graph::realize` (via em+field ops), merge keyed as `reduction::merge` (instrumented origins), `SeedableRng` Fisher–Yates permute (same as `reduction::permute`), `enc_seed_scope` / `make_seeded_rng`.

Labels attached only in temporary driver (`Kind`, `group_id`, `member_id`); **not** on public `Edge`.

### Build command
```text
clang++ -std=c++17 -O2 -maes -msse2 -mpclmul -rtlib=compiler-rt \
  -I upstream/pvac_hfhe_cpp/include \
  archive/legacy-probes/rr-01/rr01_group_retention.cpp \
  -o archive/legacy-probes/rr-01/rr01.exe
```

### Raw summary (`rr01.out`)
```text
trials=120
mean_opp_prec_N2=0.02115967  mean_opp_rec_N2=1.000000
mean_sigma_prec_N2=0.01208333 mean_sigma_rec_N2=0.004448
mean_random_pair_hit=0.02045833
mean_cand_pairs=462.19
baseline_vs_control_gap_opp=0.00070134
frac_N2_all_members_unmerged=0.889267 (1044/1174)
frac_N3_all_members_unmerged=0.827419 (513/620)
frac_merged_edges_multi_origin=0.028480 (143/5021)
public_wire_contains_labels=0
exact_partition_rate=0
```

**Interpretation (not circular):**
- Opposite-sign baseline has **recall 1.0** among pure N2 groups (true pairs are always opposite-sign) but **precision ≈ 2.1%**, matching **random pair hit ≈ 2.0%** (gap 7e-4).
- Therefore it does **not** rank true groups above control; it enumerates ~all opposite-sign pairs (~462/layer mean).
- Sigma baseline worse (prec≈1.2%, rec≈0.4%).
- Physical survivability: ~89% N2 / ~83% N3 groups keep all members unmerged; **public recognizability still fails**.
- `Edge` type has no label fields → serialize/deserialize cannot carry labels.

### Active-bound candidate space (public only, 44 layers)
From `secret.ct` via official-shape parse:
```text
opposite_sign_pairs: min=98 max=928 mean≈460 total=20246
distinct_idx_edge_triples: min=1330 max=35990 mean≈13858 total=609751
```
Artifact: `probes/rr-01/rr01_active_candidates.json`
SHA-256: `9511e13c3fce23c4952059956690be4c08fc63ebe73975583e9629dac6f5294f`

### Independent check
- Smoke compile of full active keygen+enc: `compile_smoke.exe` → enc depth2 edges=48, decrypt 42 OK.
- Merge key and permute match `encrypt.hpp` source (read + parallel instrumented merge).

### Applicability to fixed active artifact
Active wire has same public fields only; candidate pair/triple spaces are large (above). No public invariant isolates true N2/N3 groups.

### Verdict: **CLOSED**
All close conditions met: official path used; baselines ≤ random control; candidate spaces large; no exact public group ID.

### Artifacts
| Path | SHA-256 |
|------|---------|
| `probes/rr-01/rr01_group_retention.cpp` | (source) |
| `probes/rr-01/rr01.out` | `a0f0…` recompute below |
| `probes/rr-01/rr01_active_candidates.json` | `9511e13c3fce23c4952059956690be4c08fc63ebe73975583e9629dac6f5294f` |

### Next dependency
RR-02 skipped.

---

## RR-02 — Conditional ratio validation

**Verdict: SKIPPED**
Artifact: `probes/rr-02/rr02_skipped.json`

---

## RR-03 — Full deterministic seeded-build differential

### Exact input
- Same active Params as RR-01
- `keygen_from_seed` wallet `0x10..0x2F`
- enc seed `0x55^i`
- values: `0, 1, 337, 2^64-1, (1<<63)|0x1234`
- depths: `0, 2, 10, 22`
- API: `enc_value_depth_seeded` + `dec_value` + `prf_R_core` for R1/R2/R3/noise domains

### Source functions
`keygen_from_seed`, `enc_value_depth_seeded` → `core::synth_seeded`, `dec_value`, `prf_R_core` (Dom PRF_R* and PRF_NOISE*), field ops for signed numerators.

### Build commands
```text
clang++ -std=c++17 -O0 -maes -msse2 -rtlib=compiler-rt -I... rr03_seeded_diff.cpp -o rr03_O0.exe
clang++ -std=c++17 -O3 -maes -msse2 -mpclmul -rtlib=compiler-rt -I... rr03_seeded_diff.cpp -o rr03_O3.exe
```

### Raw
```text
O0 vs O3: 123/123 comparable lines equal; full stdout byte-identical
mismatches=0
Digests compared per case: ct_digest, R_cores_digest, numerators_digest, dec_lo/hi, edges/layers
Also sk_fixture + pk_H_digest + canon_tag identical across builds
```

Sample (identical both builds):
```text
sk_fixture 2a72b1fe25dca7d93490996e619e10eae648a8a283c02d2fc39c22c02d98fd3a
CASE val=0 depth=0 → dec_lo=0 edges=44 layers=2
CASE val=0 depth=2 → dec_lo=0 edges=47 layers=2
... (20 value×depth cases all decrypt match)
```

### Independent check
Re-run both exes; `python` zip-compare digests.

### Applicability
Producer single-build; no dual-build semantic fork. Seeded path deterministic across O0/O3 + scalar vs PCLMUL selection.

### Verdict: **CLOSED**

### Artifacts
- `probes/rr-03/rr03_seeded_diff.cpp`
- `probes/rr-03/rr03_O0.out` / `rr03_O3.out` (byte-identical)
- `probes/rr-03/rr03_compare.txt`

---

## RR-04 — Exact-source Toeplitz rank confirmation

### Exact input
- Official `derive_aes_key` + `AesCtr256` + `Dom::TOEP` + `fnv1a_domain(dom)`
- 44 active public seeds from `probes/seeds_active.txt`
- 6 domains: R1/R2/R3 + NOISE1/2/3
- 16 deterministic dummy `prf_k` fixtures
- **Not** the unknown active secret key

### Build
```text
clang++ -std=c++17 -O2 -maes -msse2 -mpclmul -rtlib=compiler-rt -I... rr04_toep_rank_exact.cpp -o rr04.exe
```

### Raw
```text
seeds_loaded=44
samples=4224 formula_match=4224 match_rate=1.000000
NOTE=active_seeds_plus_dummy_keys_not_exact_active_secret
rank_hist: 116:1 … 127:2145
val_hist_head: 0:2145 1:1011 2:520 … (geometric)
verdict=FORMULA_CONFIRMED
```

### Independent check
Formula `rank = 0 if top==0 else 127-val(top)` vs Gaussian on map rows; 100% match.

### Applicability
Confirms implementation map rank for AES-generated tops under **dummy** keys + **active public seeds**. Does **not** claim exact active-key rank distribution.

### Verdict: **CLOSED**

---

## File hashes

| File | SHA-256 |
|------|---------|
| `probes/rr-01/rr01.out` | `73bc5039d6562c779cf60a055a86bdce3356c8529b1ab8160190285ce7304bb2` |
| `probes/rr-01/rr01_active_candidates.json` | `9511e13c3fce23c4952059956690be4c08fc63ebe73975583e9629dac6f5294f` |
| `probes/rr-02/rr02_skipped.json` | `81b4a952a3d969fe97691614bdbede72f07b49ead7cb4cb5b59dfb9764cc857c` |
| `probes/rr-03/rr03_O0.out` | `94bdabfeb1f339991a2c40f8b423feeb62b768cc2cb9376eb9009fb77e37d42e` |
| `probes/rr-03/rr03_O3.out` | `94bdabfeb1f339991a2c40f8b423feeb62b768cc2cb9376eb9009fb77e37d42e` (identical) |
| `probes/rr-04/rr04.out` | `41265e59c72fc6b30bb04c98720f75f6b391c9756cd25776098c1cdd667e2260` |

## Bottom line

1. **RP-01 correction:** Official C++ path confirms prior qualitative close, but now with real scored baselines: opposite-sign precision equals random control (~2%), candidate pairs hundreds per layer; active total opposite-sign pairs **20246**.
2. **RP-06 correction:** Full seeded encrypt intermediates + decrypt match O0 vs O3 exactly.
3. **RP-04 narrow confirm:** AES-sourced tops obey rank formula on 4224 samples (dummy keys × active seeds).

Still **NOT SOLVED**. Blocker unchanged: keyed `R` / `prf_k` + LPN secret; no public group-ratio handle.

Skipped: SAT/GPU, mnemonic search, full QP/RP re-runs, permanent pvac tree edits.
