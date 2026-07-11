> **Historical snapshot.** This file preserves an earlier experiment record. Some commit labels, checkout hashes, local paths, and broad verdict wording were later corrected or narrowed. Use `../STATUS.md` and `../research/final-exhaustion.md` as authoritative.

# Executor Results After QP — RP-01..RP-07

**Date:** 2026-07-11
**Plan:** `../NEXT_RESEARCH_PLAN_AFTER_QP.md`
**Role:** execution only (no edits to STATUS/RESULTS/audit-log/plan)
**Challenge status:** still **NOT SOLVED**

## Target lock

| Item | Expected | Observed |
|------|----------|----------|
| challenge | `0d08e9622921e5930175a660df0061a65548972f` | match |
| pvac | `071b0e909c119de815e284b347c4bd979cb59ef3` | match |
| secret.ct | `5da7f827…fbab` | match |
| pk.bin | `1e788edf…9410` | match |

## Summary

| ID | Verdict | One-line |
|----|---------|----------|
| RP-01 | **CLOSED** | Individual N2/N3 groups not recoverable from public wire after merge+CSPRNG shuffle |
| RP-02 | **SKIPPED** | Gate: RP-01 closed |
| RP-03 | **SKIPPED** | Gate: no public ratios |
| RP-04 | **CLOSED** | Toeplitz 127×127 rank = 127−val(top); random-top mean≈126; no public core constraint |
| RP-05 | **SKIPPED** | Gate: no candidate R/ratio family |
| RP-06 | **CLOSED** | O0 vs O3 toep functional outputs identical; PRF trunc still YES |
| RP-07 | **CLOSED** | No public anchor change since QP-07 baseline |

---

## RP-01 — Group retention after merge/shuffle

**Exact input:** model of `encrypt.hpp` N2/N3 + `reduction::merge` + `permute`; B=337; Budget from source (`c2=2 log2 B`, `c3=3 log2 B`); 41 trials depths 0–20 + depth=2×20.

**Smallest probe:** `../tools/rp-01\rp01_group_retention.py`

**Raw (aggregate):**
```text
mean_merge_collision_rate ≈ 0.022
mean_n2_pure_key_rate ≈ 0.92   (keys not collided — NOT public recovery)
mean_n3_pure_key_rate ≈ 0.84
exact_group_recovery_rate_public_only = 0.0
precision_N2_public = 0.0
precision_N3_public = 0.0
serialized_order_information = 0.0
mean_opposite_sign_pair_candidates ≈ 305
active_like_depth2_budget: n2=5 n3=2
```

**Independent check:** source read
- merge key = `(layer_id, idx, sign)` weight-add + sigma XOR
- permute = Fisher–Yates with `csprng_u64` / `SeedableRng`
- N2 has `sb = sa ^ 1` (necessary, not sufficient for pairing without R)

**Applicability:** active wire exposes only layer/idx/sign/weight/sigma/order — same transforms. CF-T3 already closed perfect signal/noise; RP-01 closes **individual** noise-group recovery.

**Verdict: CLOSED**
**Artifact:** `probes/rp-01/rp01_group_retention.json`
SHA-256: `4ce38932f22cf4fa7603ff6b4ba2de415cc55018f06a10e6c3d2ca60d168e444`
**Next:** skip RP-02/03/05.

---

## RP-02 — Group sums / ratios

**Verdict: SKIPPED** (RP-01 closed)
**Artifact:** `probes/rp-02/rp-02_skip.json`

Without public partition of individual groups, `S_g = R * delta_g` and `Q_ab = S_a/S_b` are not computable from the wire. Random partitions of same sizes already known (CF-T3) not to beat residual R.

---

## RP-03 — Toy partial-state verifier from ratios

**Verdict: SKIPPED** (depends on RP-02)

---

## RP-04 — Toeplitz 127×127 map rank/entropy

**Exact input:** GF(2) low-convolution map `out[j]=Σ_{i≤j} y[i] top[j-i]`; 2000 random tops; 50 differential basis checks.

**Probe:** `probes/rp-04/rp04_toep_map_rank.py`

**Raw:**
```text
formula: rank = 0 if top==0 else 127 - valuation(top)
formula_vs_gaussian_match = 1.0
differential_basis_match_rate = 1.0
mean_rank ≈ 126.07
full_rank_rate ≈ 0.51
min_rank observed = 119 (rare high valuation)
```

**Independent check:** histogram of first-set-bit matches geometric 2^{-k}; E[rank]≈126.

**Applicability:** tops are AES-keyed (unknown). Degeneracy is not a stable secret-free kernel. Three-core product R1·R2·R3 has no public core outputs → no enforceable linear constraint on y.

**Verdict: CLOSED** (implementation property / random-top expectation only)
**Artifact:** `probes/rp-04/rp04_toep_map_rank.json`
SHA-256: `a08fa9a149ea69ee5d4346df9f2f509852885c1ddc2ba23dfae45d85403c4bde`

---

## RP-05 — Known-length anchor

**Verdict: SKIPPED** (no candidate family from RP-02/03)

15 lengths 301–315 remain indistinguishable without independent R0/R1 + wrap mask + rho.

---

## RP-06 — Differential seeded build

**Probe:** recompile `qp02_toep_window.cpp` with clang `-O0` and `-O3 -mpclmul`; rerun `qp02_prf_trunc.exe`.

**Raw:**
```text
O0 and O3 functional lines identical:
  effective_top/y_bits=127
  full_vs_truncated=256/256
  negctrl bit127 changes=0; bit0=256/256
O0 scalar_vs_pclmul=0/0  (no -mpclmul on O0 compile)
O3 scalar_vs_pclmul=256/256
PRF trunc: full_prf_core_eq_truncated_127 = YES (96/96)
SeedableRng API header present for encrypt seeded path; full dual encrypt not required after toep identity.
```

**Verdict: CLOSED**
**Artifact:** `probes/rp-06/rp06_seeded_diff.json`
SHA-256: `0be414aee2a96896d1d54e86056f199f96f502e8245aec21c27f3a867bb96537`

---

## RP-07 — Public delta (anchors only)

**Anchors vs live:**
```text
challenge HEAD 0d08e962…  same
challenge forks 26        same
challenge PRs 4           same (QP-07 baseline)
PVAC HEAD 071b0e9…        same
PVAC open PRs [499,500]   same
PVAC issues #501–503      present
Kubo watcher search hits  []
```

**Verdict: CLOSED** (no full rescan)
**Artifact:** `probes/rp-07/rp07_anchor.json`

---

## Decision tree result

```text
Noise groups recoverable from wire?     NO  → closed RP-01/02/03/05
Toeplitz map stable material degeneracy? NO (random-top only) → closed RP-04
Seeded builds semantic diverge?          NO → closed RP-06
Public delta?                            NO → closed RP-07
```

## Bottom line

Still **NOT SOLVED**. Blocker unchanged:

```text
v = N0/R0 + N1/R1 mod p
R = core_R1 * core_R2 * core_R3
PC = [center(R^-1)]G + [rho]H
```

New relative to QP:
- Confirmed individual noise-group identity does **not** survive public wire (stronger than signal/noise-only CF-T3).
- Toeplitz map rank fully characterized; not an attack surface without keyed `top`.
- No build divergence; no new public delta.

**Reopen only if:** new public equations on R/ratio, recovered missing security-test source, or new active-bound artifact.

Skipped: SAT/GPU, full fork rescan, H-rank re-run, QP-02/03 re-run, mnemonic search.

Lazier alternative done: RP-01 + RP-04 first closed the branch; rest are skips/confirmations.
