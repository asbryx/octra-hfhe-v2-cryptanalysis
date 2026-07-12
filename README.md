# OCTRA HFHE Challenge v2 Cryptanalysis

Independent, source-first analysis of OCTRA's public HFHE Challenge v2, including the 44 R1 LPN sample files added on July 11, 2026.

## Result

**No plaintext, wallet key, HFHE secret, complete masking factor, or practical public-only recovery method was found.**

The new corpus is material: it publishes 720,896 dense noisy parity equations for one shared 4,096-bit target secret and makes candidate verification straightforward. It does not publish a practical candidate-generation method, the keyed Toeplitz material, or the R2/R3 transcripts needed for normal decryption.

```text
published A_R1  -> exact verifier for a candidate PRF key
published y_R1  -> statistical verifier for a candidate LPN secret
PRF key alone   -> R1 core only; R2/R3 labels still require the LPN secret
LPN secret alone-> no keyed rows, selector words, Toeplitz top, or full R
both secrets    -> normal reconstruction of every R factor
```

## Pinned Inputs

| Meaning | Commit / hash |
|---|---|
| Target bytes introduced | `88a72b703f4cdd26b5fe6b3249850c2cbcef3b43` |
| Manifest became active | `547271bcefb77cc5c4a5bf3dd5d742e6e0ed315b` |
| Announcement snapshot | `0d08e9622921e5930175a660df0061a65548972f` |
| Current challenge HEAD assessed | `019380c97543620091409b0fbf73a8a773a9a0da` |
| Pinned PVAC source | `071b0e909c119de815e284b347c4bd979cb59ef3` |
| `secret.ct` SHA-256 | `5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab` |
| `pk.bin` SHA-256 | `1e788edff9dea19a782defae053f3757ccf5edd41cd3e24ae44e1496045e9410` |

These anchors are deliberately separate. The commit that introduced the target bytes, the activation commit, the announcement snapshot, and the current repository HEAD are not the same event.

## Confirmed Findings

### Corpus integrity and structure

- 44/44 JSONL files match the published SHA-256 manifest.
- 720,896/720,896 rows are sequential, correctly sized, and unique.
- Every row has 4,096 bits; the observed mean row weight is 2,047.94.
- All files cover only `pvac.prf.r.1`.
- The first file alone has exact GF(2) rank 4,096; `[A|y]` has rank 4,097.
- No exact two-row or three-row dependency exists in the first 16,384-row file.
- Sampled cross-file dependencies are dense, with median weight about 2,051, so their residual bias is negligible.
- Direct pivot and all-pairs LF2 runs on all 720,896 rows leave at least 4,036 full-rank residual dimensions; no tractable final stage appears.

### Effective secret dimensions

- All 256 PRF-key input bits affect the SHA-derived AES key and first output block.
- The 44 R1 counter starts are unique.
- No active key/counter/domain collision or Toeplitz counter-range overlap was found.
- The LPN secret and PRF key are independent outputs of the producer's system CSPRNG path.

### Concrete algorithm boundary

| Method | Concrete result |
|---|---|
| Prange, fixed-weight model | approximately `2^791.48` trials |
| Stern, about 64 MiB extra memory | approximately `2^785.74` list work |
| Stern, about 42.5 GiB extra memory | approximately `2^783.87` list work |
| Restricted BKW, level 3 | optimistic information remains near the residual dimension, but rows are correlated |
| Restricted BKW, level 4 | about 43 optimistic information bits remain for 4,036 dimensions |
| Information-set toy ladder | follows clean-subset/full-rank theory through `n=60`; no scaling anomaly |

These numbers are models and bounded experiments, not a formal impossibility proof.

### PC / R coupling

A full PRF-key candidate determines the PC blinding term. The exact wrapped-PC equation also contains a field-to-scalar carry: after removing the candidate blinding and plaintext point, the residual is `[q(2^127-1)]G` for a signed roughly 127-bit `q`, not the identity. The official-code fixture `tools/joint_pc_official.cpp` verifies this corrected equation with real Ristretto operations.

Opening that range still requires roughly `2^63.5` generic group operations. Public R1 data then determines only the product of the R2 and R3 cores, not either factor, so this remains less useful than checking the same PRF-key candidate directly against one published R1 row.

## Comparison with smoke-ui

[`smoke-ui/octra-hfhe-v2-security-assessment`](https://github.com/smoke-ui/octra-hfhe-v2-security-assessment) is a useful independent assessment with strong wire-format, runtime, subgroup, compiler, and methodology controls. Its assessed challenge snapshot is `0d08e96`, before the LPN corpus was added.

This repository extends that work by:

- separating the four challenge timeline anchors;
- assessing current HEAD `019380c` and all 44 R1 files;
- validating the entire 756 MB corpus by streaming;
- computing exact active R1 rank and low-weight dependency results;
- modeling fixed-sample decoding rather than assuming unlimited samples;
- auditing the dependency bridge from public R1 data to the PRF key, Toeplitz extraction, R2/R3, PC, and plaintext;
- narrowing several earlier closure claims to exactly what the probes measured.

See [`docs/smoke-ui-comparison.md`](docs/smoke-ui-comparison.md) for the dedicated result-by-result comparison, including why the LPN, compiler, concurrency, and PC/R conclusions differ.

## Repository Layout

```text
README.md                       Current result and reproduction guide
STATUS.md                       Compact decision record and reopen conditions
METHODOLOGY.md                  Evidence and reporting standards
research/reconstruction-audit.md Source, timeline, wire, and algebra audit
research/final-exhaustion.md     Full corpus and mathematical boundary report
docs/smoke-ui-comparison.md      Comparison with the smoke-ui assessment
tools/                           Small runnable probes
results/                         Committed measured JSON outputs
archive/                         Historical phase reports and 93 legacy probe/source/result files
SHA256SUMS                       Integrity manifest for this repository
```

The 756 MB upstream JSONL corpus is intentionally not duplicated. `tools/validate_lpn_corpus.py` streams the canonical files and checks them against upstream `SHA256SUMS`.

## Reproduction

Python 3.11+ is recommended.

```bash
python -m pip install -r requirements.txt
python tools/validate_lpn_corpus.py
python tools/check_finite_prf_candidates.py path/to/ct00_l0_s0_pvac_prf_r_1.jsonl
python tools/lf2_real_corpus.py path/to/lpn_samples --schedule 15,15,15,15
python tools/lpn_restricted_ladder.py --model-only
python tools/lpn_restricted_ladder.py
python tools/heuristic_ladder.py --is-only --sizes 8,12,16,20,24,28,32
python tools/qp04_joint_equations_toy.py
```

For the exact one-file rank/dependency audit, download the canonical file next to the tool or pass it explicitly:

```bash
python tools/lpn_rank_dependency_audit.py \
  --corpus path/to/ct00_l0_s0_pvac_prf_r_1.jsonl \
  --metadata results/lpn_corpus_validation.json
```

Verify repository files:

```bash
sha256sum -c SHA256SUMS
```

## Current Decision

```text
Mathematically impossible?       No
Information-theoretically stuck? No; the R1 corpus is information-rich
Known practical public method?   No
Cheap source-grounded step left? None found
```

Reopen the analysis if OCTRA publishes R2/R3 samples, keyed Toeplitz material, a reduced PRF-key candidate family, a target-bound secret reuse, a PC opening, changed target bytes, or a materially better concrete algorithm.

## Scope and Safety

This repository analyzes an explicitly public cryptographic challenge and public source code. It does not include private wallet material, credentials, the challenge secret key, or recovered plaintext. No funds were moved.

## License

Original analysis prose and tools in this repository are MIT licensed. OCTRA and PVAC artifacts remain under their upstream terms and are referenced rather than redistributed.
