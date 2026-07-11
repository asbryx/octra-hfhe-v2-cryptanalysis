# Methodology

## Principles

- Pin the exact challenge and PVAC commits before interpreting output.
- Distinguish target-byte provenance, activation, announcement snapshot, and current HEAD.
- Derive claims from source and canonical bytes, not filenames or report prose.
- Preserve negative results and failed hypotheses.
- Do not promote a toy result without a target-scale dependency bridge.

## Evidence ladder

| Level | Evidence | Interpretation |
|---|---|---|
| 0 | Suspicious code or statistic | Hypothesis only |
| 1 | Toy positive/negative control | Detector works in a bounded model |
| 2 | Fresh-key or held-out result | Potential structure |
| 3 | Candidate verifier on the active construction | Useful primitive |
| 4 | Partial recovery with active verification | Material result |
| 5 | Independent reproduction and target validation | Challenge-grade result |

## Required controls

1. Verify upstream hashes and commits.
2. Record model assumptions, dimensions, noise, and sample count.
3. Separate public stopping rules from oracle-only evaluation metrics.
4. Use exact or fixed-weight probabilities when the instance is conditioned on a fixed corpus.
5. Do not extrapolate toy timings to target exponents.
6. Correct broad statistical searches for multiple testing.
7. Retain scripts, measured JSON output, and SHA-256 manifests.

## Simplification policy

The repository keeps one small probe per nontrivial claim. Large frameworks, duplicated upstream corpora, generated binaries, and speculative solvers are intentionally omitted. Add them only when a measured result crosses a promotion gate.

## Safety

Only public challenge artifacts, public repositories, and local controlled fixtures are in scope. Private wallet material, credentials, recovered secrets, and proof-of-control data must never be committed.
