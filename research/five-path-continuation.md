# Five-Path Continuation Audit

## Result

No new plaintext recovery path was found. The public producer surface, exact active artifact path, fixed-corpus statistical-decoding gate, official update surface, and Circle read authorization path were all rechecked against current public state.

## 1. Producer artifact delta

Upstream remains at `019380c97543620091409b0fbf73a8a773a9a0da`.

- no GitHub Actions workflows;
- no Actions artifacts;
- release `v2_fix` has no downloadable assets;
- all current forks are behind, README-only, or contain analysis/tools already covered by this repository;
- no fork introduces an active `sk.bin`, plaintext, generation log, alternate active ciphertext, or target-bound candidate family.

## 2. Exact active artifact path

The active producer still performs only:

```text
keygen -> read plaintext.txt -> enc_text -> serialize pk/sk/cipher -> round-trip decrypt
```

The public audit path deserializes only `pk.bin` and `secret.ct`; it checks compatibility and structural regressions but does not load `sk.bin` or plaintext. The v3 serializer validates all layer, edge, point, field, and count boundaries relevant to the fixed artifact. No public candidate oracle or ignored secret-bearing field was found.

## 3. Optimistic low-weight-dual gate

`tools/low_weight_dual_gate.py` evaluates an intentionally attacker-favorable model:

- dense random public matrix;
- low-weight dual checks are found for free;
- checks are independent;
- the only cost counted is the number of checks needed to retain a 64-bit distinguishing margin after noise multiplication.

For `M=720896`, `n=4096`, and bias `rho=3/4`:

```text
first weight with one expected target check = 327
first optimistic distinguishing weight     = 355
required checks at weight 355              about 2^301
```

Real check generation and dependency handling can only add cost. This closes statistical decoding as a practical continuation under current parameters; it is not an impossibility proof.

## 4. Official monitor

A daily script-only watcher now tracks the official main HEAD and Git blob IDs for:

- `pk.bin`;
- `secret.ct`;
- `manifest.json`;
- `params.json`;
- `README.md`.

It emits no output when unchanged. A change reopens the analysis automatically.

## 5. Circle read authorization

The shared source path was traced end to end at lite-node commit `e88600f57ccb672d85766998b5613b3b585e60d4`.

Confirmed invariants:

- every authenticated signature binds operation, Circle ID, signer address, and normalized subject;
- the public key must derive to the claimed Octra address;
- Ed25519 verifies the complete canonical message;
- owner-only routes pass through one shared gate;
- storage snapshots require the owner;
- ordinary authenticated views run as the authenticated caller, not as the owner;
- default encrypt, decrypt, cipher serialization, and public-key serialization modes are owner-only;
- active HFHE secret serialization is exposed to WASM only after an encrypt/decrypt capability is allowed for that caller.

`tools/circle_auth_invariant.py` checks the 15 shared source guards. It is a source-level regression check because the OCaml/dune toolchain is not installed in the audit environment. No production authentication was bypassed and no third-party sealed state was accessed.

## Reopen conditions

Reopen for changed official blobs, producer artifacts tied to the active hashes, R2/R3 or Toeplitz material, an evidence-bounded PRF-key family, a demonstrated Circle guard regression, or a decoding algorithm below the measured fixed-corpus boundaries.
