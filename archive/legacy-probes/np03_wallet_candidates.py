# ponytail: finite evidenced wallet candidates only; max ~10k
from __future__ import annotations

import hashlib
import hmac
import struct
from pathlib import Path

TARGET = "octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ"
ACTIVE = {
    "secret.ct": "5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab",
    "pk.bin": "1e788edff9dea19a782defae053f3757ccf5edd41cd3e24ae44e1496045e9410",
    "params.json": "24bf1290b32f6159a95ab5a8428fcd6bd5c91c903efb77defda1bdbdda397d80",
    "manifest.json": "0cbda19f5ff723ac2586e769cbf3b26c178066f4ae1602b40a2404e7d99cc18c",
    "pk.raw": "67e8538a2a47dfc1539d2777aa36488654b1c92265be08ed941f251a08c2ce28",
}
FUNDING_TX = "ad1af0cf96a12105bb112b0f3f7275e8fbd713e2f6966d886f5ec2c04e514898"
COMMITS = [
    "0d08e9622921e5930175a660df0061a65548972f",
    "071b0e909c119de815e284b347c4bd979cb59ef3",
    "88a72b703f4cdd26b5fe6b3249850c2cbcef3b43",
    "cdc6a527fed01ce4cbd569546efee8636ef1c78d",
]
H_DIGEST = "601435f4977dd2a0c396bd96c7947fb884b602a52b6d7e0660b3fce3508497f5"
CANON = 531565633433868593
WRONG_CT = "5da3f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab"  # eienel typo


def b58encode(data: bytes) -> str:
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(alphabet[r])
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return (alphabet[0:1] * pad + out[::-1]).decode()


def addr_from_seed32(seed32: bytes) -> str:
    try:
        from nacl.signing import SigningKey
    except ImportError:
        # fallback: pure ed25519 via cryptography if available
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization
            pk = Ed25519PrivateKey.from_private_bytes(seed32).public_key()
            pub = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        except Exception as e:
            raise SystemExit(f"need pynacl or cryptography: {e}")
    else:
        pub = bytes(SigningKey(seed32).verify_key)
    return "oct" + b58encode(hashlib.sha256(pub).digest())


def octra_from_mnemonic(mn: str) -> str:
    try:
        from mnemonic import Mnemonic
    except ImportError:
        raise SystemExit("need mnemonic package")
    m = Mnemonic("english")
    seed = m.to_seed(mn)  # bip39
    mac = hmac.new(b"Octra seed", seed, hashlib.sha512).digest()
    return addr_from_seed32(mac[:32])


def bip39_12_from_entropy16(ent16: bytes) -> str | None:
    try:
        from mnemonic import Mnemonic
    except ImportError:
        return None
    m = Mnemonic("english")
    try:
        return m.to_mnemonic(ent16)
    except Exception:
        return None


def candidates() -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()

    def add(label: str, b: bytes):
        if len(b) != 32:
            return
        if b in seen:
            return
        seen.add(b)
        out.append((label, b))

    # full hashes as seeds
    for name, hx in ACTIVE.items():
        raw = bytes.fromhex(hx)
        add(f"sha256hex_as_seed:{name}", raw)
        add(f"sha256(bytes.fromhex):{name}", hashlib.sha256(raw).digest())
        add(f"sha256^2:{name}", hashlib.sha256(hashlib.sha256(raw).digest()).digest())
        # halves as entropy -> expand via sha256 of half
        add(f"first16||0:{name}", raw[:16] + b"\x00" * 16)
        add(f"last16||0:{name}", raw[16:] + b"\x00" * 16)
        add(f"sha256(first16):{name}", hashlib.sha256(raw[:16]).digest())
        add(f"sha256(last16):{name}", hashlib.sha256(raw[16:]).digest())

    # pair-binding
    pair = hashlib.sha256(bytes.fromhex(ACTIVE["pk.bin"]) + bytes.fromhex(ACTIVE["secret.ct"])).digest()
    add("sha256(pk||ct)", pair)
    add("sha256(ct||pk)", hashlib.sha256(bytes.fromhex(ACTIVE["secret.ct"]) + bytes.fromhex(ACTIVE["pk.bin"])).digest())

    # H digest, canon
    add("H_digest", bytes.fromhex(H_DIGEST))
    add("canon_le||0", CANON.to_bytes(8, "little") + b"\x00" * 24)
    add("canon_be||0", CANON.to_bytes(8, "big") + b"\x00" * 24)
    add("sha256(canon_le)", hashlib.sha256(CANON.to_bytes(8, "little")).digest())

    # commits / funding
    for c in COMMITS + [FUNDING_TX]:
        hx = c if len(c) == 64 else c  # already hex
        raw = bytes.fromhex(hx)
        add(f"hex_as_seed:{c[:12]}", raw)
        add(f"sha256(hexbytes):{c[:12]}", hashlib.sha256(raw).digest())

    # labels / domains
    labels = [
        b"OCTRA-HFHE-BTY02",
        b"octra-hfhe-bounty-v2",
        b"pvac.prf.rho",
        b"pvac.rist.pedersen.H",
        b"OCTRA_PVAC_MASTER_V1",
        b"OCTRA_PVAC_TAG",
        b"OCTRA_PVAC_SK",
        b"OCTRA_PVAC_GEN",
        b"Octra seed",
        TARGET.encode(),
        b"challenge_private/plaintext.txt",
        b"challenge_public/secret.ct",
        WRONG_CT.encode(),
        ACTIVE["secret.ct"].encode(),
        ACTIVE["pk.bin"].encode(),
    ]
    for lab in labels:
        add(f"sha256({lab!r})", hashlib.sha256(lab).digest())
        add(f"sha256^2({lab!r})", hashlib.sha256(hashlib.sha256(lab).digest()).digest())
        if len(lab) >= 32:
            add(f"raw32({lab[:16]!r})", lab[:32])
        else:
            add(f"pad32({lab!r})", lab.ljust(32, b"\x00"))

    # flip_weak-ish patterns
    for pat in [
        bytes([i] * 32) for i in (0, 1, 0xFF, 0x42)
    ] + [bytes(range(32)), bytes(range(31, -1, -1))]:
        add(f"pattern:{pat[:4].hex()}", pat)

    # eienel wrong hash as seed (sanity that we include corrected path)
    add("wrong_ct_hex_seed", bytes.fromhex(WRONG_CT))

    return out


def main():
    # verify address helper shape with random
    import os
    demo = os.urandom(32)
    a = addr_from_seed32(demo)
    assert a.startswith("oct") and len(a) > 10
    print("addr_helper_ok demo", a[:12], "...")

    cands = candidates()
    print("candidate_seeds", len(cands))
    hits = []
    # path A: raw seed
    for label, seed in cands:
        if addr_from_seed32(seed) == TARGET:
            hits.append(("raw_seed", label, seed.hex()))
        # path B: treat first 16 as bip39 entropy
        mn = bip39_12_from_entropy16(seed[:16])
        if mn:
            try:
                if octra_from_mnemonic(mn) == TARGET:
                    hits.append(("bip39_12_octra", label, mn))
            except Exception:
                pass
        # path C: sha256 of seed as ed25519
        s2 = hashlib.sha256(seed).digest()
        if addr_from_seed32(s2) == TARGET:
            hits.append(("sha256_seed_raw", label, s2.hex()))
        # path D: HMAC Octra seed on seed as bip seed
        mac = hmac.new(b"Octra seed", seed, hashlib.sha512).digest()
        if addr_from_seed32(mac[:32]) == TARGET:
            hits.append(("hmac_octra_on_seed", label, mac[:32].hex()))

    print("hits", len(hits))
    for h in hits[:20]:
        print("HIT", h)
    print("tested_paths_per_seed=4 approx_total", len(cands) * 4)
    if not hits:
        print("VERDICT no match in finite evidenced set")


if __name__ == "__main__":
    main()
