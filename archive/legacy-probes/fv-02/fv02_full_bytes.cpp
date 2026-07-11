// FV-02: full-byte O0/O3 comparison with full sigma words, serialize_cipher, prf_noise_delta.
// Build twice O0 and O3; compare digests.

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <pvac/pvac.hpp>
#include <pvac/core/seedable_rng.hpp>
#include <pvac/core/hash.hpp>

// Challenge serializer
#include "hfhe-challenge@0d08e96/source/pvac_artifact_serialize.hpp"

using namespace pvac;

static void sha_hex(const uint8_t* d, size_t n, char out[65]) {
    static const char* H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = H[d[i] >> 4];
        out[2 * i + 1] = H[d[i] & 0xf];
    }
    out[2 * n] = 0;
}

static void acc_u64(Sha256& h, uint64_t x) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)((x >> (8 * i)) & 0xff);
    h.update(b, 8);
}
static void acc_fp(Sha256& h, const Fp& x) {
    acc_u64(h, x.lo);
    acc_u64(h, x.hi);
}
static void print_d(const char* tag, Sha256& h) {
    uint8_t o[32];
    h.finish(o);
    char hex[65];
    sha_hex(o, 32, hex);
    std::printf("%s %s\n", tag, hex);
}

static Params active_params() {
    Params p;
    p.noise_entropy_bits = 128.0;
    return p;
}

static void run_case(const PubKey& pk, const SecKey& sk, uint64_t val, int depth, const uint8_t seed[32]) {
    Cipher C = enc_value_depth_seeded(pk, sk, val, depth, seed);
    Fp dec = dec_value(pk, sk, C);

    // full sigma digest
    Sha256 h_sig;
    h_sig.init();
    for (const auto& e : C.E) {
        acc_u64(h_sig, e.s.nbits);
        acc_u64(h_sig, e.s.w.size());
        for (uint64_t w : e.s.w) acc_u64(h_sig, w);
    }

    // serialized cipher bytes
    auto blob = pvac_ser::serialize_cipher(C);
    Sha256 h_ser;
    h_ser.init();
    h_ser.update(blob.data(), blob.size());

    // R cores + exact prf_noise_delta per group actually made
    Sha256 h_rd;
    h_rd.init();
    Sha256 h_num;
    h_num.init();
    Sha256 h_pc;
    h_pc.init();
    for (uint32_t lid = 0; lid < (uint32_t)C.L.size(); ++lid) {
        const Layer& L = C.L[lid];
        if (L.rule != RRule::BASE) continue;
        Fp r1 = prf_R_core(pk, sk, L.seed, Dom::PRF_R1);
        Fp r2 = prf_R_core(pk, sk, L.seed, Dom::PRF_R2);
        Fp r3 = prf_R_core(pk, sk, L.seed, Dom::PRF_R3);
        Fp R = fp_mul(fp_mul(r1, r2), r3);
        acc_fp(h_rd, r1);
        acc_fp(h_rd, r2);
        acc_fp(h_rd, r3);
        acc_fp(h_rd, R);
        acc_u64(h_rd, L.seed.ztag);
        acc_u64(h_rd, L.seed.nonce.lo);
        acc_u64(h_rd, L.seed.nonce.hi);
        h_rd.update(L.R_com.data(), 32);
        for (const auto& pc : L.PC) h_pc.update(pc.data(), 32);

        // budget at this layer: we don't store depth on layer; recompute from edge density?
        // Use depths from case for both BASE layers of wrap is approximate.
        // Better: for each possible gid in budget at `depth` for this encryption depth.
        entropy::Budget b = entropy::Budget::compute(pk.prm, depth);
        // N2 groups: kind 0, N3: kind 1 per Set::make
        for (int g = 0; g < b.n2; ++g) {
            Fp dlt = prf_noise_delta(pk, sk, L.seed, (uint32_t)g, 0);
            acc_fp(h_rd, dlt);
        }
        for (int g = 0; g < b.n3; ++g) {
            Fp dlt = prf_noise_delta(pk, sk, L.seed, (uint32_t)(b.n2 + g), 1);
            acc_fp(h_rd, dlt);
        }
        // Note: wrapped layers may have been built at same depth d for both halves of enc_value_depth_seeded.
    }
    for (const auto& e : C.E) {
        Fp tw = fp_mul(e.w[0], pk.powg_B[e.idx]);
        if (e.ch == SGN_M) tw = fp_neg(tw);
        acc_fp(h_num, tw);
    }

    std::printf("CASE val=%llu depth=%d seed0=%u\n", (unsigned long long)val, depth, seed[0]);
    print_d("serialized_ct_sha256", h_ser);
    print_d("full_sigma_sha256", h_sig);
    print_d("R_and_delta_sha256", h_rd);
    print_d("layer_numerator_sha256", h_num);
    print_d("PC_sha256", h_pc);
    std::printf("dec_lo=%llu dec_hi=%llu edges=%zu layers=%zu ser_bytes=%zu\n",
        (unsigned long long)dec.lo, (unsigned long long)dec.hi, C.E.size(), C.L.size(), blob.size());
}

int main() {
    Params prm = active_params();
    uint8_t wallet[32];
    for (int i = 0; i < 32; i++) wallet[i] = (uint8_t)(0x20 + i);
    PubKey pk;
    SecKey sk;
    keygen_from_seed(prm, pk, sk, wallet);

    Sha256 hsk;
    hsk.init();
    for (int i = 0; i < 4; i++) acc_u64(hsk, sk.prf_k[i]);
    for (auto w : sk.lpn_s_bits) acc_u64(hsk, w);
    print_d("sk_fixture", hsk);
    char hex[65];
    sha_hex(pk.H_digest.data(), 32, hex);
    std::printf("pk_H_digest %s\n", hex);

    // self-check: serialize roundtrip one toy
    {
        uint8_t s[32];
        for (int i = 0; i < 32; i++) s[i] = (uint8_t)i;
        Cipher C = enc_value_depth_seeded(pk, sk, 7, 0, s);
        auto blob = pvac_ser::serialize_cipher(C);
        auto C2 = pvac_ser::deserialize_cipher(blob.data(), blob.size());
        auto blob2 = pvac_ser::serialize_cipher(C2);
        bool ok = blob == blob2 && dec_value(pk, sk, C2).lo == 7;
        std::printf("serializer_self_check=%d ser_bytes=%zu\n", ok ? 1 : 0, blob.size());
    }

    uint64_t values[] = { 0, 1, 337, ~0ull, ((uint64_t)1 << 63) | 0x1234 };
    int depths[] = { 0, 2, 10, 22 };
    // 3 encryption seeds
    for (int si = 0; si < 3; si++) {
        uint8_t seed[32];
        for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(0x55 ^ i ^ (si * 0x11));
        for (uint64_t v : values) {
            for (int d : depths) {
                run_case(pk, sk, v, d, seed);
            }
        }
    }
    return 0;
}
