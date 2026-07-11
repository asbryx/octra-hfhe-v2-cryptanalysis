// RR-03: full deterministic seeded-build differential digests O0 vs O3.
// Build twice:
//   clang++ -O0 -maes -msse2 -Iinclude rr03_seeded_diff.cpp -o rr03_O0.exe -rtlib=compiler-rt
//   clang++ -O3 -maes -msse2 -mpclmul -Iinclude rr03_seeded_diff.cpp -o rr03_O3.exe -rtlib=compiler-rt

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <pvac/pvac.hpp>
#include <pvac/core/seedable_rng.hpp>
#include <pvac/core/hash.hpp>

using namespace pvac;

static void sha_hex(const uint8_t* d, size_t n, char out[65]) {
    static const char* hexd = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hexd[d[i] >> 4];
        out[2 * i + 1] = hexd[d[i] & 0xf];
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

static void print_digest(const char* tag, Sha256& h) {
    uint8_t out[32];
    h.finish(out);
    char hex[65];
    sha_hex(out, 32, hex);
    std::printf("%s %s\n", tag, hex);
}

static Params active_params() {
    Params p;
    p.B = 337;
    p.m_bits = 8192;
    p.n_bits = 16384;
    p.h_col_wt = 192;
    p.x_col_wt = 128;
    p.err_wt = 128;
    p.noise_entropy_bits = 128.0;
    p.tuple2_fraction = 0.55;
    p.depth_slope_bits = 16.0;
    p.edge_budget = 1200000;
    p.lpn_n = 4096;
    p.lpn_t = 16384;
    p.lpn_tau_num = 1;
    p.lpn_tau_den = 8;
    return p;
}

// Digest intermediates for one seeded encryption via official APIs.
static void run_case(const PubKey& pk, const SecKey& sk, uint64_t val, int depth, const uint8_t seed[32]) {
    std::vector<Fp> vals = { fp_from_u64(val) };
    // For depth path use enc_value_depth_seeded; also capture cores via recompute from layer seeds after encrypt.
    Cipher C = enc_value_depth_seeded(pk, sk, val, depth, seed);

    // decrypt
    Fp dec = dec_value(pk, sk, C);

    // digests
    Sha256 h_ct;
    h_ct.init();
    acc_u64(h_ct, C.slots);
    acc_u64(h_ct, C.L.size());
    acc_u64(h_ct, C.E.size());
    for (const auto& L : C.L) {
        acc_u64(h_ct, (uint64_t)L.rule);
        acc_u64(h_ct, L.seed.ztag);
        acc_u64(h_ct, L.seed.nonce.lo);
        acc_u64(h_ct, L.seed.nonce.hi);
        h_ct.update(L.R_com.data(), 32);
        for (const auto& pc : L.PC) h_ct.update(pc.data(), 32);
    }
    for (const auto& e : C.E) {
        acc_u64(h_ct, e.layer_id);
        acc_u64(h_ct, e.idx);
        acc_u64(h_ct, e.ch);
        for (const auto& w : e.w) acc_fp(h_ct, w);
        // sigma fingerprint
        acc_u64(h_ct, e.s.nbits);
        acc_u64(h_ct, e.s.popcnt());
    }
    for (const auto& c : C.c0) acc_fp(h_ct, c);

    Sha256 h_R;
    h_R.init();
    Sha256 h_num;
    h_num.init();
    for (uint32_t lid = 0; lid < (uint32_t)C.L.size(); ++lid) {
        const Layer& L = C.L[lid];
        if (L.rule != RRule::BASE) continue;
        Fp r1 = prf_R_core(pk, sk, L.seed, Dom::PRF_R1);
        Fp r2 = prf_R_core(pk, sk, L.seed, Dom::PRF_R2);
        Fp r3 = prf_R_core(pk, sk, L.seed, Dom::PRF_R3);
        Fp R = fp_mul(fp_mul(r1, r2), r3);
        acc_fp(h_R, r1);
        acc_fp(h_R, r2);
        acc_fp(h_R, r3);
        acc_fp(h_R, R);
        // noise cores
        Fp n1 = prf_R_core(pk, sk, L.seed, Dom::PRF_NOISE1);
        Fp n2 = prf_R_core(pk, sk, L.seed, Dom::PRF_NOISE2);
        Fp n3 = prf_R_core(pk, sk, L.seed, Dom::PRF_NOISE3);
        acc_fp(h_R, n1);
        acc_fp(h_R, n2);
        acc_fp(h_R, n3);
    }
    // signed numerators per edge
    for (const auto& e : C.E) {
        Fp gp = pk.powg_B[e.idx];
        Fp tw = fp_mul(e.w[0], gp);
        if (e.ch == SGN_M) tw = fp_neg(tw);
        acc_fp(h_num, tw);
    }

    std::printf("CASE val=%llu depth=%d\n", (unsigned long long)val, depth);
    print_digest("ct_digest", h_ct);
    print_digest("R_cores_digest", h_R);
    print_digest("numerators_digest", h_num);
    std::printf("dec_lo=%llu dec_hi=%llu\n", (unsigned long long)dec.lo, (unsigned long long)dec.hi);
    std::printf("edges=%zu layers=%zu\n", C.E.size(), C.L.size());
}

int main() {
    Params prm = active_params();
    uint8_t wallet[32];
    for (int i = 0; i < 32; i++) wallet[i] = (uint8_t)(0x10 + i);

    PubKey pk;
    SecKey sk;
    keygen_from_seed(prm, pk, sk, wallet);

    // sk fixture identity
    Sha256 hsk;
    hsk.init();
    for (int i = 0; i < 4; i++) acc_u64(hsk, sk.prf_k[i]);
    for (auto w : sk.lpn_s_bits) acc_u64(hsk, w);
    print_digest("sk_fixture", hsk);

    // pk digest (H_digest already)
    char hex[65];
    sha_hex(pk.H_digest.data(), 32, hex);
    std::printf("pk_H_digest %s\n", hex);
    std::printf("canon_tag %llu\n", (unsigned long long)pk.canon_tag);

    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(0x55 ^ i);

    uint64_t values[] = { 0, 1, 337, 0xFFFFFFFFFFFFFFFFULL, ((uint64_t)1 << 63) | 0x1234 };
    int depths[] = { 0, 2, 10, 22 };

    for (uint64_t v : values) {
        for (int d : depths) {
            run_case(pk, sk, v, d, seed);
        }
    }
    return 0;
}
