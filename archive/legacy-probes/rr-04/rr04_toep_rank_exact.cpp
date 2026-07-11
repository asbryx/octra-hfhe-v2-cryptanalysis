// RR-04: exact-source Toeplitz top rank via official AES/derive_aes_key path.
// clang++ -std=c++17 -O2 -maes -msse2 -mpclmul -rtlib=compiler-rt -Iinclude rr04_toep_rank_exact.cpp -o rr04.exe

#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <pvac/core/types.hpp>
#include <pvac/crypto/lpn.hpp>
#include <pvac/crypto/toeplitz.hpp>

using namespace pvac;

static int valuation127(uint64_t lo, uint64_t hi) {
    // bits 0..63 in lo, 64..126 in hi low 63 bits
    if (lo) {
        // ctz
        int v = 0;
        uint64_t x = lo;
        while ((x & 1) == 0) {
            x >>= 1;
            v++;
        }
        return v;
    }
    uint64_t x = hi & ((1ull << 63) - 1); // bits 64..126
    if (!x) return 127; // all zero in 127
    int v = 64;
    while ((x & 1) == 0) {
        x >>= 1;
        v++;
    }
    return v;
}

static int gaussian_rank127(uint64_t top_lo, uint64_t top_hi) {
    // Build 127x127 map rows as bitsets in two u64? use array of 127 uint64_t for low 64 and need 127 bits
    // Use vector of __int128 or two words per row: store as array of 2 uint64 truncated to 127 cols
    uint64_t rows_lo[127];
    uint64_t rows_hi[127];
    auto top_bit = [&](int j) -> int {
        if (j < 64) return (int)((top_lo >> j) & 1);
        return (int)((top_hi >> (j - 64)) & 1);
    };
    for (int j = 0; j < 127; j++) {
        rows_lo[j] = 0;
        rows_hi[j] = 0;
        for (int i = 0; i <= j; i++) {
            if (top_bit(j - i)) {
                if (i < 64) rows_lo[j] |= 1ull << i;
                else rows_hi[j] |= 1ull << (i - 64);
            }
        }
    }
    // GF2 rank
    int rank = 0;
    bool used[127] = {};
    for (int col = 0; col < 127; col++) {
        int piv = -1;
        for (int r = 0; r < 127; r++) {
            if (used[r]) continue;
            int bit = (col < 64) ? (int)((rows_lo[r] >> col) & 1) : (int)((rows_hi[r] >> (col - 64)) & 1);
            if (bit) {
                piv = r;
                break;
            }
        }
        if (piv < 0) continue;
        used[piv] = true;
        rank++;
        for (int r = 0; r < 127; r++) {
            if (r == piv) continue;
            int bit = (col < 64) ? (int)((rows_lo[r] >> col) & 1) : (int)((rows_hi[r] >> (col - 64)) & 1);
            if (!bit) continue;
            rows_lo[r] ^= rows_lo[piv];
            rows_hi[r] ^= rows_hi[piv];
        }
    }
    return rank;
}

static void gen_top127(const PubKey& pk, const SecKey& sk, const RSeed& seed, const char* dom,
                       uint64_t& lo, uint64_t& hi) {
    uint8_t toep_key[32];
    uint64_t toep_nonce;
    derive_aes_key(pk, sk, seed, Dom::TOEP, toep_key, toep_nonce);
    toep_nonce ^= fnv1a_domain(dom);
    AesCtr256 prg;
    prg.init(toep_key, toep_nonce);
    size_t top_words = ((size_t)pk.prm.lpn_t + 127u + 63u) / 64u;
    std::vector<uint64_t> top(top_words);
    prg.fill_u64(top.data(), top_words);
    // low 127 bits
    lo = top[0];
    hi = (top.size() > 1) ? (top[1] & ((1ull << 63) - 1)) : 0;
    // clear bit 127+ in hi already
}

int main() {
    Params prm;
    prm.lpn_n = 4096;
    prm.lpn_t = 16384;
    prm.lpn_tau_num = 1;
    prm.lpn_tau_den = 8;
    prm.m_bits = 8192;
    prm.n_bits = 16384;
    prm.B = 337;

    // load active seeds from seeds_active.txt style via embedded parse later — generate from file
    // For dummy keys: 16 fixtures
    const char* domains[] = {
        Dom::PRF_R1, Dom::PRF_R2, Dom::PRF_R3,
        Dom::PRF_NOISE1, Dom::PRF_NOISE2, Dom::PRF_NOISE3
    };

    // Read seeds file
    FILE* f = std::fopen("archive/legacy-probes/seeds_active.txt", "r");
    if (!f) {
        std::fprintf(stderr, "missing seeds_active.txt\n");
        return 1;
    }
    std::vector<RSeed> seeds;
    char line[512];
    while (std::fgets(line, sizeof line, f)) {
        unsigned long long z = 0, lo = 0, hi = 0;
        if (std::sscanf(line, "C%*d L%*d rule=BASE ztag=%llx lo=%llx hi=%llx", &z, &lo, &hi) == 3 ||
            std::sscanf(line, "%*s %*s rule=BASE ztag=%llx lo=%llx hi=%llx", &z, &lo, &hi) == 3) {
            RSeed s;
            s.ztag = (uint64_t)z;
            s.nonce.lo = (uint64_t)lo;
            s.nonce.hi = (uint64_t)hi;
            seeds.push_back(s);
        }
    }
    std::fclose(f);
    // fallback parse with strstr
    if (seeds.size() != 44) {
        seeds.clear();
        f = std::fopen("archive/legacy-probes/seeds_active.txt", "r");
        while (std::fgets(line, sizeof line, f)) {
            char* pz = std::strstr(line, "ztag=");
            char* pl = std::strstr(line, " lo=");
            char* ph = std::strstr(line, " hi=");
            if (!pz || !pl || !ph) continue;
            RSeed s;
            s.ztag = std::strtoull(pz + 5, nullptr, 0);
            s.nonce.lo = std::strtoull(pl + 4, nullptr, 0);
            s.nonce.hi = std::strtoull(ph + 4, nullptr, 0);
            seeds.push_back(s);
        }
        std::fclose(f);
    }
    std::printf("seeds_loaded=%zu\n", seeds.size());

    PubKey pk;
    pk.prm = prm;
    pk.canon_tag = 531565633433868593ull;
    // H_digest active
    static const char* hd = "601435f4977dd2a0c396bd96c7947fb884b602a52b6d7e0660b3fce3508497f5";
    for (int i = 0; i < 32; i++) {
        unsigned v;
        std::sscanf(hd + 2 * i, "%02x", &v);
        pk.H_digest[i] = (uint8_t)v;
    }

    int total = 0, match = 0;
    std::map<int, int> rank_hist, val_hist;

    for (int ki = 0; ki < 16; ki++) {
        SecKey sk;
        for (int i = 0; i < 4; i++) sk.prf_k[i] = 0xA11CE5EED0000000ull + ki * 0x100000001B3ull + i;
        sk.lpn_s_bits.assign((prm.lpn_n + 63) / 64, 0);
        for (size_t i = 0; i < sk.lpn_s_bits.size(); i++)
            sk.lpn_s_bits[i] = 0xC0FFEEULL + ki * 0x9E3779B97F4A7C15ULL + i;

        for (const auto& seed : seeds) {
            for (const char* dom : domains) {
                uint64_t lo, hi;
                gen_top127(pk, sk, seed, dom, lo, hi);
                int val = valuation127(lo, hi);
                int pred = (val >= 127) ? 0 : (127 - val);
                int gr = gaussian_rank127(lo, hi);
                total++;
                if (pred == gr) match++;
                rank_hist[gr]++;
                val_hist[val]++;
            }
        }
    }

    std::printf("samples=%d formula_match=%d match_rate=%.6f\n", total, match, total ? (double)match / total : 0);
    std::printf("NOTE=active_seeds_plus_dummy_keys_not_exact_active_secret\n");
    std::printf("rank_hist:");
    for (auto& kv : rank_hist) std::printf(" %d:%d", kv.first, kv.second);
    std::printf("\nval_hist_head:");
    int shown = 0;
    for (auto& kv : val_hist) {
        std::printf(" %d:%d", kv.first, kv.second);
        if (++shown >= 12) break;
    }
    std::printf("\nverdict=%s\n", (match == total && total > 0) ? "FORMULA_CONFIRMED" : "MISMATCH");
    return match == total ? 0 : 2;
}
