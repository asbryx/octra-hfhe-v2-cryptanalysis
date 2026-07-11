// QP-02: prove toep_127 depends only on input bits 0..126 of top and ybits.
// Reuses official pvac toeplitz.hpp scalar path.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

#include "pvac/crypto/toeplitz.hpp"

using namespace pvac;

static void zero_bits_above(std::vector<uint64_t>& v, int max_bit_inclusive) {
    // keep bits 0..max_bit_inclusive, zero the rest
    for (size_t wi = 0; wi < v.size(); ++wi) {
        uint64_t keep = 0;
        for (int b = 0; b < 64; ++b) {
            int g = (int)(wi * 64 + b);
            if (g <= max_bit_inclusive) keep |= (1ull << b);
        }
        v[wi] &= keep;
    }
}

static void fill_rand(std::vector<uint64_t>& v, std::mt19937_64& rng) {
    for (auto& x : v) x = rng();
}

int main() {
    // active params: lpn_t=16384 for ybits length; top_words = (lpn_t+127+63)/64
    const int lpn_t = 16384;
    const int lpn_n = 4096; // ybits can be longer than 127; use t words
    size_t y_words = ((size_t)lpn_t + 63) / 64;
    size_t top_words = ((size_t)lpn_t + 127u + 63u) / 64u;

    std::mt19937_64 rng(0x5151515151515151ull);
    int N = 256;
    int full_vs_trunc = 0;
    int scalar_vs_pclmul = 0;
    int scalar_vs_pclmul_tests = 0;

    for (int i = 0; i < N; i++) {
        std::vector<uint64_t> top(top_words), y(y_words);
        fill_rand(top, rng);
        fill_rand(y, rng);

        uint64_t lo0, hi0, lo1, hi1, lo2, hi2, lo3, hi3;
        toep_127_scalar(top, y, lo0, hi0);

        auto top_t = top;
        zero_bits_above(top_t, 126);
        toep_127_scalar(top_t, y, lo1, hi1);

        auto y_t = y;
        zero_bits_above(y_t, 126);
        toep_127_scalar(top, y_t, lo2, hi2);

        auto top_tt = top_t;
        auto y_tt = y_t;
        toep_127_scalar(top_tt, y_tt, lo3, hi3);

        if (lo0 == lo1 && hi0 == hi1 && lo0 == lo2 && hi0 == hi2 && lo0 == lo3 && hi0 == hi3)
            full_vs_trunc++;

#if defined(__PCLMUL__)
        uint64_t loc, hic;
        toep_127_clmul(top, y, loc, hic);
        scalar_vs_pclmul_tests++;
        if (loc == lo0 && hic == hi0) scalar_vs_pclmul++;
#endif
    }

    // effective bit probe: which top bit positions change output when flipped?
    int eff_top = 0, eff_y = 0;
    {
        std::vector<uint64_t> top(top_words, 0), y(y_words, 0);
        // set a base pattern
        for (size_t i = 0; i < top_words; i++) top[i] = 0xA5A5A5A5A5A5A5A5ull ^ (uint64_t)i * 0x9e3779b97f4a7c15ull;
        for (size_t i = 0; i < y_words; i++) y[i] = 0x3C3C3C3C3C3C3C3Cull ^ (uint64_t)i * 0xbf58476d1ce4e5b9ull;
        uint64_t blo, bhi;
        toep_127_scalar(top, y, blo, bhi);
        int max_check = (int)std::min<size_t>(top_words * 64, (size_t)lpn_t + 200);
        for (int b = 0; b < max_check; b++) {
            auto t2 = top;
            t2[b >> 6] ^= 1ull << (b & 63);
            uint64_t lo, hi;
            toep_127_scalar(t2, y, lo, hi);
            if (lo != blo || hi != bhi) eff_top++;
        }
        max_check = (int)std::min<size_t>(y_words * 64, (size_t)lpn_t);
        for (int b = 0; b < max_check; b++) {
            auto y2 = y;
            y2[b >> 6] ^= 1ull << (b & 63);
            uint64_t lo, hi;
            toep_127_scalar(top, y2, lo, hi);
            if (lo != blo || hi != bhi) eff_y++;
        }
    }

    std::printf("effective_top_bits=%d\n", eff_top);
    std::printf("effective_y_bits=%d\n", eff_y);
    std::printf("full_vs_truncated_match_count=%d/%d\n", full_vs_trunc, N);
    std::printf("scalar_vs_pclmul_match_count=%d/%d\n", scalar_vs_pclmul, scalar_vs_pclmul_tests);
    if (full_vs_trunc != N) return 2;
    if (eff_top != 127 || eff_y != 127) {
        // still print; may depend on base pattern sparsity — recheck dense
        std::printf("NOTE: influence counts from one base vector; truncation match is primary signal\n");
    }
    return 0;
}
