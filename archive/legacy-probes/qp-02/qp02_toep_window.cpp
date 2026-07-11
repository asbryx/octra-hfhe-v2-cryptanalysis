// QP-02: prove toep_127 effective window is bits 0..126 of both operands.
// Reuses official include/pvac/crypto/toeplitz.hpp
// Build:
//   clang++ -std=c++17 -O2 -mpclmul -msse2 -I"pvac_hfhe_cpp@071b0e9/include" \
//     qp02_toep_window.cpp -o qp02_toep_window.exe

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <random>

#include "pvac/crypto/toeplitz.hpp"

using pvac::toep_127_scalar;
#if defined(__PCLMUL__)
using pvac::toep_127_clmul;
#endif

static constexpr int LPN_T = 16384; // active
static constexpr int EFF = 127;

static size_t y_words() { return ((size_t)LPN_T + 63) / 64; }
static size_t top_words() { return ((size_t)LPN_T + 127u + 63u) / 64u; }

static void mask_low127(std::vector<uint64_t>& v) {
    // zero bits with index >= 127
    for (size_t wi = 0; wi < v.size(); ++wi) {
        for (int b = 0; b < 64; ++b) {
            size_t idx = wi * 64 + (size_t)b;
            if (idx >= (size_t)EFF) {
                v[wi] &= ~(1ull << b);
            }
        }
    }
}

static void fill_det(std::vector<uint64_t>& v, uint64_t seed, uint64_t salt) {
    // deterministic splitmix-ish
    uint64_t x = seed ^ (salt * 0x9e3779b97f4a7c15ull);
    for (size_t i = 0; i < v.size(); ++i) {
        x += 0x9e3779b97f4a7c15ull;
        uint64_t z = x;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
        z = z ^ (z >> 31);
        v[i] = z;
    }
}

int main() {
    const int N = 256;
    int full_vs_trunc = 0;
    int scalar_vs_pclmul = 0;
    int scalar_vs_pclmul_total = 0;

    for (int trial = 0; trial < N; ++trial) {
        std::vector<uint64_t> top(top_words()), y(y_words());
        fill_det(top, 0xC0FFEEULL + (uint64_t)trial, 1);
        fill_det(y, 0xBADC0DEULL + (uint64_t)trial * 17, 2);

        uint64_t lo0=0, hi0=0, lo1=0, hi1=0, lo2=0, hi2=0, lo3=0, hi3=0;
        toep_127_scalar(top, y, lo0, hi0);

        auto top_t = top; mask_low127(top_t);
        auto y_t = y; mask_low127(y_t);

        toep_127_scalar(top_t, y, lo1, hi1);   // top only
        toep_127_scalar(top, y_t, lo2, hi2);   // y only
        toep_127_scalar(top_t, y_t, lo3, hi3); // both

        bool ok = (lo0==lo1 && hi0==hi1 && lo0==lo2 && hi0==hi2 && lo0==lo3 && hi0==hi3);
        if (ok) full_vs_trunc++;

#if defined(__PCLMUL__)
        uint64_t lc=0, hc=0;
        toep_127_clmul(top, y, lc, hc);
        scalar_vs_pclmul_total++;
        if (lc==lo0 && hc==hi0) scalar_vs_pclmul++;
#endif
    }

    // negative control: flipping bit 127 of y must NOT change output if hypothesis true;
    // flipping bit 0 must change for some vectors
    int bit127_changes = 0, bit0_changes = 0;
    for (int trial = 0; trial < N; ++trial) {
        std::vector<uint64_t> top(top_words()), y(y_words());
        fill_det(top, 0x1111ULL + trial, 3);
        fill_det(y, 0x2222ULL + trial, 4);
        // clear then set controlled bits for cleaner test
        y[0] |= 1ull; // bit 0
        if (y.size() > 1) y[1] |= (1ull << (127-64)); // bit 127

        uint64_t loA=0, hiA=0, loB=0, hiB=0, loC=0, hiC=0;
        toep_127_scalar(top, y, loA, hiA);
        auto y127 = y;
        y127[1] ^= (1ull << (127-64)); // flip bit 127
        toep_127_scalar(top, y127, loB, hiB);
        auto y0 = y;
        y0[0] ^= 1ull; // flip bit 0
        toep_127_scalar(top, y0, loC, hiC);
        if (loA!=loB || hiA!=hiB) bit127_changes++;
        if (loA!=loC || hiA!=hiC) bit0_changes++;
    }

    std::printf("effective_top_bits=%d\n", EFF);
    std::printf("effective_y_bits=%d\n", EFF);
    std::printf("full_vs_truncated_match_count=%d/%d\n", full_vs_trunc, N);
    std::printf("scalar_vs_pclmul_match_count=%d/%d\n", scalar_vs_pclmul, scalar_vs_pclmul_total);
    std::printf("negctrl_flip_bit127_changes=%d/%d (expect 0)\n", bit127_changes, N);
    std::printf("negctrl_flip_bit0_changes=%d/%d (expect >0)\n", bit0_changes, N);
    std::printf("lpn_t=%d top_words=%zu y_words=%zu\n", LPN_T, top_words(), y_words());

    bool pass = (full_vs_trunc == N) && (bit127_changes == 0) && (bit0_changes > 0);
#if defined(__PCLMUL__)
    pass = pass && (scalar_vs_pclmul == scalar_vs_pclmul_total);
#endif
    std::printf("verdict=%s\n", pass ? "TRUNCATION_EQUIVALENCE_PROVEN" : "FAIL");
    return pass ? 0 : 1;
}
