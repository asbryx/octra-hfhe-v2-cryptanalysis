// QP-05: GF(2) rank of active H from pk.raw (8192 x 16384).
// clang++ -std=c++17 -O3 -I. qp05_h_rank.cpp -o qp05_h_rank.exe

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>

static constexpr int M = 8192;
static constexpr int N = 16384;
static constexpr int W = M / 64; // 128 words per column

struct Reader {
    const uint8_t* p;
    const uint8_t* end;
    explicit Reader(const std::vector<uint8_t>& b) : p(b.data()), end(b.data() + b.size()) {}
    void take(void* out, size_t n) {
        if (p + n > end) throw std::runtime_error("trunc");
        std::memcpy(out, p, n);
        p += n;
    }
    uint64_t u64() { uint64_t x; take(&x, 8); return x; }
    int32_t i32() { int32_t x; take(&x, 4); return x; }
    double f64() { double x; take(&x, 8); return x; }
    void skip(size_t n) { if (p + n > end) throw std::runtime_error("trunc"); p += n; }
};

// Column-major: cols[j] is array of W uint64 words (bit 0 = row 0)
// Rank via Gaussian elimination on rows: treat each of N columns as vector in F2^M.
// Memory: N * W * 8 = 16384 * 128 * 8 = 16MB.

static int gf2_rank(std::vector<uint64_t>& mat /* N * W, row-major over columns */) {
    // mat layout: column j starts at mat[j*W]
    int rank = 0;
    std::vector<char> used(N, 0);
    for (int row = 0; row < M; row++) {
        int word = row >> 6;
        uint64_t bit = 1ull << (row & 63);
        int piv = -1;
        for (int j = 0; j < N; j++) {
            if (!used[j] && (mat[j * W + word] & bit)) {
                piv = j;
                break;
            }
        }
        if (piv < 0) continue;
        used[piv] = 1;
        rank++;
        // eliminate
        for (int j = 0; j < N; j++) {
            if (j == piv) continue;
            if (mat[j * W + word] & bit) {
                uint64_t* a = &mat[j * W];
                uint64_t* b = &mat[piv * W];
                for (int k = 0; k < W; k++) a[k] ^= b[k];
            }
        }
    }
    return rank;
}

int main(int argc, char** argv) {
    const char* path = argc > 1 ? argv[1] : "local-corpus/pk.raw";
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::fprintf(stderr, "open fail %s\n", path); return 1; }
    std::vector<uint8_t> raw((std::istreambuf_iterator<char>(f)), {});
    Reader r(raw);
    char magic[6];
    r.take(magic, 6);
    if (std::memcmp(magic, "PVAC\x03\x01", 6) != 0) {
        std::fprintf(stderr, "bad magic\n");
        return 1;
    }
    int B = r.i32();
    int m_bits = r.i32();
    int n_bits = r.i32();
    int h_col_wt = r.i32();
    r.i32(); r.i32(); // x, err
    r.f64(); r.f64(); r.f64();
    r.u64(); // edge budget
    r.i32(); r.i32(); r.i32(); r.i32(); // lpn
    uint64_t canon = r.u64();
    uint64_t ncol = r.u64();
    if (m_bits != M || n_bits != N || (int)ncol != N) {
        std::fprintf(stderr, "dim mismatch m=%d n=%d ncol=%llu\n", m_bits, n_bits, (unsigned long long)ncol);
        return 1;
    }

    std::vector<uint64_t> mat((size_t)N * W, 0);
    for (int j = 0; j < N; j++) {
        uint64_t nbits = r.u64();
        uint64_t nw = r.u64();
        if ((int)nbits != M) {
            std::fprintf(stderr, "col %d nbits=%llu\n", j, (unsigned long long)nbits);
            return 1;
        }
        for (uint64_t wi = 0; wi < nw; wi++) {
            uint64_t w = r.u64();
            if (wi < (uint64_t)W) mat[(size_t)j * W + wi] = w;
        }
    }

    auto t0 = std::chrono::steady_clock::now();
    int rank = gf2_rank(mat);
    auto t1 = std::chrono::steady_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();

    int kdim = M - rank;
    std::printf("active_H_rank=%d\n", rank);
    std::printf("left_kernel_dimension=%d\n", kdim);
    std::printf("m_bits=%d n_bits=%d h_col_wt=%d B=%d\n", m_bits, n_bits, h_col_wt, B);
    std::printf("canon_tag=%llu\n", (unsigned long long)canon);
    std::printf("rank_seconds=%.3f\n", sec);
    std::printf("verdict=%s\n", rank == M ? "FULL_RANK_CLOSED" : "RANK_DEFICIENT");
    return 0;
}
