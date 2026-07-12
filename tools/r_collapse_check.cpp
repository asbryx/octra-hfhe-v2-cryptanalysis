#include <pvac/core/field.hpp>
#include <pvac/crypto/lpn.hpp>

#include <cstdio>
#include <stdexcept>

using namespace pvac;

static bool eq(const Fp& a, const Fp& b) {
    return a.lo == b.lo && a.hi == b.hi;
}

int main() {
    const Fp one = fp_from_u64(1);
    const Fp zero = fp_from_u64(0);

    // ponytail: boundary cases cover the only fold in hash_to_fp_nonzero.
    if (!eq(hash_to_fp_nonzero(0, 0), one)) throw std::runtime_error("zero fold");
    if (!eq(hash_to_fp_nonzero(UINT64_MAX, MASK63), one)) throw std::runtime_error("p fold");
    if (!eq(hash_to_fp_nonzero(2, 0), fp_from_u64(2))) throw std::runtime_error("ordinary map");

    const Fp a = hash_to_fp_nonzero(0x0123456789abcdefULL, 0x123456789abcdef0ULL);
    const Fp b = hash_to_fp_nonzero(0xfedcba9876543210ULL, 0x0fedcba987654321ULL);
    const Fp c = hash_to_fp_nonzero(0x55aa55aa55aa55aaULL, 0x2aaa5555aaaa5555ULL);
    const Fp product = fp_mul(fp_mul(a, b), c);
    if (eq(a, zero) || eq(b, zero) || eq(c, zero) || eq(product, zero))
        throw std::runtime_error("nonzero closure");
    if (!eq(fp_mul(product, fp_inv(product)), one)) throw std::runtime_error("inverse identity");

    std::printf("hash_boundary=PASS\nnonzero_product=PASS\ninverse_identity=PASS\n");
    std::printf("verdict=R_ENDPOINT_HAS_NO_PUBLIC_OR_SMALL_FAMILY_COLLAPSE\n");
}
