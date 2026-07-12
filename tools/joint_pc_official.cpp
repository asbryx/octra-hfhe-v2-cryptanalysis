#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>

#include <pvac/pvac.hpp>

using namespace pvac;

static bool scalar_eq(const Scalar& a, const Scalar& b) {
    return a.v[0] == b.v[0] && a.v[1] == b.v[1] && a.v[2] == b.v[2] && a.v[3] == b.v[3];
}

static Scalar rho_for(const SecKey& sk, const Layer& layer) {
    Sha256 h;
    h.init();
    h.update(Dom::PRF_RHO, std::strlen(Dom::PRF_RHO));
    for (int i = 0; i < 4; ++i) sha256_acc_u64(h, sk.prf_k[i]);
    sha256_acc_u64(h, layer.seed.nonce.lo);
    sha256_acc_u64(h, layer.seed.nonce.hi);
    sha256_acc_u64(h, 0);
    uint8_t out[32];
    h.finish(out);
    return sc_reduce256(out);
}

static std::array<Fp, 2> public_numerators(const PubKey& pk, const Cipher& cipher) {
    std::array<Fp, 2> out{fp_from_u64(0), fp_from_u64(0)};
    for (const auto& edge : cipher.E) {
        if (edge.layer_id >= out.size()) throw std::runtime_error("unexpected layer");
        Fp term = fp_mul(edge.w[0], pk.powg_B[edge.idx]);
        out[edge.layer_id] = edge.ch == SGN_P ? fp_add(out[edge.layer_id], term)
                                                    : fp_sub(out[edge.layer_id], term);
    }
    return out;
}

static Fp quotient_abs_product(const Fp& a, const Fp& b) {
    uint64_t w[4] = {};
    const uint64_t av[2] = {a.lo, a.hi};
    const uint64_t bv[2] = {b.lo, b.hi};
    for (int i = 0; i < 2; ++i) {
        u128 carry = 0;
        for (int j = 0; j < 2; ++j) {
            u128 value = static_cast<u128>(av[i]) * bv[j] + w[i + j] + carry;
            w[i + j] = static_cast<uint64_t>(value);
            carry = value >> 64;
        }
        w[i + 2] += static_cast<uint64_t>(carry);
    }

    const uint64_t low_lo = w[0];
    const uint64_t low_hi = w[1] & MASK63;
    uint64_t high_lo = (w[1] >> 63) | (w[2] << 1);
    uint64_t high_hi = (w[2] >> 63) | (w[3] << 1);

    u128 sum_lo = static_cast<u128>(low_lo) + high_lo;
    uint64_t sum_hi = low_hi + high_hi + static_cast<uint64_t>(sum_lo >> 64);
    const bool extra = sum_hi > MASK63 ||
                       (sum_hi == MASK63 && static_cast<uint64_t>(sum_lo) == UINT64_MAX);
    if (extra && ++high_lo == 0) ++high_hi;
    return fp_from_words(high_lo, high_hi);
}

static Scalar signed_scalar(const Fp& magnitude, bool negative) {
    Scalar out = sc_from_fp(magnitude);
    return negative ? sc_neg(out) : out;
}

static Scalar small_signed(int value) {
    Scalar out = sc_from_fp(fp_from_u64(static_cast<uint64_t>(value < 0 ? -value : value)));
    return value < 0 ? sc_neg(out) : out;
}

int main() {
    Params params;
    params.noise_entropy_bits = 128.0;
    uint8_t wallet[32];
    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) {
        wallet[i] = static_cast<uint8_t>(0x20 + i);
        seed[i] = static_cast<uint8_t>(i);
    }

    PubKey pk;
    SecKey sk;
    keygen_from_seed(params, pk, sk, wallet);
    const Fp value = fp_from_u64(313);
    Cipher cipher = enc_value_depth_seeded(pk, sk, value.lo, 2, seed);
    if (cipher.L.size() != 2 || cipher.slots != 1) throw std::runtime_error("wrapper shape");
    if (dec_value(pk, sk, cipher).lo != value.lo) throw std::runtime_error("decrypt mismatch");

    const auto numerators = public_numerators(pk, cipher);
    std::array<Fp, 2> inverses;
    std::array<Scalar, 2> rhos;
    Scalar g_coefficient = sc_zero();
    Scalar blind_coefficient = sc_zero();
    Scalar quotient = sc_zero();
    Scalar residue = sc_neg(sc_from_fp_signed(value));
    RistrettoPoint combined = rist_identity();

    for (size_t i = 0; i < 2; ++i) {
        Fp r = prf_R(pk, sk, cipher.L[i].seed);
        inverses[i] = fp_inv(r);
        rhos[i] = rho_for(sk, cipher.L[i]);

        Fp plain_part = fp_mul(numerators[i], inverses[i]);
        g_coefficient = sc_add(g_coefficient,
                               sc_mul(sc_from_fp(numerators[i]), sc_from_fp_signed(inverses[i])));
        blind_coefficient = sc_add(blind_coefficient,
                                   sc_mul(sc_from_fp(numerators[i]), rhos[i]));
        combined = rist_add(combined,
                            rist_scalarmul(cipher.L[i].PC[0], sc_from_fp(numerators[i])));

        const bool negative = (inverses[i].hi & (uint64_t{1} << 62)) != 0;
        const Fp magnitude = negative ? fp_neg(inverses[i]) : inverses[i];
        quotient = sc_add(quotient, signed_scalar(quotient_abs_product(numerators[i], magnitude), negative));
        residue = sc_add(residue, signed_scalar(fp_mul(numerators[i], magnitude), negative));

        RistrettoPoint opened = rist_sub(cipher.L[i].PC[0], rist_scalarmul(rist_H(), rhos[i]));
        if (opened != rist_basemul(sc_from_fp_signed(inverses[i])))
            throw std::runtime_error("PC opening mismatch");
        if (i == 0 && plain_part.lo == value.lo && plain_part.hi == value.hi)
            throw std::runtime_error("unexpected unwrapped first layer");
    }

    Fp recovered = fp_add(fp_mul(numerators[0], inverses[0]),
                          fp_mul(numerators[1], inverses[1]));
    if (recovered.lo != value.lo || recovered.hi != value.hi)
        throw std::runtime_error("field wrapper identity mismatch");

    const Scalar p_scalar{{UINT64_MAX, MASK63, 0, 0}};
    int residue_carry = 99;
    for (int candidate = -3; candidate <= 3; ++candidate) {
        if (scalar_eq(residue, sc_mul(p_scalar, small_signed(candidate)))) {
            residue_carry = candidate;
            break;
        }
    }
    if (residue_carry == 99) throw std::runtime_error("carry bound mismatch");
    quotient = sc_add(quotient, small_signed(residue_carry));

    combined = rist_sub(combined, rist_scalarmul(rist_H(), blind_coefficient));
    combined = rist_sub(combined, rist_basemul(sc_from_fp_signed(value)));
    const Scalar direct = sc_sub(g_coefficient, sc_from_fp_signed(value));
    if (!scalar_eq(direct, sc_mul(p_scalar, quotient)))
        throw std::runtime_error("scalar carry identity mismatch");
    if (combined != rist_basemul(sc_mul(p_scalar, quotient)))
        throw std::runtime_error("joint point identity mismatch");

    std::printf("decrypt=PASS\n");
    std::printf("layer_numerator_identity=PASS\n");
    std::printf("pc_opening=PASS\n");
    std::printf("residue_carry=%d\n", residue_carry);
    std::printf("joint_point_identity=PASS\n");
    std::printf("verdict=CORRECTED_IDENTITY_HAS_BOUNDED_CARRY\n");
}
