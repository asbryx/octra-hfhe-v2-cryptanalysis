#include <pvac/pvac.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <vector>

using namespace pvac;

struct Baby {
    RistrettoPoint point;
    uint32_t scalar;
};

static Scalar scalar_u64(uint64_t value) {
    return Scalar{{value, 0, 0, 0}};
}

static std::vector<Baby> baby_table(uint64_t width, const ExtPoint& generator) {
    std::vector<Baby> table;
    table.reserve(static_cast<size_t>(width));
    ExtPoint point = ext_identity();
    for (uint64_t value = 0; value < width; ++value) {
        table.push_back({rist_encode(point), static_cast<uint32_t>(value)});
        point = ext_add(point, generator);
    }
    std::sort(table.begin(), table.end(), [](const Baby& a, const Baby& b) {
        return a.point < b.point;
    });
    return table;
}

static bool lookup(const std::vector<Baby>& table, const RistrettoPoint& point, uint32_t& scalar) {
    auto it = std::lower_bound(table.begin(), table.end(), point,
        [](const Baby& baby, const RistrettoPoint& target) { return baby.point < target; });
    if (it == table.end() || it->point != point) return false;
    scalar = it->scalar;
    return true;
}

static bool bounded_dlp(const RistrettoPoint& target, uint64_t bound, uint64_t width,
                        const std::vector<Baby>& table, const ExtPoint& generator,
                        uint64_t& answer) {
    ExtPoint current = rist_decode_or_throw(target);
    ExtPoint step = ext_neg(ext_scalarmul(generator, scalar_u64(width)));
    const uint64_t giant_count = (bound + width - 1) / width;
    for (uint64_t giant = 0; giant < giant_count; ++giant) {
        uint32_t baby = 0;
        if (lookup(table, rist_encode(current), baby)) {
            const uint64_t candidate = giant * width + baby;
            if (candidate < bound && rist_basemul(scalar_u64(candidate)) == target) {
                answer = candidate;
                return true;
            }
        }
        current = ext_add(current, step);
    }
    return false;
}

static void print_hex(const RistrettoPoint& point) {
    for (uint8_t byte : point) std::printf("%02x", byte);
}

int main(int argc, char** argv) {
    const unsigned bits = argc == 2 ? static_cast<unsigned>(std::stoul(argv[1])) : 40;
    if (bits == 0 || bits > 48) throw std::runtime_error("bits must be 1..48");
    const uint64_t bound = uint64_t{1} << bits;
    const uint64_t width = uint64_t{1} << ((bits + 1) / 2);

    const auto started = std::chrono::steady_clock::now();
    const ExtPoint generator = rist_decode_or_throw(rist_G());
    const auto table = baby_table(width, generator);

    // ponytail: one self-check exercises both baby lookup and at least one giant step.
    const uint64_t known = width * 17 + 12345;
    if (known >= bound) throw std::runtime_error("self-check bound too small");
    uint64_t recovered = 0;
    if (!bounded_dlp(rist_basemul(scalar_u64(known)), bound, width, table, generator, recovered) ||
        recovered != known)
        throw std::runtime_error("self-check failed");

    const RistrettoPoint h = rist_H();
    const RistrettoPoint neg_h = rist_encode(ext_neg(rist_decode_or_throw(h)));
    uint64_t positive = 0, negative = 0;
    const bool found_positive = bounded_dlp(h, bound, width, table, generator, positive);
    const bool found_negative = bounded_dlp(neg_h, bound, width, table, generator, negative);
    const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();

    std::printf("{\n  \"bits\": %u,\n  \"bound\": %llu,\n  \"baby_width\": %llu,\n",
                bits, static_cast<unsigned long long>(bound), static_cast<unsigned long long>(width));
    std::printf("  \"self_check\": \"PASS\",\n  \"H_hex\": \"");
    print_hex(h);
    std::printf("\",\n  \"positive_found\": %s,\n  \"negative_found\": %s,\n",
                found_positive ? "true" : "false", found_negative ? "true" : "false");
    if (found_positive) std::printf("  \"positive_scalar\": %llu,\n", static_cast<unsigned long long>(positive));
    if (found_negative) std::printf("  \"negative_magnitude\": %llu,\n", static_cast<unsigned long long>(negative));
    std::printf("  \"seconds\": %.6f,\n  \"verdict\": \"%s\"\n}\n", seconds,
                (found_positive || found_negative) ? "SMALL_RELATION_FOUND" : "NO_SIGNED_RELATION_IN_BOUND");
    return (found_positive || found_negative) ? 3 : 0;
}
