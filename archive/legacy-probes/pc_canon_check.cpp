// ponytail: active PC canonicity + issue #503 repro
#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <fstream>
#include <iostream>
#include <array>
#include <cstring>
#include <cstdio>
using namespace pvac;

static std::vector<uint8_t> rd(const char* p) {
    std::ifstream in(p, std::ios::binary);
    in.seekg(0, std::ios::end);
    auto n = in.tellg();
    in.seekg(0);
    std::vector<uint8_t> d((size_t)n);
    in.read((char*)d.data(), (std::streamsize)n);
    return d;
}

static constexpr std::array<uint8_t, 16> MAG = {
    'O', 'C', 'T', 'R', 'A', '-', 'H', 'F', 'H', 'E', '-', 'B', 'T', 'Y', '0', '2'};

static uint64_t tu64(const std::vector<uint8_t>& in, size_t& pos) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)in[pos++] << (8 * i);
    return v;
}

int main() {
    auto pkb = rd("hfhe-challenge@0d08e96/pk.bin");
    auto ctb = rd("hfhe-challenge@0d08e96/secret.ct");
    size_t pos = MAG.size();
    uint64_t count = tu64(ctb, pos);
    int total = 0, hi = 0, reenc_mismatch = 0, decode_fail = 0;

    auto check = [&](const RistrettoPoint& pt, const char* name) {
        total++;
        if (pt.data()[31] & 0x80) {
            hi++;
            std::cout << "HI " << name << "\n";
        }
        ExtPoint P;
        bool ok = rist_decode(P, pt);
        if (!ok) {
            decode_fail++;
            std::cout << "DECODE_FAIL " << name << "\n";
            return;
        }
        auto re = rist_encode(P);
        if (std::memcmp(re.data(), pt.data(), 32) != 0) {
            reenc_mismatch++;
            std::cout << "REENC_MISMATCH " << name << "\n";
        }
    };

    check(rist_G(), "G");
    auto H = rist_H();
    check(H, "H");

    for (uint64_t i = 0; i < count; i++) {
        uint64_t n = tu64(ctb, pos);
        auto C = pvac_ser::deserialize_cipher(ctb.data() + pos, n);
        pos += n;
        for (size_t l = 0; l < C.L.size(); l++) {
            for (size_t j = 0; j < C.L[l].PC.size(); j++) {
                char name[40];
                std::snprintf(name, sizeof(name), "C%lluL%zuP%zu",
                              (unsigned long long)i, l, j);
                check(C.L[l].PC[j], name);
            }
        }
    }

    RistrettoPoint Hhi = H;
    Hhi.data()[31] |= 0x80;
    ExtPoint P0, P1;
    bool ok0 = rist_decode(P0, H);
    bool ok1 = rist_decode(P1, Hhi);
    auto e0 = rist_encode(P0);
    auto e1 = rist_encode(P1);
    bool same = ok1 && std::memcmp(e0.data(), e1.data(), 32) == 0;
    std::cout << "issue_repro noncanon_accepted=" << ok1
              << " same_point=" << same << "\n";
    std::cout << "SUMMARY total=" << total << " hi_bit=" << hi
              << " decode_fail=" << decode_fail
              << " reenc_mismatch=" << reenc_mismatch << "\n";
    return (hi || decode_fail || reenc_mismatch) ? 1 : 0;
}
