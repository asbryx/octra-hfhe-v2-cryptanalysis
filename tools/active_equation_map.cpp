#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"

#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace pvac;

static constexpr std::array<uint8_t, 16> MAGIC = {
    'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'
};

static std::vector<uint8_t> read_file(const char* path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error(std::string("open ") + path);
    in.seekg(0, std::ios::end);
    const auto size = in.tellg();
    if (size < 0) throw std::runtime_error("file size");
    in.seekg(0);
    std::vector<uint8_t> out(static_cast<size_t>(size));
    if (!out.empty()) in.read(reinterpret_cast<char*>(out.data()), size);
    if (!in) throw std::runtime_error("file read");
    return out;
}

static uint64_t take_u64(const std::vector<uint8_t>& data, size_t& pos) {
    if (pos + 8 > data.size()) throw std::runtime_error("truncated bundle");
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) value |= static_cast<uint64_t>(data[pos++]) << (8 * i);
    return value;
}

static std::vector<Cipher> load_bundle(const char* path) {
    const auto data = read_file(path);
    if (data.size() < MAGIC.size() || !std::equal(MAGIC.begin(), MAGIC.end(), data.begin()))
        throw std::runtime_error("bad bundle magic");
    size_t pos = MAGIC.size();
    const uint64_t count = take_u64(data, pos);
    if (count == 0 || count > 1024) throw std::runtime_error("bad cipher count");
    std::vector<Cipher> out;
    out.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        const uint64_t size = take_u64(data, pos);
        if (size == 0 || size > data.size() - pos) throw std::runtime_error("bad cipher size");
        out.push_back(pvac_ser::deserialize_cipher(data.data() + pos, static_cast<size_t>(size)));
        pos += static_cast<size_t>(size);
    }
    if (pos != data.size()) throw std::runtime_error("trailing bundle bytes");
    return out;
}

static Fp numerator(const PubKey& pk, const Cipher& cipher, uint32_t layer) {
    Fp out = fp_from_u64(0);
    for (const auto& edge : cipher.E) {
        if (edge.layer_id != layer) continue;
        if (edge.w.size() != 1 || edge.idx >= pk.powg_B.size())
            throw std::runtime_error("edge shape");
        const Fp term = fp_mul(edge.w[0], pk.powg_B[edge.idx]);
        out = edge.ch == SGN_P ? fp_add(out, term) : fp_sub(out, term);
    }
    return out;
}

static std::string fp_hex(const Fp& value) {
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(16) << value.hi
        << std::setw(16) << value.lo;
    return out.str();
}

static std::string u64_hex(uint64_t value) {
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(16) << value;
    return out.str();
}

static std::string bytes_hex(const uint8_t* data, size_t size) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) out << std::setw(2) << static_cast<unsigned>(data[i]);
    return out.str();
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: active_equation_map <pk.bin> <secret.ct>\n";
        return 2;
    }
    try {
        const auto pk_data = read_file(argv[1]);
        const PubKey pk = pvac_ser::deserialize_pubkey(pk_data.data(), pk_data.size());
        const auto ciphers = load_bundle(argv[2]);
        if (ciphers.size() != 22) throw std::runtime_error("expected 22 ciphers");

        std::set<std::pair<uint64_t, uint64_t>> rho_inputs;
        std::set<std::array<uint8_t, 32>> pc_points;
        size_t nonzero_coefficients = 0;
        bool first = true;

        std::cout << "{\n  \"schema\": 1,\n  \"objects\": [\n";
        for (size_t ci = 0; ci < ciphers.size(); ++ci) {
            const Cipher& cipher = ciphers[ci];
            if (cipher.slots != 1 || cipher.L.size() != 2 || cipher.c0.size() != 1 ||
                cipher.c0[0].lo != 0 || cipher.c0[0].hi != 0)
                throw std::runtime_error("unexpected wrapped shape");
            if (!first) std::cout << ",\n";
            first = false;
            std::cout << "    {\"cipher\": " << ci << ", \"layers\": [";
            for (size_t li = 0; li < 2; ++li) {
                const Layer& layer = cipher.L[li];
                if (layer.rule != RRule::BASE || layer.PC.size() != 1)
                    throw std::runtime_error("unexpected layer shape");
                const Fp t = numerator(pk, cipher, static_cast<uint32_t>(li));
                if (t.lo == 0 && t.hi == 0) throw std::runtime_error("zero rho coefficient");
                ++nonzero_coefficients;
                if (!rho_inputs.emplace(layer.seed.nonce.lo, layer.seed.nonce.hi).second)
                    throw std::runtime_error("reused rho input");
                pc_points.insert(layer.PC[0]);
                if (li) std::cout << ",";
                std::cout << "{\"layer\": " << li
                          << ", \"T_hex\": \"" << fp_hex(t)
                          << "\", \"ztag\": " << layer.seed.ztag
                          << ", \"nonce_lo_hex\": \"" << u64_hex(layer.seed.nonce.lo)
                          << "\", \"nonce_hi_hex\": \"" << u64_hex(layer.seed.nonce.hi)
                          << "\", \"PC_hex\": \"" << bytes_hex(layer.PC[0].data(), 32)
                          << "\"}";
            }
            std::cout << "]}";
        }
        std::cout << "\n  ],\n  \"summary\": {\n"
                  << "    \"cipher_count\": " << ciphers.size() << ",\n"
                  << "    \"rho_symbol_count\": " << rho_inputs.size() << ",\n"
                  << "    \"nonzero_rho_coefficients\": " << nonzero_coefficients << ",\n"
                  << "    \"unique_pc_points\": " << pc_points.size() << ",\n"
                  << "    \"rho_matrix_rows\": 22,\n"
                  << "    \"rho_matrix_columns\": 44,\n"
                  << "    \"rho_matrix_row_rank\": 22,\n"
                  << "    \"rho_cancelling_left_kernel_dimension\": 0,\n"
                  << "    \"proof\": \"Each row has two nonzero coefficients on rho symbols not used by any other row; any cancelling row combination forces every row coefficient to zero.\"\n"
                  << "  }\n}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 1;
    }
}
