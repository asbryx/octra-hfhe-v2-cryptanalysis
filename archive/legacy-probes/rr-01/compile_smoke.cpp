#include <cstdio>
#include <chrono>
#include <pvac/pvac.hpp>
#include <pvac/core/seedable_rng.hpp>
using namespace pvac;
int main() {
  Params prm;
  prm.B = 337; prm.m_bits = 8192; prm.n_bits = 16384;
  prm.h_col_wt = 192; prm.x_col_wt = 128; prm.err_wt = 128;
  prm.noise_entropy_bits = 128; prm.tuple2_fraction = 0.55; prm.depth_slope_bits = 16;
  prm.edge_budget = 1200000; prm.lpn_n = 4096; prm.lpn_t = 16384;
  prm.lpn_tau_num = 1; prm.lpn_tau_den = 8;
  uint8_t w[32]; for(int i=0;i<32;i++) w[i]=(uint8_t)(i+1);
  PubKey pk; SecKey sk;
  auto t0=std::chrono::steady_clock::now();
  keygen_from_seed(prm, pk, sk, w);
  auto t1=std::chrono::steady_clock::now();
  double s=std::chrono::duration<double>(t1-t0).count();
  std::printf("keygen_sec=%.3f B=%d m=%d n=%d canon=%llu\n", s, prm.B, prm.m_bits, prm.n_bits, (unsigned long long)pk.canon_tag);
  // one seeded enc depth 2
  uint8_t seed[32]; for(int i=0;i<32;i++) seed[i]=(uint8_t)(100+i);
  auto t2=std::chrono::steady_clock::now();
  Cipher C = enc_value_depth_seeded(pk, sk, 42, 2, seed);
  auto t3=std::chrono::steady_clock::now();
  Fp d = dec_value(pk, sk, C);
  std::printf("enc_sec=%.3f edges=%zu layers=%zu dec_lo=%llu\n",
    std::chrono::duration<double>(t3-t2).count(), C.E.size(), C.L.size(), (unsigned long long)d.lo);
  return 0;
}
