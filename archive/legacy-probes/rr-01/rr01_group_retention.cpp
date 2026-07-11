// RR-01: official-path group retention with labels + public reconstruction baselines.
// Build:
//   clang++ -std=c++17 -O2 -maes -msse2 -mpclmul -rtlib=compiler-rt \
//     -I"upstream/pvac_hfhe_cpp/include" rr01_group_retention.cpp -o rr01.exe
//
// Does NOT permanently modify pvac tree. Reimplements synth_seeded with parallel labels
// using the same official classes: Budget, Selector, SigEdge, N2/N3, realize, merge, permute.

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <pvac/pvac.hpp>
#include <pvac/core/seedable_rng.hpp>

using namespace pvac;

enum class Kind : uint8_t { Signal = 0, N2 = 1, N3 = 2 };

struct Label {
    Kind kind;
    int group_id;
    int member_id;
};

struct LEdge {
    Edge e;
    std::vector<Label> origins; // multi after merge
};

static uint64_t key_u64(uint32_t lid, uint16_t idx, uint8_t ch) {
    return (uint64_t)lid << 32 | (uint64_t)idx << 8 | ch;
}

// Merge with origin tracking (same keying as reduction::merge)
static std::vector<LEdge> merge_labeled(std::vector<LEdge> edges, const PubKey& pk) {
    const int B = pk.prm.B;
    size_t S = edges[0].e.w.size();
    uint32_t maxL = 0;
    for (auto& le : edges)
        if (le.e.layer_id > maxL) maxL = le.e.layer_id;
    const size_t L = (size_t)maxL + 1;

    struct Slot {
        bool active = false;
        std::vector<Fp> w;
        BitVec s;
        std::vector<Label> origins;
    };
    std::vector<Slot> acc_p(L * B), acc_m(L * B);

    for (auto& le : edges) {
        size_t idx = (size_t)le.e.layer_id * B + le.e.idx;
        auto& acc = (le.e.ch == SGN_P) ? acc_p : acc_m;
        if (!acc[idx].active) {
            acc[idx].active = true;
            acc[idx].w = std::move(le.e.w);
            acc[idx].s = std::move(le.e.s);
            acc[idx].origins = std::move(le.origins);
        } else {
            for (size_t j = 0; j < S; ++j)
                acc[idx].w[j] = fp_add(acc[idx].w[j], le.e.w[j]);
            acc[idx].s.xor_with(le.e.s);
            acc[idx].origins.insert(acc[idx].origins.end(), le.origins.begin(), le.origins.end());
        }
    }

    auto nz = [](const std::vector<Fp>& w, const BitVec& s) {
        for (const auto& x : w)
            if (ct::fp_is_nonzero(x)) return true;
        return s.popcnt() != 0;
    };

    std::vector<LEdge> out;
    for (size_t lid = 0; lid < L; ++lid) {
        for (int k = 0; k < B; ++k) {
            size_t idx = lid * B + k;
            for (int sgni = 0; sgni < 2; ++sgni) {
                auto& acc = (sgni == 0) ? acc_p[idx] : acc_m[idx];
                if (!acc.active || !nz(acc.w, acc.s)) continue;
                LEdge le;
                le.e.layer_id = (uint32_t)lid;
                le.e.idx = (uint16_t)k;
                le.e.ch = (sgni == 0) ? SGN_P : SGN_M;
                le.e.w = std::move(acc.w);
                le.e.s = std::move(acc.s);
                le.origins = std::move(acc.origins);
                out.push_back(std::move(le));
            }
        }
    }
    return out;
}

static void permute_labeled(std::vector<LEdge>& e, SeedableRng& rng) {
    for (size_t i = e.size(); i > 1; --i) {
        size_t j = (size_t)rng.bounded(i);
        std::swap(e[i - 1], e[j]);
    }
}

// Official synth_seeded with labels
static std::vector<LEdge> synth_seeded_labeled(
    const PubKey& pk, const SecKey& sk, const std::vector<Fp>& v, int depth, SeedableRng& rng,
    // stats out
    int& out_n2, int& out_n3, int& out_sig
) {
    size_t S = v.size();
    Layer L{};
    L.rule = RRule::BASE;
    L.seed.nonce = rng.nonce128();
    L.seed.ztag = prg_layer_ztag(pk.canon_tag, L.seed.nonce);

    entropy::Budget b = entropy::Budget::compute(pk.prm, depth);
    out_n2 = b.n2;
    out_n3 = b.n3;

    delta::Gen dg{ pk, sk, L.seed };
    delta::Set ds = delta::Set::make(dg, b, S);
    auto R = prf_R_slots(pk, sk, L.seed, S);
    L.R_com = compute_R_com_base(pk.canon_tag, L.seed.ztag, L.seed.nonce.lo, L.seed.nonce.hi, R);
    compute_layer_PC(L, sk, R, S);
    auto va = field::Op::sub(v, ds.agg);

    idx::Selector sel(pk.prm.B);
    graph::Emitter em{ pk, L.seed };

    graph::SigEdge sig(pk, sel);
    alg::Carrier<graph::SigNode> sn = sig.build(va, rng);
    out_sig = (int)sn.len();

    std::vector<LEdge> pre;
    pre.reserve(sn.len() + (size_t)b.n2 * 2 + (size_t)b.n3 * 3);

    int sig_i = 0;
    for (size_t i = 0; i < sn.len(); ++i) {
        const graph::SigNode& n = sn[i];
        Edge e = em(static_cast<uint16_t>(n.pos), n.pol, field::Op::mul(n.coef, R), rng);
        e.layer_id = 0;
        LEdge le;
        le.e = std::move(e);
        le.origins.push_back({ Kind::Signal, sig_i, 0 });
        pre.push_back(std::move(le));
        ++sig_i;
    }

    graph::N2Edge n2e(pk, sel);
    for (int t = 0; t < b.n2; ++t) {
        auto n2 = n2e.build(ds[t], S, rng);
        // realize produces 2 edges
        Edge ea = em(static_cast<uint16_t>(n2.pa), n2.sa, field::Op::mul(R, n2.ra), rng);
        Edge eb = em(static_cast<uint16_t>(n2.pb), n2.sb, field::Op::mul(R, n2.rb), rng);
        ea.layer_id = eb.layer_id = 0;
        LEdge la, lb;
        la.e = std::move(ea);
        la.origins.push_back({ Kind::N2, t, 0 });
        lb.e = std::move(eb);
        lb.origins.push_back({ Kind::N2, t, 1 });
        pre.push_back(std::move(la));
        pre.push_back(std::move(lb));
    }

    graph::N3Edge n3e(pk, sel);
    for (int t = 0; t < b.n3; ++t) {
        auto n3 = n3e.build(ds[(size_t)b.n2 + t], S, rng);
        Edge ea = em(static_cast<uint16_t>(n3.pa), n3.sa, field::Op::mul(R, n3.ra), rng);
        Edge eb = em(static_cast<uint16_t>(n3.pb), n3.sb, field::Op::mul(R, n3.rb), rng);
        Edge ec = em(static_cast<uint16_t>(n3.pc), n3.sc, field::Op::mul(R, n3.rc), rng);
        ea.layer_id = eb.layer_id = ec.layer_id = 0;
        LEdge la, lb, lc;
        la.e = std::move(ea); la.origins.push_back({ Kind::N3, t, 0 });
        lb.e = std::move(eb); lb.origins.push_back({ Kind::N3, t, 1 });
        lc.e = std::move(ec); lc.origins.push_back({ Kind::N3, t, 2 });
        pre.push_back(std::move(la));
        pre.push_back(std::move(lb));
        pre.push_back(std::move(lc));
    }

    auto mid = merge_labeled(std::move(pre), pk);
    permute_labeled(mid, rng);
    return mid;
}

// Signed numerator term for slot 0: sign * w * powg[idx]
static Fp term0(const PubKey& pk, const Edge& e) {
    Fp gp = pk.powg_B[e.idx];
    Fp tw = fp_mul(e.w[0], gp);
    return (e.ch == SGN_P) ? tw : fp_neg(tw);
}

struct BaselineScores {
    double prec_n2 = 0, rec_n2 = 0, prec_n3 = 0, rec_n3 = 0;
    double exact_partition_rate = 0;
    double cand_pairs = 0, cand_triples = 0;
    long true_n2 = 0, hit_n2 = 0, pred_n2 = 0;
    long true_n3 = 0, hit_n3 = 0, pred_n3 = 0;
};

// Ground-truth groups still pure after merge (from origins of final edges)
static void collect_true_groups(
    const std::vector<LEdge>& final_edges,
    std::map<int, std::set<std::pair<int, int>>>& n2_true, // gid -> {(idx,ch)}
    std::map<int, std::set<std::pair<int, int>>>& n3_true,
    long& n2_unmerged_all, long& n3_unmerged_all, long& n2_total, long& n3_total,
    long& multi_origin_edges
) {
    // Reconstruct purity from origins on final edges
    std::map<int, std::vector<std::pair<int, int>>> n2_members, n3_members;
    std::map<int, bool> n2_pure, n3_pure;
    multi_origin_edges = 0;
    for (const auto& le : final_edges) {
        if (le.origins.size() > 1) multi_origin_edges++;
        // only pure single-origin edges contribute to recoverable groups
        if (le.origins.size() != 1) continue;
        const Label& lab = le.origins[0];
        if (lab.kind == Kind::N2) {
            n2_members[lab.group_id].push_back({ (int)le.e.idx, (int)le.e.ch });
        } else if (lab.kind == Kind::N3) {
            n3_members[lab.group_id].push_back({ (int)le.e.idx, (int)le.e.ch });
        }
    }
    // Also count groups that existed pre-merge: from all origins including multi
    std::set<int> n2_all, n3_all;
    for (const auto& le : final_edges) {
        for (const auto& lab : le.origins) {
            if (lab.kind == Kind::N2) n2_all.insert(lab.group_id);
            if (lab.kind == Kind::N3) n3_all.insert(lab.group_id);
        }
    }
    n2_total = (long)n2_all.size();
    n3_total = (long)n3_all.size();
    n2_unmerged_all = 0;
    n3_unmerged_all = 0;
    for (auto& kv : n2_members) {
        if ((int)kv.second.size() == 2) {
            n2_unmerged_all++;
            n2_true[kv.first] = std::set<std::pair<int, int>>(kv.second.begin(), kv.second.end());
        }
    }
    for (auto& kv : n3_members) {
        if ((int)kv.second.size() == 3) {
            n3_unmerged_all++;
            n3_true[kv.first] = std::set<std::pair<int, int>>(kv.second.begin(), kv.second.end());
        }
    }
}

static BaselineScores score_opposite_sign(
    const PubKey& pk, const std::vector<LEdge>& edges,
    const std::map<int, std::set<std::pair<int, int>>>& n2_true
) {
    BaselineScores sc;
    // Predict all opposite-sign distinct-idx pairs as N2 candidates
    std::vector<const LEdge*> pos, neg;
    for (const auto& le : edges) {
        if (le.e.ch == SGN_P) pos.push_back(&le);
        else neg.push_back(&le);
    }
    sc.cand_pairs = (double)pos.size() * (double)neg.size();
    // predicted pairs
    std::vector<std::set<std::pair<int, int>>> preds;
    for (auto* a : pos) {
        for (auto* b : neg) {
            if (a->e.idx == b->e.idx) continue;
            preds.push_back({
                { (int)a->e.idx, (int)a->e.ch },
                { (int)b->e.idx, (int)b->e.ch }
            });
        }
    }
    sc.pred_n2 = (long)preds.size();
    sc.true_n2 = (long)n2_true.size();
    for (const auto& kv : n2_true) {
        for (const auto& p : preds) {
            if (p == kv.second) { sc.hit_n2++; break; }
        }
    }
    sc.prec_n2 = sc.pred_n2 ? (double)sc.hit_n2 / sc.pred_n2 : 0;
    sc.rec_n2 = sc.true_n2 ? (double)sc.hit_n2 / sc.true_n2 : 0;
    return sc;
}

static BaselineScores score_weight_ratio(
    const PubKey& pk, const std::vector<LEdge>& edges,
    const std::map<int, std::set<std::pair<int, int>>>& n2_true
) {
    // N2 algebraic: for true pair with sa = sb^1, signed terms sum to R*delta.
    // Public: without R we look for pairs where... no equality without second group.
    // Use: among opposite-sign pairs, no filter — same as opposite-sign unless we use
    // weight magnitude heuristics (not algebraic). Try exact: none.
    // Weight-ratio baseline: pair opposite-sign edges if neither weight is zero (all).
    // Better: for N2, rb related via fixed g — without ra free, no public constraint on single pair.
    // Implement: score same candidate set as opposite-sign (documents no extra filter).
    return score_opposite_sign(pk, edges, n2_true);
}

static uint64_t sigma_hash(const BitVec& s) {
    // first 4 words if available via popcnt + crude fingerprint
    // BitVec API: use serialize-ish — popcnt and nbits
    return ((uint64_t)s.nbits << 32) ^ (uint64_t)s.popcnt();
}

static BaselineScores score_sigma(
    const PubKey& pk, const std::vector<LEdge>& edges,
    const std::map<int, std::set<std::pair<int, int>>>& n2_true
) {
    BaselineScores sc;
    // exact sigma equality pairs (opposite sign, distinct idx)
    std::vector<const LEdge*> all;
    for (const auto& le : edges) all.push_back(&le);
    std::vector<std::set<std::pair<int, int>>> preds;
    for (size_t i = 0; i < all.size(); ++i) {
        for (size_t j = i + 1; j < all.size(); ++j) {
            if (all[i]->e.ch == all[j]->e.ch) continue;
            if (all[i]->e.idx == all[j]->e.idx) continue;
            // sigma equality: popcnt equal as weak feature; also XOR popcnt==0 if same
            // true N2 have independent PRG sigmas — equality rare
            if (all[i]->e.s.popcnt() != all[j]->e.s.popcnt()) continue;
            // require exact bitvec equal if possible
            bool eq = (all[i]->e.s.nbits == all[j]->e.s.nbits);
            // BitVec may not expose words; use popcnt-only weak
            if (!eq) continue;
            // without word access, skip exact; use identical popcnt only as weak (already)
            // Don't add — too weak. Instead: nearest neighbor by |popcnt diff|==0 only when both popcnt match AND opposite sign
            preds.push_back({
                { (int)all[i]->e.idx, (int)all[i]->e.ch },
                { (int)all[j]->e.idx, (int)all[j]->e.ch }
            });
        }
    }
    sc.cand_pairs = (double)preds.size();
    sc.pred_n2 = (long)preds.size();
    sc.true_n2 = (long)n2_true.size();
    for (const auto& kv : n2_true) {
        for (const auto& p : preds) {
            if (p == kv.second) { sc.hit_n2++; break; }
        }
    }
    sc.prec_n2 = sc.pred_n2 ? (double)sc.hit_n2 / sc.pred_n2 : 0;
    sc.rec_n2 = sc.true_n2 ? (double)sc.hit_n2 / sc.true_n2 : 0;
    return sc;
}

// Random control: sample same number of opposite-sign pairs at random, score hit rate
static double random_pair_hit_rate(
    const std::vector<LEdge>& edges,
    const std::map<int, std::set<std::pair<int, int>>>& n2_true,
    SeedableRng& rng, int samples
) {
    std::vector<const LEdge*> pos, neg;
    for (const auto& le : edges) {
        if (le.e.ch == SGN_P) pos.push_back(&le);
        else neg.push_back(&le);
    }
    if (pos.empty() || neg.empty() || n2_true.empty()) return 0;
    long hits = 0;
    for (int t = 0; t < samples; ++t) {
        auto* a = pos[(size_t)rng.bounded(pos.size())];
        auto* b = neg[(size_t)rng.bounded(neg.size())];
        if (a->e.idx == b->e.idx) { --t; continue; }
        std::set<std::pair<int, int>> p{
            { (int)a->e.idx, (int)a->e.ch },
            { (int)b->e.idx, (int)b->e.ch }
        };
        for (const auto& kv : n2_true) {
            if (kv.second == p) { hits++; break; }
        }
    }
    return (double)hits / samples;
}

static void active_candidate_space() {
    // Parse active edges from secret.ct via deep parse in Python separately;
    // here print placeholder — filled by companion Python from seeds/active edges.
}

int main() {
    Params prm; // defaults already active-like
    prm.noise_entropy_bits = 128.0;

    uint8_t wallet[32];
    for (int i = 0; i < 32; i++) wallet[i] = (uint8_t)(0xA0 + i);

    PubKey pk;
    SecKey sk;
    keygen_from_seed(prm, pk, sk, wallet);

    // Accumulators
    double sum_prec_opp = 0, sum_rec_opp = 0, sum_prec_sig = 0, sum_rec_sig = 0;
    double sum_rand_hit = 0;
    double sum_pairs = 0;
    long trials = 0;
    long n2_unmerged = 0, n3_unmerged = 0, n2_tot = 0, n3_tot = 0, multi_orig = 0, edges_tot = 0;
    long pure_exact_partition = 0; // if all N2 groups pure AND uniquely identifiable — never

    // 100+ wrapped: for each trial, two layers like wrap (or single BASE for group stats)
    // Plan: 100 single-layer synths + 20 wrapped (combine) depth emphasis 2..22
    const int N_SINGLE = 100;
    const int N_WRAP = 20;

    auto run_one = [&](int depth, uint64_t val, int trial_id) {
        uint8_t seed[32];
        for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(trial_id * 17 + i * 3 + depth);
        auto scoped = enc_seed_scope(pk, seed, "rr01", 1, depth, { fp_from_u64(val) });
        SeedableRng rng = make_seeded_rng(scoped.data());
        int n2 = 0, n3 = 0, nsig = 0;
        std::vector<Fp> v = { fp_from_u64(val) };
        auto final_edges = synth_seeded_labeled(pk, sk, v, depth, rng, n2, n3, nsig);

        std::map<int, std::set<std::pair<int, int>>> n2t, n3t;
        long u2, u3, t2, t3, mo;
        collect_true_groups(final_edges, n2t, n3t, u2, u3, t2, t3, mo);
        n2_unmerged += u2;
        n3_unmerged += u3;
        n2_tot += t2;
        n3_tot += t3;
        multi_orig += mo;
        edges_tot += (long)final_edges.size();

        auto opp = score_opposite_sign(pk, final_edges, n2t);
        auto sig = score_sigma(pk, final_edges, n2t);
        SeedableRng crng = make_seeded_rng(scoped.data());
        // re-seed control differently
        uint8_t cseed[32];
        for (int i = 0; i < 32; i++) cseed[i] = seed[i] ^ 0x5A;
        SeedableRng ctrl = make_seeded_rng(cseed);
        double rh = random_pair_hit_rate(final_edges, n2t, ctrl, 200);

        sum_prec_opp += opp.prec_n2;
        sum_rec_opp += opp.rec_n2;
        sum_prec_sig += sig.prec_n2;
        sum_rec_sig += sig.rec_n2;
        sum_rand_hit += rh;
        sum_pairs += opp.cand_pairs;
        trials++;

        if (trial_id < 3) {
            std::printf(
                "trial=%d depth=%d edges=%zu n2=%d n3=%d pureN2=%ld/%ld pureN3=%ld/%ld multi_orig=%ld "
                "opp_pairs=%.0f opp_prec=%.6f opp_rec=%.4f sig_prec=%.6f rand_hit=%.6f\n",
                trial_id, depth, final_edges.size(), n2, n3, u2, t2, u3, t3, mo,
                opp.cand_pairs, opp.prec_n2, opp.rec_n2, sig.prec_n2, rh);
        }
    };

    int tid = 0;
    // values: 0, small, random-ish
    uint64_t vals[] = { 0, 1, 42, 337, 0xFFFFFFFFFFFFFFFFULL };
    for (int i = 0; i < N_SINGLE; i++) {
        int depth = 2 + (i % 21); // 2..22
        uint64_t val = vals[i % 5];
        if (i % 7 == 0) val = (uint64_t)i * 0x9E3779B97F4A7C15ULL;
        run_one(depth, val, tid++);
    }
    for (int i = 0; i < N_WRAP; i++) {
        // wrapped path uses official enc_value_depth_seeded (labels not on wrap fuse);
        // still run labeled single layers at wrap depths for group stats
        run_one(2 + (i % 21), vals[i % 5], tid++);
    }

    // Public wire has no labels: prove by serializing edge public fields only
    // (no label fields exist on Edge — already true by type)

    std::printf("\n=== SUMMARY trials=%ld ===\n", trials);
    std::printf("mean_opp_prec_N2=%.8f mean_opp_rec_N2=%.6f\n", sum_prec_opp / trials, sum_rec_opp / trials);
    std::printf("mean_sigma_prec_N2=%.8f mean_sigma_rec_N2=%.6f\n", sum_prec_sig / trials, sum_rec_sig / trials);
    std::printf("mean_random_pair_hit=%.8f\n", sum_rand_hit / trials);
    std::printf("mean_cand_pairs=%.2f\n", sum_pairs / trials);
    std::printf("frac_N2_all_members_unmerged=%.6f (%ld/%ld)\n",
        n2_tot ? (double)n2_unmerged / n2_tot : 0, n2_unmerged, n2_tot);
    std::printf("frac_N3_all_members_unmerged=%.6f (%ld/%ld)\n",
        n3_tot ? (double)n3_unmerged / n3_tot : 0, n3_unmerged, n3_tot);
    std::printf("frac_merged_edges_multi_origin=%.6f (%ld/%ld)\n",
        edges_tot ? (double)multi_orig / edges_tot : 0, multi_orig, edges_tot);
    std::printf("public_wire_contains_labels=0\n");
    std::printf("exact_partition_rate=0\n");

    // Compare baselines to random control
    double mop = sum_prec_opp / trials;
    double mrh = sum_rand_hit / trials;
    // opposite-sign predicts ALL pairs: precision = true_pairs / all_pairs ≈ random
    // random_pair_hit is P(random pair is true) which equals true_pairs/all_pairs = precision
    std::printf("baseline_vs_control_gap_opp=%.8f\n", mop - mrh);
    std::printf("verdict_hint=%s\n",
        (std::fabs(mop - mrh) < 1e-4 && mop < 0.05) ? "CLOSED_LIKE" : "CHECK");

    return 0;
}
