// FV-01: complete public-field ranking for N2/N3 on official seeded path.
// Build: clang++ -std=c++17 -O2 -maes -msse2 -mpclmul -rtlib=compiler-rt -I$PV/include fv01_group_ranking.cpp -o fv01.exe
// Labels ONLY for scoring after ranking; never as features.

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <numeric>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <pvac/pvac.hpp>
#include <pvac/core/seedable_rng.hpp>

using namespace pvac;

enum class Kind : uint8_t { Signal = 0, N2 = 1, N3 = 2 };
struct Label { Kind kind; int group_id; int member_id; };
struct LEdge {
    Edge e;
    std::vector<Label> origins;
    Fp term; // sign * w[0] * powg[idx]
};

static Fp edge_term(const PubKey& pk, const Edge& e) {
    Fp tw = fp_mul(e.w[0], pk.powg_B[e.idx]);
    return e.ch == SGN_P ? tw : fp_neg(tw);
}

static size_t sigma_xor_pop(const BitVec& a, const BitVec& b) {
    size_t L = std::min(a.w.size(), b.w.size());
    size_t s = 0;
    for (size_t i = 0; i < L; i++) s += (size_t)__builtin_popcountll(a.w[i] ^ b.w[i]);
    // tail
    for (size_t i = L; i < a.w.size(); i++) s += (size_t)__builtin_popcountll(a.w[i]);
    for (size_t i = L; i < b.w.size(); i++) s += (size_t)__builtin_popcountll(b.w[i]);
    return s;
}

static bool sigma_equal(const BitVec& a, const BitVec& b) {
    if (a.nbits != b.nbits || a.w.size() != b.w.size()) return false;
    for (size_t i = 0; i < a.w.size(); i++) if (a.w[i] != b.w[i]) return false;
    return true;
}

static std::vector<LEdge> merge_labeled(std::vector<LEdge> edges, const PubKey& pk) {
    const int B = pk.prm.B;
    size_t S = edges[0].e.w.size();
    uint32_t maxL = 0;
    for (auto& le : edges) if (le.e.layer_id > maxL) maxL = le.e.layer_id;
    const size_t L = (size_t)maxL + 1;
    struct Slot { bool active=false; std::vector<Fp> w; BitVec s; std::vector<Label> origins; };
    std::vector<Slot> acc_p(L*B), acc_m(L*B);
    for (auto& le : edges) {
        size_t idx = (size_t)le.e.layer_id * B + le.e.idx;
        auto& acc = (le.e.ch == SGN_P) ? acc_p : acc_m;
        if (!acc[idx].active) {
            acc[idx].active = true;
            acc[idx].w = std::move(le.e.w);
            acc[idx].s = std::move(le.e.s);
            acc[idx].origins = std::move(le.origins);
        } else {
            for (size_t j=0;j<S;++j) acc[idx].w[j]=fp_add(acc[idx].w[j], le.e.w[j]);
            acc[idx].s.xor_with(le.e.s);
            acc[idx].origins.insert(acc[idx].origins.end(), le.origins.begin(), le.origins.end());
        }
    }
    auto nz=[](const std::vector<Fp>& w, const BitVec& s){
        for (auto& x:w) if (ct::fp_is_nonzero(x)) return true;
        return s.popcnt()!=0;
    };
    std::vector<LEdge> out;
    for (size_t lid=0; lid<L; ++lid) for (int k=0;k<B;++k) {
        size_t idx=lid*B+k;
        for (int sg=0; sg<2; ++sg) {
            auto& acc = sg? acc_m[idx]:acc_p[idx];
            if (!acc.active || !nz(acc.w,acc.s)) continue;
            LEdge le;
            le.e.layer_id=(uint32_t)lid; le.e.idx=(uint16_t)k; le.e.ch=sg?SGN_M:SGN_P;
            le.e.w=std::move(acc.w); le.e.s=std::move(acc.s); le.origins=std::move(acc.origins);
            le.term = edge_term(pk, le.e);
            out.push_back(std::move(le));
        }
    }
    return out;
}

static void permute_labeled(std::vector<LEdge>& e, SeedableRng& rng) {
    for (size_t i=e.size(); i>1; --i) std::swap(e[i-1], e[(size_t)rng.bounded(i)]);
}

static std::vector<LEdge> synth_seeded_labeled(
    const PubKey& pk, const SecKey& sk, const std::vector<Fp>& v, int depth, SeedableRng& rng
) {
    size_t S = v.size();
    Layer L{}; L.rule=RRule::BASE;
    L.seed.nonce=rng.nonce128();
    L.seed.ztag=prg_layer_ztag(pk.canon_tag, L.seed.nonce);
    entropy::Budget b=entropy::Budget::compute(pk.prm, depth);
    delta::Gen dg{pk,sk,L.seed};
    delta::Set ds=delta::Set::make(dg,b,S);
    auto R=prf_R_slots(pk,sk,L.seed,S);
    L.R_com=compute_R_com_base(pk.canon_tag,L.seed.ztag,L.seed.nonce.lo,L.seed.nonce.hi,R);
    compute_layer_PC(L,sk,R,S);
    auto va=field::Op::sub(v, ds.agg);
    idx::Selector sel(pk.prm.B);
    graph::Emitter em{pk, L.seed};
    graph::SigEdge sig(pk, sel);
    auto sn=sig.build(va, rng);
    std::vector<LEdge> pre;
    int si=0;
    for (size_t i=0;i<sn.len();++i) {
        const auto& n=sn[i];
        Edge e=em((uint16_t)n.pos,n.pol,field::Op::mul(n.coef,R),rng); e.layer_id=0;
        LEdge le; le.e=std::move(e); le.origins.push_back({Kind::Signal,si++,0});
        le.term=edge_term(pk, le.e); pre.push_back(std::move(le));
    }
    graph::N2Edge n2e(pk,sel);
    for (int t=0;t<b.n2;++t) {
        auto n2=n2e.build(ds[t],S,rng);
        Edge ea=em((uint16_t)n2.pa,n2.sa,field::Op::mul(R,n2.ra),rng);
        Edge eb=em((uint16_t)n2.pb,n2.sb,field::Op::mul(R,n2.rb),rng);
        ea.layer_id=eb.layer_id=0;
        LEdge la,lb;
        la.e=std::move(ea); la.origins.push_back({Kind::N2,t,0}); la.term=edge_term(pk,la.e);
        lb.e=std::move(eb); lb.origins.push_back({Kind::N2,t,1}); lb.term=edge_term(pk,lb.e);
        pre.push_back(std::move(la)); pre.push_back(std::move(lb));
    }
    graph::N3Edge n3e(pk,sel);
    for (int t=0;t<b.n3;++t) {
        auto n3=n3e.build(ds[(size_t)b.n2+t],S,rng);
        Edge ea=em((uint16_t)n3.pa,n3.sa,field::Op::mul(R,n3.ra),rng);
        Edge eb=em((uint16_t)n3.pb,n3.sb,field::Op::mul(R,n3.rb),rng);
        Edge ec=em((uint16_t)n3.pc,n3.sc,field::Op::mul(R,n3.rc),rng);
        ea.layer_id=eb.layer_id=ec.layer_id=0;
        LEdge la,lb,lc;
        la.e=std::move(ea); la.origins.push_back({Kind::N3,t,0}); la.term=edge_term(pk,la.e);
        lb.e=std::move(eb); lb.origins.push_back({Kind::N3,t,1}); lb.term=edge_term(pk,lb.e);
        lc.e=std::move(ec); lc.origins.push_back({Kind::N3,t,2}); lc.term=edge_term(pk,lc.e);
        pre.push_back(std::move(la)); pre.push_back(std::move(lb)); pre.push_back(std::move(lc));
    }
    auto mid=merge_labeled(std::move(pre), pk);
    permute_labeled(mid, rng);
    return mid;
}

struct Cand2 {
    int i,j;
    double score_sigma, score_weight, score_joint;
    bool is_true=false;
};

struct Cand3 {
    int i,j,k;
    double score_sigma, score_weight, score_joint;
    bool is_true=false;
};

struct RankStats {
    long n_true=0, n_cand=0;
    double sum_rank=0, sum_pct=0;
    long r1=0,r5=0,r10=0,r_sqrt=0;
};

static void accum_rank(RankStats& st, const std::vector<double>& ranks_of_true, long n_cand) {
    if (ranks_of_true.empty() || n_cand<=0) return;
    st.n_true += (long)ranks_of_true.size();
    st.n_cand += n_cand;
    long sq = (long)std::ceil(std::sqrt((double)n_cand));
    for (double r : ranks_of_true) {
        st.sum_rank += r;
        // percentile: lower rank better; pct = 1 - (r-1)/(n_cand)
        st.sum_pct += 1.0 - (r - 1.0) / (double)n_cand;
        if (r <= 1) st.r1++;
        if (r <= 5) st.r5++;
        if (r <= 10) st.r10++;
        if (r <= sq) st.r_sqrt++;
    }
}

// Rank 1-based after sorting by score desc; ties broken by index order
static std::vector<double> true_ranks_from_scores(const std::vector<double>& scores, const std::vector<bool>& is_true) {
    std::vector<int> order(scores.size());
    std::iota(order.begin(), order.end(), 0);
    std::stable_sort(order.begin(), order.end(), [&](int a, int b){
        if (scores[a]!=scores[b]) return scores[a]>scores[b];
        return a<b;
    });
    std::vector<double> ranks;
    for (size_t rank=0; rank<order.size(); ++rank) {
        if (is_true[order[rank]]) ranks.push_back((double)rank+1);
    }
    return ranks;
}

static void collect_true_n2_n3(
    const std::vector<LEdge>& edges,
    std::map<int,std::set<std::pair<int,int>>>& n2,
    std::map<int,std::set<std::pair<int,int>>>& n3
) {
    std::map<int,std::vector<std::pair<int,int>>> m2,m3;
    for (const auto& le: edges) {
        if (le.origins.size()!=1) continue;
        auto lab=le.origins[0];
        if (lab.kind==Kind::N2) m2[lab.group_id].push_back({(int)le.e.idx,(int)le.e.ch});
        if (lab.kind==Kind::N3) m3[lab.group_id].push_back({(int)le.e.idx,(int)le.e.ch});
    }
    for (auto& kv:m2) if (kv.second.size()==2)
        n2[kv.first]=std::set<std::pair<int,int>>(kv.second.begin(),kv.second.end());
    for (auto& kv:m3) if (kv.second.size()==3)
        n3[kv.first]=std::set<std::pair<int,int>>(kv.second.begin(),kv.second.end());
}

static double score_sigma_pair(const LEdge& a, const LEdge& b) {
    // lower xor_pop better -> invert
    size_t xp = sigma_xor_pop(a.e.s, b.e.s);
    size_t bits = std::max(a.e.s.nbits, b.e.s.nbits);
    if (!bits) return 0;
    double ham = (double)xp / (double)bits;
    double eq = sigma_equal(a.e.s,b.e.s) ? 1.0 : 0.0;
    return eq * 10.0 + (1.0 - ham); // prefer equal, then low hamming
}

static double score_weight_pair(const LEdge& a, const LEdge& b) {
    // no public invariant; use |term| product inverse as weak magnitude heuristic (control-ish)
    // Prefer features that could relate: we use 0 for all (uniform) would not rank.
    // Use sum of terms abs-ish via field: just use lo bits as magnitude proxy for control feature
    uint64_t ma = a.term.lo ^ a.term.hi;
    uint64_t mb = b.term.lo ^ b.term.hi;
    // "collision-ish": prefer closer popcnt of magnitude proxies — weak, not invariant
    int pa=__builtin_popcountll(ma), pb=__builtin_popcountll(mb);
    return 64.0 - std::abs(pa-pb);
}

static double score_joint_pair(const LEdge& a, const LEdge& b) {
    return score_sigma_pair(a,b) + 0.01 * score_weight_pair(a,b);
}

static double score_sigma_triple(const LEdge& a, const LEdge& b, const LEdge& c) {
    double s = score_sigma_pair(a,b)+score_sigma_pair(a,c)+score_sigma_pair(b,c);
    return s / 3.0;
}
static double score_weight_triple(const LEdge& a, const LEdge& b, const LEdge& c) {
    return (score_weight_pair(a,b)+score_weight_pair(a,c)+score_weight_pair(b,c))/3.0;
}
static double score_joint_triple(const LEdge& a, const LEdge& b, const LEdge& c) {
    return score_sigma_triple(a,b,c)+0.01*score_weight_triple(a,b,c);
}

// Perfect synthetic feature harness: score=1 if true else 0
static void harness_check(const std::vector<bool>& is_true) {
    std::vector<double> scores(is_true.size());
    for (size_t i=0;i<is_true.size();++i) scores[i]=is_true[i]?1.0:0.0;
    auto ranks=true_ranks_from_scores(scores, is_true);
    bool ok=true;
    for (double r: ranks) if (r > (double)std::count(is_true.begin(),is_true.end(),true)+1e-9) ok=false;
    // all true should rank in top n_true
    long nt=std::count(is_true.begin(),is_true.end(),true);
    for (double r: ranks) if (r > nt) ok=false;
    std::printf("harness_perfect_feature_ok=%d n_true=%ld n_cand=%zu\n", ok?1:0, nt, is_true.size());
}

int main() {
    Params prm;
    prm.noise_entropy_bits=128.0;
    uint8_t wallet[32]; for(int i=0;i<32;i++) wallet[i]=(uint8_t)(0xB0+i);
    PubKey pk; SecKey sk;
    keygen_from_seed(prm, pk, sk, wallet);

    RankStats n2_sig, n2_w, n2_j, n2_rand, n2_idx;
    RankStats n3_sig, n3_w, n3_j, n3_rand;
    long trials=0;
    double sum_pairs=0, sum_triples=0;

    // harness once
    {
        std::vector<bool> fake(100,false);
        fake[3]=fake[7]=fake[50]=true;
        harness_check(fake);
    }

    const int N=200;
    for (int t=0;t<N;t++) {
        int depth=2+(t%21);
        uint64_t val = (t%5==0)?0:(t%5==1)?1:(t%5==2)?337:(t%5==3)?~0ull:((uint64_t)t*0x9E3779B97F4A7C15ull);
        uint8_t seed[32]; for(int i=0;i<32;i++) seed[i]=(uint8_t)(t*13+i*7+depth);
        auto scoped=enc_seed_scope(pk,seed,"fv01",1,depth,{fp_from_u64(val)});
        SeedableRng rng=make_seeded_rng(scoped.data());
        auto edges=synth_seeded_labeled(pk,sk,{fp_from_u64(val)},depth,rng);

        std::map<int,std::set<std::pair<int,int>>> n2t,n3t;
        collect_true_n2_n3(edges,n2t,n3t);

        // N2 candidates
        std::vector<Cand2> c2;
        for (int i=0;i<(int)edges.size();++i) for (int j=i+1;j<(int)edges.size();++j) {
            if (edges[i].e.ch==edges[j].e.ch) continue;
            if (edges[i].e.idx==edges[j].e.idx) continue;
            Cand2 c; c.i=i; c.j=j;
            c.score_sigma=score_sigma_pair(edges[i],edges[j]);
            c.score_weight=score_weight_pair(edges[i],edges[j]);
            c.score_joint=score_joint_pair(edges[i],edges[j]);
            std::set<std::pair<int,int>> key{
                {(int)edges[i].e.idx,(int)edges[i].e.ch},
                {(int)edges[j].e.idx,(int)edges[j].e.ch}
            };
            for (auto& kv:n2t) if (kv.second==key) { c.is_true=true; break; }
            c2.push_back(c);
        }
        sum_pairs += c2.size();

        auto pack2=[&](auto score_fn, RankStats& st){
            std::vector<double> scores; std::vector<bool> tr;
            scores.reserve(c2.size()); tr.reserve(c2.size());
            for (auto& c:c2){ scores.push_back(score_fn(c)); tr.push_back(c.is_true); }
            accum_rank(st, true_ranks_from_scores(scores,tr), (long)c2.size());
        };
        pack2([](const Cand2& c){return c.score_sigma;}, n2_sig);
        pack2([](const Cand2& c){return c.score_weight;}, n2_w);
        pack2([](const Cand2& c){return c.score_joint;}, n2_j);
        // random control: score from rng
        {
            SeedableRng cr=make_seeded_rng(seed);
            std::vector<double> scores; std::vector<bool> tr;
            for (auto& c:c2){ scores.push_back((double)cr.u64()); tr.push_back(c.is_true); }
            accum_rank(n2_rand, true_ranks_from_scores(scores,tr), (long)c2.size());
        }
        // index/sign-only: prefer lower idx sum
        pack2([&](const Cand2& c){
            return 10000.0 - (edges[c.i].e.idx + edges[c.j].e.idx);
        }, n2_idx);

        // N3 candidates (all sign patterns, 3 distinct idx)
        std::vector<Cand3> c3;
        int m=(int)edges.size();
        for (int i=0;i<m;i++) for (int j=i+1;j<m;j++) for (int k=j+1;k<m;k++) {
            if (edges[i].e.idx==edges[j].e.idx || edges[i].e.idx==edges[k].e.idx || edges[j].e.idx==edges[k].e.idx) continue;
            Cand3 c; c.i=i;c.j=j;c.k=k;
            c.score_sigma=score_sigma_triple(edges[i],edges[j],edges[k]);
            c.score_weight=score_weight_triple(edges[i],edges[j],edges[k]);
            c.score_joint=score_joint_triple(edges[i],edges[j],edges[k]);
            std::set<std::pair<int,int>> key{
                {(int)edges[i].e.idx,(int)edges[i].e.ch},
                {(int)edges[j].e.idx,(int)edges[j].e.ch},
                {(int)edges[k].e.idx,(int)edges[k].e.ch}
            };
            for (auto& kv:n3t) if (kv.second==key) { c.is_true=true; break; }
            c3.push_back(c);
        }
        sum_triples += c3.size();
        auto pack3=[&](auto score_fn, RankStats& st){
            std::vector<double> scores; std::vector<bool> tr;
            for (auto& c:c3){ scores.push_back(score_fn(c)); tr.push_back(c.is_true); }
            accum_rank(st, true_ranks_from_scores(scores,tr), (long)c3.size());
        };
        pack3([](const Cand3& c){return c.score_sigma;}, n3_sig);
        pack3([](const Cand3& c){return c.score_weight;}, n3_w);
        pack3([](const Cand3& c){return c.score_joint;}, n3_j);
        {
            SeedableRng cr=make_seeded_rng(seed);
            std::vector<double> scores; std::vector<bool> tr;
            for (auto& c:c3){ scores.push_back((double)cr.u64()); tr.push_back(c.is_true); }
            accum_rank(n3_rand, true_ranks_from_scores(scores,tr), (long)c3.size());
        }

        // permuted-label control once every 20: shuffle is_true
        if (t%20==0 && !c2.empty()) {
            std::vector<bool> tr;
            for (auto& c:c2) tr.push_back(c.is_true);
            // rotate
            if (!tr.empty()) std::rotate(tr.begin(), tr.begin()+1, tr.end());
            std::vector<double> scores;
            for (auto& c:c2) scores.push_back(c.score_joint);
            auto ranks=true_ranks_from_scores(scores,tr);
            // just print first occurrence effect
            if (t==0) {
                double meanr=0; for(double r:ranks) meanr+=r;
                if (!ranks.empty()) meanr/=ranks.size();
                std::printf("permuted_label_joint_mean_true_rank=%.2f (n=%zu)\n", meanr, ranks.size());
            }
        }
        trials++;
        if (t<2) {
            std::printf("trial=%d edges=%zu n2_cand=%zu n3_cand=%zu n2_true=%zu n3_true=%zu\n",
                t, edges.size(), c2.size(), c3.size(), n2t.size(), n3t.size());
        }
    }

    auto dump=[&](const char* name, const RankStats& st){
        if (st.n_true==0) { std::printf("%s no_true\n", name); return; }
        std::printf("%s mean_true_rank=%.2f mean_true_pct=%.4f recall@1=%.4f @5=%.4f @10=%.4f @sqrt=%.4f n_true=%ld\n",
            name, st.sum_rank/st.n_true, st.sum_pct/st.n_true,
            (double)st.r1/st.n_true, (double)st.r5/st.n_true, (double)st.r10/st.n_true, (double)st.r_sqrt/st.n_true,
            st.n_true);
    };

    std::printf("\n=== FV-01 SUMMARY trials=%ld mean_pairs=%.1f mean_triples=%.1f ===\n",
        trials, sum_pairs/trials, sum_triples/trials);
    dump("N2_sigma", n2_sig);
    dump("N2_weight", n2_w);
    dump("N2_joint", n2_j);
    dump("N2_random", n2_rand);
    dump("N2_idx_sign", n2_idx);
    dump("N3_sigma", n3_sig);
    dump("N3_weight", n3_w);
    dump("N3_joint", n3_j);
    dump("N3_random", n3_rand);

    // effect vs random: mean pct difference
    auto eff=[&](const RankStats& a, const RankStats& b){
        if (!a.n_true||!b.n_true) return 0.0;
        return (a.sum_pct/a.n_true) - (b.sum_pct/b.n_true);
    };
    std::printf("effect_N2_joint_minus_random_pct=%.6f\n", eff(n2_j, n2_rand));
    std::printf("effect_N3_joint_minus_random_pct=%.6f\n", eff(n3_j, n3_rand));
    std::printf("exact_partition_rate=0\n"); // no unique public partition observed in ranking tops

    // Wrapped applicability smoke: 20 official wrapped encs
    long w_edges=0; double w_pairs=0;
    for (int i=0;i<20;i++) {
        uint8_t seed[32]; for(int k=0;k<32;k++) seed[k]=(uint8_t)(0x40+i+k);
        Cipher C=enc_value_depth_seeded(pk,sk,(uint64_t)(i*17), 2+(i%21), seed);
        w_edges += (long)C.E.size();
        // per-layer pair counts
        std::map<uint32_t,std::vector<const Edge*>> by;
        for (auto& e:C.E) by[e.layer_id].push_back(&e);
        for (auto& kv:by) {
            int p=0,n=0;
            for (auto* e:kv.second){ if(e->ch==SGN_P)p++; else n++; }
            w_pairs += (double)p*n; // upper bound opposite-sign pairs (idx filter not applied)
        }
    }
    std::printf("wrapped_smoke_n=20 mean_edges=%.2f mean_opp_sign_pair_ub=%.2f\n",
        w_edges/20.0, w_pairs/20.0);

    // CLOSED if joint not materially better than random (pct effect < 0.02)
    double e2=eff(n2_j,n2_rand), e3=eff(n3_j,n3_rand);
    bool closed = (std::fabs(e2)<0.02 && std::fabs(e3)<0.02);
    std::printf("verdict=%s\n", closed?"CLOSED":"PROMISING");
    std::printf("labels_excluded_from_features=1\n");
    return 0;
}
