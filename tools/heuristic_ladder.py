#!/usr/bin/env python3
"""Toy benchmark for lightweight recovery of oversampled noisy parities."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import statistics
import time
from pathlib import Path

import numpy as np

RATIO = 176
NOISE_DENOMINATOR = 8
PARITY8 = np.array([value.bit_count() & 1 for value in range(256)], dtype=np.uint8)
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "results" / "heuristic_ladder_results.json"


def parity64(values: np.ndarray) -> np.ndarray:
    raw = np.ascontiguousarray(values, dtype=np.uint64).view(np.uint8).reshape(-1, 8)
    return np.bitwise_xor.reduce(PARITY8[raw], axis=1)


def make_instance(n: int, rng: np.random.Generator):
    m = RATIO * n
    rows = rng.integers(0, 1 << n, size=m, dtype=np.uint64)
    columns = ((rows[:, None] >> np.arange(n, dtype=np.uint64)) & 1).astype(np.uint8)
    secret_bits = np.zeros(n, dtype=np.uint8)
    secret_bits[rng.choice(n, n // 2, replace=False)] = 1
    secret = sum(int(bit) << index for index, bit in enumerate(secret_bits))
    errors = np.zeros(m, dtype=np.uint8)
    errors[rng.choice(m, m // NOISE_DENOMINATOR, replace=False)] = 1
    labels = parity64(rows & np.uint64(secret)) ^ errors
    return rows, columns, labels, secret


def solve_square(rows: np.ndarray, labels: np.ndarray, n: int) -> int | None:
    equations = [int(row) | (int(label) << n) for row, label in zip(rows, labels)]
    for column in range(n):
        pivot = next(
            (index for index in range(column, n) if (equations[index] >> column) & 1),
            None,
        )
        if pivot is None:
            return None
        equations[column], equations[pivot] = equations[pivot], equations[column]
        for index in range(n):
            if index != column and ((equations[index] >> column) & 1):
                equations[index] ^= equations[column]
    return sum(((equations[column] >> n) & 1) << column for column in range(n))


def information_set(
    rows: np.ndarray,
    labels: np.ndarray,
    n: int,
    rng: np.random.Generator,
    max_attempts: int,
):
    threshold = 3 * len(rows) // 4
    best_candidate, best_score = 0, -1
    for attempt in range(1, max_attempts + 1):
        chosen = rng.choice(len(rows), n, replace=False)
        candidate = solve_square(rows[chosen], labels[chosen], n)
        if candidate is None:
            continue
        score = int(np.count_nonzero(parity64(rows & np.uint64(candidate)) == labels))
        if score > best_score:
            best_candidate, best_score = candidate, score
        if score >= threshold:
            return candidate, attempt, best_score
    return best_candidate, max_attempts, best_score


def coordinate_local(
    columns: np.ndarray,
    labels: np.ndarray,
    rng: np.random.Generator,
    max_restarts: int,
):
    n, threshold = columns.shape[1], 3 * len(labels) // 4
    best_bits, best_score, updates = None, -1, 0
    for restart in range(1, max_restarts + 1):
        bits = rng.integers(0, 2, size=n, dtype=np.uint8)
        residual = labels ^ ((columns @ bits) & 1)
        score = len(labels) - int(residual.sum())
        while True:
            gains = columns.T @ (2 * residual.astype(np.int32) - 1)
            coordinate = int(np.argmax(gains))
            gain = int(gains[coordinate])
            if gain <= 0:
                break
            bits[coordinate] ^= 1
            residual ^= columns[:, coordinate]
            score += gain
            updates += 1
        if score > best_score:
            best_bits, best_score = bits.copy(), score
        if score >= threshold:
            break
    candidate = sum(int(bit) << index for index, bit in enumerate(best_bits))
    return candidate, restart, updates, best_score


def timed_run(function, *args):
    started = time.perf_counter()
    result = function(*args)
    return result, time.perf_counter() - started


def method_summary(successes, seconds, work, budget, extra=None):
    result = {
        "successes": sum(successes),
        "trials": len(successes),
        "success_rate": sum(successes) / len(successes),
        "budget_per_trial": budget,
        "work_mean_including_censored_failures": statistics.fmean(work),
        "work_median_including_censored_failures": statistics.median(work),
        "seconds_total": sum(seconds),
        "seconds_mean": statistics.fmean(seconds),
        "seconds_median": statistics.median(seconds),
    }
    if extra:
        result.update(extra)
    return result


def information_set_theory(n: int, m: int, budget: int):
    errors = m // NOISE_DENOMINATOR
    clean_exact = math.prod((m - errors - index) / (m - index) for index in range(n))
    clean_approx = ((NOISE_DENOMINATOR - 1) / NOISE_DENOMINATOR) ** n
    full_rank = math.prod(1.0 - 2.0**-index for index in range(1, n + 1))
    per_attempt = clean_exact * full_rank
    return {
        "clean_set_probability_7_over_8_power_n": clean_approx,
        "clean_set_probability_exact_fixed_weight": clean_exact,
        "gf2_full_rank_probability": full_rank,
        "success_probability_per_attempt": per_attempt,
        "expected_attempts": 1.0 / per_attempt,
        "success_probability_within_budget": -math.expm1(
            budget * math.log1p(-per_attempt)
        ),
    }


def wilson_interval(successes: int, attempts: int):
    z = 1.959963984540054
    estimate = successes / attempts
    denominator = 1 + z * z / attempts
    center = (estimate + z * z / (2 * attempts)) / denominator
    radius = z * math.sqrt(
        estimate * (1 - estimate) / attempts + z * z / (4 * attempts * attempts)
    ) / denominator
    return [center - radius, center + radius]


def binomial_two_sided(successes: int, trials: int, probability: float):
    observed = math.comb(trials, successes) * probability**successes * (
        1 - probability
    ) ** (trials - successes)
    probabilities = [
        math.comb(trials, count) * probability**count * (1 - probability) ** (trials - count)
        for count in range(trials + 1)
    ]
    return min(1.0, sum(value for value in probabilities if value <= observed * (1 + 1e-12)))


def benchmark(sizes, trials, local_restarts, is_attempts, seed, is_only=False):
    rows_out = []
    previous_medians = {"coordinate_local": None, "information_set": None}
    for n in sizes:
        local_success, local_seconds, local_work, local_updates = [], [], [], []
        is_public, is_oracle, is_seconds, is_work, success_work = [], [], [], [], []
        for trial in range(trials):
            instance_rng = np.random.default_rng(np.random.SeedSequence([seed, n, trial, 0]))
            rows, columns, labels, secret = make_instance(n, instance_rng)

            if not is_only:
                local_rng = np.random.default_rng(np.random.SeedSequence([seed, n, trial, 1]))
                local_result, elapsed = timed_run(
                    coordinate_local, columns, labels, local_rng, local_restarts
                )
                candidate, restarts_used, updates, _ = local_result
                local_success.append(candidate == secret)
                local_seconds.append(elapsed)
                local_work.append(restarts_used)
                local_updates.append(updates)

            is_rng = np.random.default_rng(np.random.SeedSequence([seed, n, trial, 2]))
            is_result, elapsed = timed_run(
                information_set, rows, labels, n, is_rng, is_attempts
            )
            candidate, attempts_used, best_score = is_result
            public_accepted = best_score >= 3 * len(rows) // 4
            oracle_match = candidate == secret
            is_public.append(public_accepted)
            is_oracle.append(oracle_match)
            is_seconds.append(elapsed)
            is_work.append(attempts_used)
            success_work.append(attempts_used if public_accepted else None)

        total_attempts = sum(is_work)
        theory = information_set_theory(n, len(rows), is_attempts)
        observed_per_attempt = sum(is_public) / total_attempts
        methods = {
            "information_set": method_summary(
                is_public,
                is_seconds,
                is_work,
                is_attempts,
                {
                    "public_accepts": sum(is_public),
                    "oracle_matches": sum(is_oracle),
                    "public_oracle_agreements": sum(
                        public == oracle for public, oracle in zip(is_public, is_oracle)
                    ),
                    "false_public_accepts": sum(
                        public and not oracle for public, oracle in zip(is_public, is_oracle)
                    ),
                    "oracle_matches_without_public_accept": sum(
                        oracle and not public for public, oracle in zip(is_public, is_oracle)
                    ),
                    "attempts_to_public_accept": success_work,
                    "total_attempts_including_censored_failures": total_attempts,
                    "observed_successes_per_attempt_mle": observed_per_attempt,
                    "observed_successes_per_attempt_wilson_95": wilson_interval(
                        sum(is_public), total_attempts
                    ),
                    "theory": theory,
                    "expected_public_accepting_trials": (
                        trials * theory["success_probability_within_budget"]
                    ),
                    "trial_success_binomial_two_sided_p": binomial_two_sided(
                        sum(is_public), trials, theory["success_probability_within_budget"]
                    ),
                    "deviation_promoted_bonferroni_0_05": (
                        binomial_two_sided(
                            sum(is_public),
                            trials,
                            theory["success_probability_within_budget"],
                        )
                        < 0.05 / len(sizes)
                    ),
                    "theory_inside_observed_wilson_95": (
                        wilson_interval(sum(is_public), total_attempts)[0]
                        <= theory["success_probability_per_attempt"]
                        <= wilson_interval(sum(is_public), total_attempts)[1]
                    ),
                    "observed_attempts_mean_successes_only": (
                        statistics.fmean(value for value in success_work if value is not None)
                        if any(is_public)
                        else None
                    ),
                    "observed_attempts_median_successes_only": (
                        statistics.median(value for value in success_work if value is not None)
                        if any(is_public)
                        else None
                    ),
                },
            ),
        }
        if not is_only:
            methods["coordinate_local"] = method_summary(
                local_success,
                local_seconds,
                local_work,
                local_restarts,
                {"coordinate_updates_mean": statistics.fmean(local_updates)},
            )
        for name, result in methods.items():
            previous = previous_medians[name]
            result["median_seconds_ratio_from_previous_n"] = (
                result["seconds_median"] / previous if previous else None
            )
            previous_medians[name] = result["seconds_median"]
        row = {"n": n, "m": RATIO * n, "secret_weight": n // 2, "methods": methods}
        rows_out.append(row)
        print(
            f"n={n:2d} M={RATIO*n:5d} | IS-public {sum(is_public):2d}/{trials} "
            f"oracle {sum(is_oracle):2d}/{trials} attempts={total_attempts:7d} "
            f"med={statistics.median(is_seconds):.4f}s"
        )
    return rows_out


def self_check():
    n, secret = 6, 0b101011
    rows = np.array([1 << index for index in range(n)], dtype=np.uint64)
    labels = np.array([(secret >> index) & 1 for index in range(n)], dtype=np.uint8)
    assert solve_square(rows, labels, n) == secret
    assert np.array_equal(parity64(rows & np.uint64(secret)), labels)
    theory = information_set_theory(8, 8 * RATIO, 512)
    assert 0 < theory["success_probability_per_attempt"] < 1
    assert theory["clean_set_probability_exact_fixed_weight"] < (7 / 8) ** 8


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", default="8,12,16,20,24,28,32")
    parser.add_argument("--trials", type=int, default=24)
    parser.add_argument("--local-restarts", type=int, default=64)
    parser.add_argument("--is-attempts", type=int, default=512)
    parser.add_argument("--is-only", action="store_true")
    parser.add_argument("--seed", type=int, default=20250308)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    sizes = [int(value) for value in args.sizes.split(",")]
    if args.trials < 1 or args.local_restarts < 1 or args.is_attempts < 1:
        parser.error("trials and method budgets must be positive")
    if not sizes or any(n < 4 or n > 63 for n in sizes):
        parser.error("sizes must be in 4..63 (uint64 implementation ceiling)")

    self_check()
    started = time.time()
    results = benchmark(
        sizes, args.trials, args.local_restarts, args.is_attempts, args.seed, args.is_only
    )
    script_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    output = {
        "experiment": "dense-secret noisy parity heuristic ladder",
        "model": {
            "samples": "M=176n",
            "noise": "exact fixed weight M/8",
            "secret": "exact fixed weight floor(n/2)",
        },
        "methods": {
            "coordinate_local": "random restart, strict best single-bit improvement",
            "information_set": "random n-row GF(2) solve, verify on all M rows",
        },
        "verifier_audit": {
            "search_reads_secret": False,
            "public_acceptance_rule": "candidate agrees with at least floor(3M/4) public rows",
            "correct_secret_public_score": "exactly 7M/8 under the fixed-weight noise model",
            "secret_oracle_use": "post-run audit only; never used to select or stop a candidate",
            "success_definition": "public acceptance; oracle fields measure verifier agreement",
        },
        "config": vars(args) | {"out": str(args.out), "sizes": sizes},
        "environment": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "platform": platform.platform(),
        },
        # ponytail: measured tiers and direct theory only; no fit means no invented scaling law.
        "scope": "Empirical results only for listed n and budgets; no fitted exponent or extrapolation.",
        "started_unix": started,
        "elapsed_seconds": time.time() - started,
        "script_sha256": script_hash,
        "results": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
