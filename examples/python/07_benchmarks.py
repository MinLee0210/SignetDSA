#!/usr/bin/env python3
"""
In-process micro-benchmarks across all 11 signature algorithms in Python.

Demonstrates:
- Executing Signet.benchmark_all(iterations=N)
- Measuring Sign & Verify latency, ops per second, and key/sig sizes
"""

import signetdsa


def main():
    print("=== SignetDSA Python SDK - Micro-Benchmark Suite ===\n")

    iterations = 2
    print(f"Running in-process benchmarks ({iterations} iterations per algorithm)...")
    print("-" * 92)
    print(
        f"{'Algorithm':<18} | {'Sign (ops/s)':>12} | {'Keygen (ms)':>11} | "
        f"{'Sign (ms)':>10} | {'Verify (ms)':>11} | {'Sig (B)':>7}"
    )
    print("-" * 92)

    results = signetdsa.Signet.benchmark_all(iterations=iterations)

    for r in results:
        print(
            f"{r.algo:<18} | {r.sign_ops_per_sec:>12.1f} | {r.keygen_ms:>11.3f} | "
            f"{r.sign_ms:>10.3f} | {r.verify_ms:>11.3f} | {r.sig_bytes:>7}"
        )

    print("-" * 92)
    print("\n[✓] Benchmarking complete!")


if __name__ == "__main__":
    main()
