#!/usr/bin/env python3
"""
Measurement script for the report "Cryptographic Hash Functions".

Produces every quantitative figure referenced by the report:

  1. Avalanche effect over 10,000 single-bit flips      -> Table 1, Figure 1
  2. Birthday-attack collision search                   -> Table 2
  3. Data-hashing throughput on 64 MiB                   -> Figure 2
  4. Password-hashing cost (bcrypt / scrypt / Argon2)    -> Table 4
  5. Single-call latency of fast hashes                  -> Section 4.3

Usage:
    python benchmark.py                 # run everything
    python benchmark.py --quick         # fewer repetitions, for a smoke test
    python benchmark.py --only avalanche,timing
    python benchmark.py --no-plots      # skip PNG generation

The three demo programs (bcrypt.py, argon2.py, BLAKE2.py) only demonstrate
hashing and verification; they do not emit any of the numbers above.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import secrets
import statistics
import sys
import time

# ---------------------------------------------------------------------------
# bcrypt.py and argon2.py in this directory shadow the installed libraries of
# the same name. Drop this directory from sys.path while importing them.
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))


def _import_shadowed(name):
    saved_path = list(sys.path)
    saved_mod = sys.modules.pop(name, None)
    try:
        sys.path = [p for p in sys.path if os.path.abspath(p or ".") != _HERE]
        return importlib.import_module(name)
    finally:
        sys.path = saved_path
        if saved_mod is not None:
            sys.modules.setdefault(name, saved_mod)


bcrypt_lib = _import_shadowed("bcrypt")
argon2_lib = _import_shadowed("argon2")

PASSWORD = "MatKhau@123"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def fnv1a_32(data: bytes) -> bytes:
    """Non-cryptographic hash, included as a control in the avalanche test."""
    h = 0x811C9DC5
    for byte in data:
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h.to_bytes(4, "big")


HASHES = {
    "FNV-1a (non-cryptographic control)": (fnv1a_32, 32),
    "SHA-256": (lambda d: hashlib.sha256(d).digest(), 256),
    "SHA3-256": (lambda d: hashlib.sha3_256(d).digest(), 256),
    "BLAKE2b-256": (lambda d: hashlib.blake2b(d, digest_size=32).digest(), 256),
}


def popcount_diff(a: bytes, b: bytes) -> int:
    return int.from_bytes(a, "big").__xor__(int.from_bytes(b, "big")).bit_count()


def flip_one_bit(data: bytes) -> bytes:
    pos = secrets.randbelow(len(data) * 8)
    out = bytearray(data)
    out[pos // 8] ^= 1 << (pos % 8)
    return bytes(out)


def timeit(fn, repeats: int):
    """Return the median wall-clock seconds per call over `repeats` calls."""
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)


# ---------------------------------------------------------------------------
# 1. avalanche effect  -> Table 1 + Figure 1
# ---------------------------------------------------------------------------
def run_avalanche(trials: int):
    print(f"\n{'='*78}\n1. AVALANCHE EFFECT  ({trials:,} single-bit flips, 32-byte messages)\n{'='*78}")
    results = {}
    sha256_counts = []

    for name, (fn, bits) in HASHES.items():
        changed = []
        for _ in range(trials):
            msg = secrets.token_bytes(32)
            diff = popcount_diff(fn(msg), fn(flip_one_bit(msg)))
            changed.append(diff)
            if name == "SHA-256":
                sha256_counts.append(diff)

        mean = statistics.fmean(changed)
        stdev = statistics.stdev(changed)
        results[name] = {
            "output_bits": bits,
            "mean_bits_changed": round(mean, 2),
            "ratio_percent": round(100 * mean / bits, 2),
            "stdev": round(stdev, 2),
            "min": min(changed),
            "max": max(changed),
        }
        print(f"  {name:36s} {bits:4d} bit | mean {mean:7.2f} "
              f"({100*mean/bits:5.2f}%) | sd {stdev:5.2f} | min {min(changed):3d} max {max(changed):3d}")

    print(f"\n  Theory for an ideal n-bit hash: mean n/2, sd sqrt(n)/2 "
          f"(= 128.00 and 8.00 for n = 256)")
    return results, sha256_counts


# ---------------------------------------------------------------------------
# 2. birthday attack  -> Table 2
# ---------------------------------------------------------------------------
def first_collision(bits: int) -> int:
    """Hash 'Hop_dong_chuyen_khoan_<k>_trieu_VND' until the truncated digest
    repeats. A random nonce per trial makes repetitions independent."""
    nonce = secrets.token_hex(8)
    nbytes = bits // 8
    seen = {}
    k = 0
    while True:
        k += 1
        msg = f"Hop_dong_chuyen_khoan_{k}_trieu_VND_{nonce}".encode()
        digest = hashlib.sha256(msg).digest()[:nbytes]
        if digest in seen:
            return k
        seen[digest] = k


def run_birthday(plan):
    print(f"\n{'='*78}\n2. BIRTHDAY ATTACK  (truncated SHA-256)\n{'='*78}")
    import math

    results = {}
    for bits, reps in plan:
        counts = [first_collision(bits) for _ in range(reps)]
        measured = statistics.fmean(counts)
        theory = math.sqrt(math.pi / 2 * 2 ** bits)
        results[bits] = {
            "repetitions": reps,
            "measured_mean": round(measured),
            "theory": round(theory),
            "brute_force": 2 ** bits,
            "ratio": round(measured / theory, 3),
        }
        print(f"  {bits:2d} bit | {reps:4d} runs | measured {measured:12,.0f} | "
              f"theory {theory:12,.0f} | brute force {2**bits:>15,} | "
              f"measured/theory {measured/theory:.3f}")
    return results


# ---------------------------------------------------------------------------
# 3. throughput  -> Figure 2
# ---------------------------------------------------------------------------
THROUGHPUT_ALGOS = [
    ("MD5", lambda d: hashlib.md5(d).digest(), True),
    ("SHA-1", lambda d: hashlib.sha1(d).digest(), True),
    ("SHA-256", lambda d: hashlib.sha256(d).digest(), False),
    ("SHA-512", lambda d: hashlib.sha512(d).digest(), False),
    ("SHA3-256", lambda d: hashlib.sha3_256(d).digest(), False),
    ("BLAKE2b", lambda d: hashlib.blake2b(d).digest(), False),
    ("BLAKE2s", lambda d: hashlib.blake2s(d).digest(), False),
]


def run_throughput(mib: int, repeats: int):
    print(f"\n{'='*78}\n3. DATA HASHING THROUGHPUT  ({mib} MiB buffer, single core)\n{'='*78}")
    data = secrets.token_bytes(mib * 1024 * 1024)
    results = {}
    for name, fn, broken in THROUGHPUT_ALGOS:
        sec = timeit(lambda: fn(data), repeats)
        mibs = mib / sec
        results[name] = {"mib_per_sec": round(mibs), "seconds": round(sec, 4), "broken": broken}
        flag = "  (broken)" if broken else ""
        print(f"  {name:10s} {mibs:8,.0f} MiB/s   ({sec*1000:7.1f} ms per {mib} MiB){flag}")
    return results


# ---------------------------------------------------------------------------
# 4. password hashing cost  -> Table 4
# ---------------------------------------------------------------------------
def run_password_timing(repeats: int):
    print(f"\n{'='*78}\n4. PASSWORD HASHING COST  (median of {repeats} runs)\n{'='*78}")
    pwd = PASSWORD.encode()
    results = {"bcrypt": {}, "scrypt": {}, "argon2": {}, "argon2_variants": {}}

    print("  bcrypt (Blowfish, 4 KiB memory)")
    for cost in (10, 12, 14):
        salt = bcrypt_lib.gensalt(cost)
        sec = timeit(lambda: bcrypt_lib.hashpw(pwd, salt), repeats)
        results["bcrypt"][cost] = round(sec * 1000)
        print(f"    cost {cost:2d}  ->  {sec*1000:8.1f} ms")

    print("  scrypt (r = 8, p = 1)")
    for log_n, mib in ((14, 16), (17, 128)):
        n = 2 ** log_n
        salt = secrets.token_bytes(16)
        sec = timeit(lambda: hashlib.scrypt(pwd, salt=salt, n=n, r=8, p=1, dklen=32,
                                            maxmem=4 * mib * 1024 * 1024), repeats)
        results["scrypt"][f"2^{log_n}"] = {"ms": round(sec * 1000), "mib": mib}
        print(f"    N = 2^{log_n} ({mib:3d} MiB)  ->  {sec*1000:8.1f} ms")

    print("  Argon2id")
    argon_cfgs = [
        ("19 MiB, t=2, p=1  (OWASP minimum)", 2, 19 * 1024, 1),
        ("64 MiB, t=3, p=4  (RFC 9106 #2)", 3, 65536, 4),
        ("256 MiB, t=3, p=4", 3, 262144, 4),
    ]
    for label, t, m, p in argon_cfgs:
        ph = argon2_lib.PasswordHasher(time_cost=t, memory_cost=m, parallelism=p,
                                       hash_len=32, salt_len=16)
        sec = timeit(lambda: ph.hash(PASSWORD), repeats)
        results["argon2"][label] = round(sec * 1000)
        print(f"    {label:36s} ->  {sec*1000:8.1f} ms")

    print("  Argon2 variants (64 MiB, t=3, p=4)")
    for vname, vtype in (("argon2id", argon2_lib.Type.ID),
                         ("argon2i", argon2_lib.Type.I),
                         ("argon2d", argon2_lib.Type.D)):
        ph = argon2_lib.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
                                       hash_len=32, salt_len=16, type=vtype)
        sec = timeit(lambda: ph.hash(PASSWORD), repeats)
        results["argon2_variants"][vname] = round(sec * 1000)
        print(f"    {vname:10s} ->  {sec*1000:8.1f} ms")

    return results


# ---------------------------------------------------------------------------
# 5. single-call latency of fast hashes  -> Section 4.3
# ---------------------------------------------------------------------------
def run_fast_latency(repeats: int):
    print(f"\n{'='*78}\n5. SINGLE-CALL LATENCY  (short input, {repeats:,} calls)\n{'='*78}")
    import timeit as _t

    msg = b"MyMessageOrPassword"
    results = {}
    for name, stmt in (
        ("BLAKE2b-512", "hashlib.blake2b(msg).digest()"),
        ("BLAKE2b-256", "hashlib.blake2b(msg, digest_size=32).digest()"),
        ("BLAKE2s-256", "hashlib.blake2s(msg).digest()"),
        ("SHA-256", "hashlib.sha256(msg).digest()"),
        ("SHA3-256", "hashlib.sha3_256(msg).digest()"),
    ):
        total = _t.timeit(stmt, globals={"hashlib": hashlib, "msg": msg}, number=repeats)
        usec = total / repeats * 1e6
        results[name] = round(usec, 3)
        print(f"  {name:12s} {usec:7.3f} us per call")
    return results


# ---------------------------------------------------------------------------
# plots
# ---------------------------------------------------------------------------
def plot_avalanche(counts, path):
    import math
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    n = 256
    fig, ax = plt.subplots(figsize=(8, 4.5))
    lo, hi = min(counts), max(counts)
    bins = range(lo, hi + 2)
    ax.hist(counts, bins=bins, density=True, alpha=0.75,
            edgecolor="white", linewidth=0.3, label="SHA-256 (measured)")

    xs = list(bins)
    ys = [math.comb(n, k) * 0.5 ** n for k in xs]
    ax.plot(xs, ys, color="crimson", linewidth=2, label="Binomial B(256; 0.5)")

    ax.axvline(128, color="black", linestyle="--", linewidth=1, label="Expected value 128")
    ax.set_xlabel("Number of output bits changed (out of 256)")
    ax.set_ylabel("Probability density")
    ax.set_title("Avalanche effect of SHA-256 versus the theoretical distribution")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  -> saved {path}")


def plot_throughput(results, mib, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    names = list(results.keys())
    values = [results[k]["mib_per_sec"] for k in names]
    colors = ["#999999" if results[k]["broken"] else "#1f77b4" for k in names]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    bars = ax.bar(names, values, color=colors)
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, v, f"{v:,}",
                ha="center", va="bottom", fontsize=9)
    ax.set_ylabel("Throughput (MiB/s)")
    ax.set_title(f"Hashing throughput on a {mib} MiB buffer, single core\n"
                 "(grey = algorithm already broken)")
    ax.set_ylim(0, max(values) * 1.15)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  -> saved {path}")


# ---------------------------------------------------------------------------
def environment():
    import ssl
    try:
        cores = len(os.sched_getaffinity(0))  # type: ignore[attr-defined]
    except AttributeError:
        cores = os.cpu_count()
    return {
        "cpu": platform.processor(),
        "logical_cpus": cores,
        "platform": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "openssl": ssl.OPENSSL_VERSION,
        "bcrypt": getattr(bcrypt_lib, "__version__", "n/a"),
        "argon2_cffi": getattr(argon2_lib, "__version__", "n/a"),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="fewer repetitions")
    ap.add_argument("--only", default="", help="comma-separated subset: "
                    "avalanche,birthday,throughput,timing,latency")
    ap.add_argument("--no-plots", action="store_true")
    ap.add_argument("--json", default="benchmark_results.json")
    args = ap.parse_args()

    wanted = {s.strip() for s in args.only.split(",") if s.strip()} or None

    def want(name):
        return wanted is None or name in wanted

    env = environment()
    print("=" * 78)
    print("MEASUREMENT ENVIRONMENT")
    print("=" * 78)
    for k, v in env.items():
        print(f"  {k:14s}: {v}")

    out = {"environment": env}
    t_start = time.time()

    if args.quick:
        trials, bplan, mib, treps, preps, lreps = (
            1000, [(16, 30), (24, 30)], 16, 1, 1, 20_000)
    else:
        trials, bplan, mib, treps, preps, lreps = (
            10_000, [(16, 200), (24, 200), (32, 30)], 64, 3, 5, 200_000)

    sha_counts = None
    if want("avalanche"):
        out["avalanche"], sha_counts = run_avalanche(trials)
    if want("birthday"):
        out["birthday"] = run_birthday(bplan)
    if want("throughput"):
        out["throughput"] = run_throughput(mib, treps)
    if want("timing"):
        out["password_timing"] = run_password_timing(preps)
    if want("latency"):
        out["fast_latency_us"] = run_fast_latency(lreps)

    if not args.no_plots:
        print(f"\n{'='*78}\nFIGURES\n{'='*78}")
        if sha_counts:
            plot_avalanche(sha_counts, os.path.join(_HERE, "figure1_avalanche.png"))
        if out.get("throughput"):
            plot_throughput(out["throughput"], mib,
                            os.path.join(_HERE, "figure2_throughput.png"))

    with open(os.path.join(_HERE, args.json), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)

    print(f"\nTotal run time: {time.time() - t_start:.1f} s")
    print(f"Results written to {args.json}")


if __name__ == "__main__":
    main()
