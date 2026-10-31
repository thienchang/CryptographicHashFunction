"""
Cryptographic Hash Function: Argon2 Implementation in Python
============================================================
This script provides Argon2 (Argon2id, Argon2i, Argon2d) hashing and verification
methods with both interactive command-line interface (CLI) and CLI argument support.
Winner of the Password Hashing Competition (PHC, 2015).
"""

import sys
import os
import argparse
import importlib

# Ensure we import the installed 'argon2' library package, not this script file itself
_current_dir = os.path.dirname(os.path.abspath(__file__))
_orig_sys_path = list(sys.path)
try:
    sys.path = [p for p in sys.path if os.path.abspath(p or ".") != _current_dir]
    argon2_lib = importlib.import_module("argon2")
    PasswordHasher = argon2_lib.PasswordHasher
    Type = argon2_lib.Type
    exceptions = importlib.import_module("argon2.exceptions")
    VerifyMismatchError = exceptions.VerifyMismatchError
    VerificationError = exceptions.VerificationError
    InvalidHashError = exceptions.InvalidHashError
finally:
    sys.path = _orig_sys_path

# Mapping string representations to argon2 Type enum
ARGON2_TYPES = {
    "argon2id": Type.ID,
    "argon2i": Type.I,
    "argon2d": Type.D,
}


def hash_password(
    password: str,
    time_cost: int = 3,
    memory_cost: int = 65536,
    parallelism: int = 4,
    hash_len: int = 32,
    salt_len: int = 16,
    variant: str = "argon2id",
) -> str:
    """
    Hash a plaintext password using Argon2.

    :param password: The plain text password to hash.
    :param time_cost: Iterations / number of passes over memory (t).
    :param memory_cost: Memory usage in KiB (m). Default 65536 KiB = 64 MiB.
    :param parallelism: Number of parallel threads/lanes (p).
    :param hash_len: Length of the generated hash key in bytes.
    :param salt_len: Length of the random salt in bytes.
    :param variant: Argon2 variant: 'argon2id' (recommended), 'argon2i', or 'argon2d'.
    :return: Formatted modular crypt Argon2 hash string.
    """
    variant_lower = variant.lower()
    argon_type = ARGON2_TYPES.get(variant_lower, Type.ID)

    ph = PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        salt_len=salt_len,
        type=argon_type,
    )
    return ph.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against an existing Argon2 hash.

    :param password: The plain text password to check.
    :param hashed_password: The Argon2 formatted hash string to verify against.
    :return: True if the password matches, False otherwise.
    """
    ph = PasswordHasher()
    try:
        return ph.verify(hashed_password, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def inspect_argon2_hash(hash_str: str) -> dict:
    """
    Parse the standard modular crypt format of an Argon2 hash string:
    $[type]$v=[version]$m=[mem],t=[time],p=[threads]$[salt_b64]$[hash_b64]
    """
    parts = hash_str.split("$")
    # Expected format: ['', type, 'v=19', 'm=65536,t=3,p=4', salt, hash]
    if len(parts) >= 6:
        variant = parts[1]
        version = parts[2]
        params_str = parts[3]
        salt = parts[4]
        checksum = parts[5]

        params = {}
        for item in params_str.split(","):
            if "=" in item:
                k, v = item.split("=", 1)
                params[k] = v

        mem_kib = int(params.get("m", 0)) if params.get("m", "").isdigit() else 0
        mem_mb = round(mem_kib / 1024, 2)

        return {
            "valid_format": True,
            "variant": variant,
            "version": version,
            "time_cost": params.get("t", "N/A"),
            "memory_cost_kib": mem_kib,
            "memory_cost_mb": mem_mb,
            "parallelism": params.get("p", "N/A"),
            "salt_b64": salt,
            "checksum_b64": checksum,
            "length": len(hash_str),
        }
    return {"valid_format": False, "raw": hash_str}


def interactive_menu():
    """Interactive command-line prompt for the user."""
    print("=" * 60)
    print("    Argon2 Cryptographic Hash Function Utility")
    print("    (Winner of the Password Hashing Competition)")
    print("=" * 60)

    while True:
        print("\nSelect an option:")
        print(" [1] Hash a password / text")
        print(" [2] Verify a password against an Argon2 hash")
        print(" [3] Run an automated demonstration")
        print(" [4] Exit")

        choice = input("\nEnter choice [1-4]: ").strip()

        if choice == "1":
            password = input("\nEnter the string/password to hash: ")
            if not password:
                print("[-] Error: Input string cannot be empty.")
                continue

            print("\nSelect Argon2 variant:")
            print(" [1] Argon2id (Recommended: Hybrid defense against side-channel & GPU)")
            print(" [2] Argon2i  (Data-independent memory access: best for side-channel defense)")
            print(" [3] Argon2d  (Data-dependent memory access: maximum resistance to GPU/ASIC cracking)")
            variant_choice = input("Enter variant [1-3, default 1]: ").strip()
            variant_map = {"1": "argon2id", "2": "argon2i", "3": "argon2d"}
            variant = variant_map.get(variant_choice, "argon2id")

            # Time cost (t)
            time_cost_input = input("Enter time cost / iterations (t) [default: 3]: ").strip()
            time_cost = int(time_cost_input) if time_cost_input.isdigit() and int(time_cost_input) > 0 else 3

            # Memory cost (m in KiB)
            mem_input = input("Enter memory cost in KiB (m) [default: 65536 = 64MB]: ").strip()
            memory_cost = int(mem_input) if mem_input.isdigit() and int(mem_input) >= 8 else 65536

            # Parallelism (p)
            threads_input = input("Enter parallelism / threads (p) [default: 4]: ").strip()
            parallelism = int(threads_input) if threads_input.isdigit() and int(threads_input) > 0 else 4

            print(f"\nComputing {variant.upper()} hash (memory: {memory_cost} KiB, time: {time_cost}, threads: {parallelism})...")
            result_hash = hash_password(
                password=password,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                variant=variant,
            )

            print("\n" + "-" * 60)
            print("HASH RESULT:")
            print(f"  Plaintext Input : {password}")
            print(f"  Argon2 Hash     : {result_hash}")
            print("-" * 60)

            # Detailed breakdown
            info = inspect_argon2_hash(result_hash)
            if info["valid_format"]:
                print("Argon2 Hash Components Breakdown:")
                print(f"  - Variant       : {info['variant']} (Type: {info['variant'].upper()})")
                print(f"  - Version       : {info['version']}")
                print(f"  - Time Cost (t) : {info['time_cost']} iterations")
                print(f"  - Memory (m)    : {info['memory_cost_kib']} KiB (~{info['memory_cost_mb']} MiB)")
                print(f"  - Parallelism(p): {info['parallelism']} threads")
                print(f"  - Salt (Base64) : {info['salt_b64']}")
                print(f"  - Checksum(B64) : {info['checksum_b64']}")
                print(f"  - Total length  : {info['length']} characters")
            print("-" * 60)

        elif choice == "2":
            password = input("\nEnter the plaintext password to verify: ")
            stored_hash = input("Enter the Argon2 hash: ").strip()

            if not password or not stored_hash:
                print("[-] Error: Both password and hash are required.")
                continue

            print("\nVerifying...")
            is_valid = verify_password(password, stored_hash)

            print("-" * 60)
            if is_valid:
                print("[+] SUCCESS: Password matches the Argon2 hash!")
            else:
                print("[-] FAILED: Password does NOT match the hash (or hash is malformed).")
            print("-" * 60)

        elif choice == "3":
            sample_pwd = "MySecretPassword123!"
            print(f"\n[Demo] Hashing sample password: '{sample_pwd}' using Argon2id...")
            hashed = hash_password(sample_pwd, time_cost=2, memory_cost=32768, parallelism=2, variant="argon2id")
            print(f"[Demo] Generated Hash:\n       {hashed}")

            print("\n[Demo] Testing valid match verification...")
            match_ok = verify_password(sample_pwd, hashed)
            print(f"[Demo] Result with '{sample_pwd}': {match_ok} (Expected: True)")

            wrong_pwd = "WrongPassword999"
            print(f"\n[Demo] Testing incorrect match verification with '{wrong_pwd}'...")
            mismatch_ok = verify_password(wrong_pwd, hashed)
            print(f"[Demo] Result with '{wrong_pwd}': {mismatch_ok} (Expected: False)")

        elif choice == "4":
            print("\nExiting. Goodbye!")
            sys.exit(0)
        else:
            print("[-] Invalid choice. Please choose 1, 2, 3, or 4.")


def main():
    parser = argparse.ArgumentParser(
        description="Argon2 Cryptographic Hash Function Utility (Hashing & Verification)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Sub-command: hash
    hash_parser = subparsers.add_parser("hash", help="Hash a string using Argon2")
    hash_parser.add_argument("-p", "--password", help="Plaintext password to hash")
    hash_parser.add_argument(
        "--variant",
        choices=["argon2id", "argon2i", "argon2d"],
        default="argon2id",
        help="Argon2 variant (default: argon2id)",
    )
    hash_parser.add_argument("-t", "--time-cost", type=int, default=3, help="Time cost / iterations (default: 3)")
    hash_parser.add_argument("-m", "--memory-cost", type=int, default=65536, help="Memory cost in KiB (default: 65536)")
    hash_parser.add_argument("-k", "--parallelism", type=int, default=4, help="Parallelism / threads (default: 4)")

    # Sub-command: verify
    verify_parser = subparsers.add_parser("verify", help="Verify a password against an Argon2 hash")
    verify_parser.add_argument("-p", "--password", help="Plaintext password to test")
    verify_parser.add_argument("-H", "--hash", help="Stored Argon2 hash string")

    args = parser.parse_args()

    if args.command == "hash":
        pwd = args.password
        if pwd is None:
            pwd = input("Enter password to hash: ")
        result = hash_password(
            password=pwd,
            time_cost=args.time_cost,
            memory_cost=args.memory_cost,
            parallelism=args.parallelism,
            variant=args.variant,
        )
        print(f"Hash: {result}")
    elif args.command == "verify":
        pwd = args.password
        if pwd is None:
            pwd = input("Enter password: ")
        hash_val = args.hash
        if hash_val is None:
            hash_val = input("Enter Argon2 hash: ").strip()
        matched = verify_password(pwd, hash_val)
        if matched:
            print("[+] MATCH: Password matches hash.")
        else:
            print("[-] NO MATCH: Password does not match hash.")
            sys.exit(1)
    else:
        # If no CLI subcommands provided, enter interactive mode
        interactive_menu()


if __name__ == "__main__":
    main()
