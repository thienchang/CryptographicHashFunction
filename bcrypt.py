"""
Cryptographic Hash Function: bcrypt Implementation in Python
============================================================
This script provides bcrypt hashing and verification methods with
both interactive command-line interface (CLI) and CLI argument support.
"""

import sys
import os
import argparse
import importlib

# Ensure we import the installed 'bcrypt' library package, not this script file itself
_current_dir = os.path.dirname(os.path.abspath(__file__))
_orig_sys_path = list(sys.path)
try:
    sys.path = [p for p in sys.path if os.path.abspath(p or ".") != _current_dir]
    bcrypt_lib = importlib.import_module("bcrypt")
finally:
    sys.path = _orig_sys_path


def hash_password(password: str, rounds: int = 12) -> str:
    """
    Hash a plaintext password using bcrypt with a generated salt.

    :param password: The plain text password to hash.
    :param rounds: The cost factor (log2 rounds, standard is 12).
    :return: The bcrypt hashed string (UTF-8 encoded).
    """
    # bcrypt requires bytes as input
    password_bytes = password.encode("utf-8")
    salt = bcrypt_lib.gensalt(rounds=rounds)
    hashed_bytes = bcrypt_lib.hashpw(password_bytes, salt)
    return hashed_bytes.decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a stored bcrypt hash.

    :param password: The plain text password to check.
    :param hashed_password: The bcrypt hash to verify against.
    :return: True if the password matches, False otherwise.
    """
    password_bytes = password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    try:
        return bcrypt_lib.checkpw(password_bytes, hashed_bytes)
    except (ValueError, TypeError):
        return False


def inspect_bcrypt_hash(hash_str: str) -> dict:
    """
    Parse the standard modular crypt format of a bcrypt hash string:
    $[cost]$[salt + hash]
    Total length: usually 60 characters.
    """
    parts = hash_str.split("$")
    if len(parts) >= 4:
        version = parts[1]
        cost = parts[2]
        payload = parts[3]
        salt = payload[:22] if len(payload) >= 22 else ""
        checksum = payload[22:] if len(payload) > 22 else ""
        return {
            "valid_format": True,
            "version": f"${version}$",
            "cost_factor": cost,
            "iterations": 2 ** int(cost) if cost.isdigit() else "N/A",
            "salt_b64": salt,
            "checksum_b64": checksum,
            "length": len(hash_str)
        }
    return {"valid_format": False, "raw": hash_str}


def interactive_menu():
    """Interactive command-line prompt for the user."""
    print("=" * 60)
    print("    Bcrypt Cryptographic Hash Function Utility")
    print("=" * 60)

    while True:
        print("\nSelect an option:")
        print(" [1] Hash a password / text")
        print(" [2] Verify a password against a bcrypt hash")
        print(" [3] Run an automated demonstration")
        print(" [4] Exit")

        choice = input("\nEnter choice [1-4]: ").strip()

        if choice == "1":
            # Input from user
            password = input("\nEnter the string/password to hash: ")
            if not password:
                print("[-] Error: Input string cannot be empty.")
                continue

            cost_input = input("Enter cost factor (rounds) [default: 12, range 4-31]: ").strip()
            rounds = 12
            if cost_input:
                try:
                    rounds = int(cost_input)
                    if not (4 <= rounds <= 31):
                        print("[-] Cost factor must be between 4 and 31. Using default 12.")
                        rounds = 12
                except ValueError:
                    print("[-] Invalid number. Using default 12.")
                    rounds = 12

            print("\nComputing bcrypt hash (this may take a moment depending on cost)...")
            result_hash = hash_password(password, rounds=rounds)

            print("\n" + "-" * 60)
            print("HASH RESULT:")
            print(f"  Plaintext Input : {password}")
            print(f"  Bcrypt Hash     : {result_hash}")
            print("-" * 60)

            # Detailed breakdown
            info = inspect_bcrypt_hash(result_hash)
            if info["valid_format"]:
                print("Bcrypt Hash Components Breakdown:")
                print(f"  - Version       : {info['version']} (bcrypt algorithm)")
                print(f"  - Cost factor   : {info['cost_factor']} (2^{info['cost_factor']} = {info['iterations']} rounds)")
                print(f"  - Salt (22 char): {info['salt_b64']}")
                print(f"  - Checksum      : {info['checksum_b64']}")
                print(f"  - Total length  : {info['length']} characters")
            print("-" * 60)

        elif choice == "2":
            password = input("\nEnter the plaintext password to verify: ")
            stored_hash = input("Enter the bcrypt hash: ").strip()

            if not password or not stored_hash:
                print("[-] Error: Both password and hash are required.")
                continue

            print("\nVerifying...")
            is_valid = verify_password(password, stored_hash)

            print("-" * 60)
            if is_valid:
                print("[+] SUCCESS: Password matches the hash!")
            else:
                print("[-] FAILED: Password does NOT match the hash (or hash is malformed).")
            print("-" * 60)

        elif choice == "3":
            sample_pwd = "MySecretPassword123!"
            print(f"\n[Demo] Hashing sample password: '{sample_pwd}' with rounds=10...")
            hashed = hash_password(sample_pwd, rounds=10)
            print(f"[Demo] Generated Hash: {hashed}")

            print("[Demo] Testing valid match verification...")
            match_ok = verify_password(sample_pwd, hashed)
            print(f"[Demo] Result with '{sample_pwd}': {match_ok} (Expected: True)")

            wrong_pwd = "WrongPassword999"
            print(f"[Demo] Testing incorrect match verification with '{wrong_pwd}'...")
            mismatch_ok = verify_password(wrong_pwd, hashed)
            print(f"[Demo] Result with '{wrong_pwd}': {mismatch_ok} (Expected: False)")

        elif choice == "4":
            print("\nExiting. Goodbye!")
            sys.exit(0)
        else:
            print("[-] Invalid choice. Please choose 1, 2, 3, or 4.")


def main():
    parser = argparse.ArgumentParser(
        description="Bcrypt Cryptographic Hash Function Utility (Hashing & Verification)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Sub-command: hash
    hash_parser = subparsers.add_parser("hash", help="Hash a string")
    hash_parser.add_argument("-p", "--password", help="Plaintext password to hash")
    hash_parser.add_argument("-c", "--cost", type=int, default=12, help="Cost factor / log2 rounds (default: 12)")

    # Sub-command: verify
    verify_parser = subparsers.add_parser("verify", help="Verify a password against a bcrypt hash")
    verify_parser.add_argument("-p", "--password", help="Plaintext password to test")
    verify_parser.add_argument("-H", "--hash", help="Stored bcrypt hash")

    args = parser.parse_args()

    if args.command == "hash":
        pwd = args.password
        if pwd is None:
            pwd = input("Enter password to hash: ")
        result = hash_password(pwd, rounds=args.cost)
        print(f"Hash: {result}")
    elif args.command == "verify":
        pwd = args.password
        if pwd is None:
            pwd = input("Enter password: ")
        hash_val = args.hash
        if hash_val is None:
            hash_val = input("Enter bcrypt hash: ").strip()
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
