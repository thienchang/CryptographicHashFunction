"""
Cryptographic Hash Function: BLAKE2 Implementation in Python
============================================================
This script provides BLAKE2 (BLAKE2b and BLAKE2s) cryptographic hashing
and verification methods with both interactive command-line interface (CLI)
and CLI argument support.
Specified in RFC 7693. Highly optimized cryptographic hash function,
faster than MD5, SHA-1, SHA-2, and SHA-3, while providing maximum security.
"""

import sys
import hmac
import hashlib
import argparse


def hash_data(
    data: str,
    variant: str = "blake2b",
    digest_size: int = None,
    key: str = None,
    salt: str = None,
    person: str = None,
) -> str:
    """
    Hash input data/string using BLAKE2b (64-bit platforms) or BLAKE2s (8-32 bit platforms).

    :param data: The input string/message to hash.
    :param variant: 'blake2b' (up to 64 bytes) or 'blake2s' (up to 32 bytes).
    :param digest_size: Output digest size in bytes (1 to 64 for 2b, 1 to 32 for 2s).
    :param key: Optional secret key for keyed hashing (MAC).
    :param salt: Optional salt string (up to 16 bytes for 2b, up to 8 bytes for 2s).
    :param person: Optional personalization string (up to 16 bytes for 2b, up to 8 bytes for 2s).
    :return: Hexadecimal hash string.
    """
    variant_lower = variant.lower().strip()
    data_bytes = data.encode("utf-8")
    key_bytes = key.encode("utf-8") if key else b""

    kwargs = {}
    if key_bytes:
        kwargs["key"] = key_bytes

    if variant_lower == "blake2s":
        max_digest = 32
        max_salt_person = 8
        if digest_size is not None:
            kwargs["digest_size"] = min(max(1, digest_size), max_digest)
        else:
            kwargs["digest_size"] = 32

        if salt:
            kwargs["salt"] = salt.encode("utf-8")[:max_salt_person].ljust(max_salt_person, b"\x00")
        if person:
            kwargs["person"] = person.encode("utf-8")[:max_salt_person].ljust(max_salt_person, b"\x00")

        hasher = hashlib.blake2s(data_bytes, **kwargs)
    else:  # default blake2b
        max_digest = 64
        max_salt_person = 16
        if digest_size is not None:
            kwargs["digest_size"] = min(max(1, digest_size), max_digest)
        else:
            kwargs["digest_size"] = 64

        if salt:
            kwargs["salt"] = salt.encode("utf-8")[:max_salt_person].ljust(max_salt_person, b"\x00")
        if person:
            kwargs["person"] = person.encode("utf-8")[:max_salt_person].ljust(max_salt_person, b"\x00")

        hasher = hashlib.blake2b(data_bytes, **kwargs)

    return hasher.hexdigest()


def verify_hash(
    data: str,
    expected_hash: str,
    variant: str = "blake2b",
    digest_size: int = None,
    key: str = None,
    salt: str = None,
    person: str = None,
) -> bool:
    """
    Verify whether the hash of input data matches an expected hash in constant time.

    :param data: The input string/message to check.
    :param expected_hash: The hexadecimal hash string to verify against.
    :return: True if match, False otherwise.
    """
    computed_hash = hash_data(
        data=data,
        variant=variant,
        digest_size=digest_size,
        key=key,
        salt=salt,
        person=person,
    )
    # Use hmac.compare_digest for constant-time comparison (prevents timing attacks)
    return hmac.compare_digest(computed_hash.lower().strip(), expected_hash.lower().strip())


def inspect_blake2_hash(hash_hex: str, variant: str, digest_size: int, is_keyed: bool) -> dict:
    """
    Analyze and break down the cryptographic properties of the BLAKE2 hash output.
    """
    clean_hex = hash_hex.strip()
    byte_len = len(clean_hex) // 2
    bit_len = byte_len * 8

    return {
        "variant": variant.upper(),
        "mode": "Keyed Hash (MAC / Authentication)" if is_keyed else "Unkeyed Cryptographic Hash",
        "digest_bytes": byte_len,
        "digest_bits": bit_len,
        "hex_length": len(clean_hex),
        "security_level": f"{bit_len // 2}-bit collision resistance, {bit_len}-bit preimage resistance",
    }


def interactive_menu():
    """Interactive command-line prompt for the user."""
    print("=" * 60)
    print("    BLAKE2 Cryptographic Hash Function Utility (RFC 7693)")
    print("    High-Speed, High-Security Hashing (BLAKE2b / BLAKE2s)")
    print("=" * 60)

    while True:
        print("\nSelect an option:")
        print(" [1] Hash a message / text")
        print(" [2] Verify a message against an expected BLAKE2 hash")
        print(" [3] Run an automated demonstration")
        print(" [4] Exit")

        choice = input("\nEnter choice [1-4]: ").strip()

        if choice == "1":
            data = input("\nEnter the string/message to hash: ")
            if not data:
                print("[-] Error: Input string cannot be empty.")
                continue

            print("\nSelect BLAKE2 variant:")
            print(" [1] BLAKE2b (Optimized for 64-bit CPUs, digest up to 64 bytes / 512 bits)")
            print(" [2] BLAKE2s (Optimized for 8-to-32-bit CPUs, digest up to 32 bytes / 256 bits)")
            var_choice = input("Enter variant [1-2, default 1]: ").strip()
            variant = "blake2s" if var_choice == "2" else "blake2b"

            default_size = 32 if variant == "blake2s" else 64
            max_size = 32 if variant == "blake2s" else 64
            size_input = input(f"Enter digest size in bytes [1-{max_size}, default {default_size}]: ").strip()
            digest_size = int(size_input) if size_input.isdigit() and 1 <= int(size_input) <= max_size else default_size

            key_input = input("Enter optional secret key (for MAC / keyed hashing, press Enter to skip): ").strip()
            key = key_input if key_input else None

            print(f"\nComputing {variant.upper()} ({digest_size} bytes / {digest_size * 8} bits)...")
            result_hash = hash_data(data, variant=variant, digest_size=digest_size, key=key)

            print("\n" + "-" * 60)
            print("HASH RESULT:")
            print(f"  Input Message   : {data}")
            print(f"  BLAKE2 Hash     : {result_hash}")
            print("-" * 60)

            # Breakdown
            info = inspect_blake2_hash(result_hash, variant, digest_size, bool(key))
            print("BLAKE2 Hash Components Breakdown:")
            print(f"  - Algorithm     : {info['variant']}")
            print(f"  - Hash Mode     : {info['mode']}")
            print(f"  - Digest Size   : {info['digest_bytes']} bytes ({info['digest_bits']} bits)")
            print(f"  - Hex Length    : {info['hex_length']} hex characters")
            print(f"  - Security      : {info['security_level']}")
            print("-" * 60)

        elif choice == "2":
            data = input("\nEnter the plaintext message: ")
            expected_hash = input("Enter the expected BLAKE2 hash (hex): ").strip()

            if not data or not expected_hash:
                print("[-] Error: Both message and hash are required.")
                continue

            print("\nSelect BLAKE2 variant:")
            print(" [1] BLAKE2b (default)")
            print(" [2] BLAKE2s")
            var_choice = input("Enter variant [1-2, default 1]: ").strip()
            variant = "blake2s" if var_choice == "2" else "blake2b"

            expected_bytes = len(expected_hash) // 2
            key_input = input("Enter secret key (if keyed hash was used, press Enter if unkeyed): ").strip()
            key = key_input if key_input else None

            print("\nVerifying...")
            is_valid = verify_hash(data, expected_hash, variant=variant, digest_size=expected_bytes, key=key)

            print("-" * 60)
            if is_valid:
                print("[+] SUCCESS: Hash matches the input message!")
            else:
                print("[-] FAILED: Hash does NOT match the input message (or parameters differ).")
            print("-" * 60)

        elif choice == "3":
            sample_msg = "Hello Cryptographic Hash Function!"
            print(f"\n[Demo 1] BLAKE2b-512 (default 64-byte digest):")
            h2b = hash_data(sample_msg, variant="blake2b", digest_size=64)
            print(f"  Input : '{sample_msg}'")
            print(f"  Hash  : {h2b}")
            print(f"  Verify: {verify_hash(sample_msg, h2b, variant='blake2b', digest_size=64)} (Expected: True)")

            print(f"\n[Demo 2] BLAKE2b-256 (arbitrary digest size = 32 bytes):")
            h2b_256 = hash_data(sample_msg, variant="blake2b", digest_size=32)
            print(f"  Hash  : {h2b_256}")
            print(f"  Verify: {verify_hash(sample_msg, h2b_256, variant='blake2b', digest_size=32)} (Expected: True)")

            print(f"\n[Demo 3] BLAKE2s-256 (32-bit architecture optimized, 32-byte digest):")
            h2s = hash_data(sample_msg, variant="blake2s", digest_size=32)
            print(f"  Hash  : {h2s}")
            print(f"  Verify: {verify_hash(sample_msg, h2s, variant='blake2s', digest_size=32)} (Expected: True)")

            print(f"\n[Demo 4] Keyed BLAKE2b (MAC with secret key):")
            secret = "SecretKey_12345"
            h_mac = hash_data(sample_msg, variant="blake2b", digest_size=64, key=secret)
            print(f"  Key   : '{secret}'")
            print(f"  MAC   : {h_mac}")
            print(f"  Verify with correct key : {verify_hash(sample_msg, h_mac, variant='blake2b', digest_size=64, key=secret)} (Expected: True)")
            print(f"  Verify with wrong key   : {verify_hash(sample_msg, h_mac, variant='blake2b', digest_size=64, key='WrongKey')} (Expected: False)")

        elif choice == "4":
            print("\nExiting. Goodbye!")
            sys.exit(0)
        else:
            print("[-] Invalid choice. Please choose 1, 2, 3, or 4.")


def main():
    parser = argparse.ArgumentParser(
        description="BLAKE2 Cryptographic Hash Function Utility (RFC 7693)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Sub-command: hash
    hash_parser = subparsers.add_parser("hash", help="Hash a string using BLAKE2")
    hash_parser.add_argument("-d", "--data", "-p", "--password", dest="data", help="Input message/data to hash")
    hash_parser.add_argument(
        "--variant",
        choices=["blake2b", "blake2s"],
        default="blake2b",
        help="BLAKE2 variant (default: blake2b)",
    )
    hash_parser.add_argument(
        "-s", "--size",
        type=int,
        default=None,
        help="Digest size in bytes (blake2b: 1-64 [default 64], blake2s: 1-32 [default 32])",
    )
    hash_parser.add_argument("-k", "--key", help="Optional secret key for keyed hashing (MAC)")
    hash_parser.add_argument("--salt", help="Optional salt string")
    hash_parser.add_argument("--person", help="Optional personalization string")

    # Sub-command: verify
    verify_parser = subparsers.add_parser("verify", help="Verify a message against a BLAKE2 hash")
    verify_parser.add_argument("-d", "--data", "-p", "--password", dest="data", help="Input message/data to test")
    verify_parser.add_argument("-H", "--hash", help="Expected BLAKE2 hexadecimal hash")
    verify_parser.add_argument(
        "--variant",
        choices=["blake2b", "blake2s"],
        default="blake2b",
        help="BLAKE2 variant (default: blake2b)",
    )
    verify_parser.add_argument("-s", "--size", type=int, default=None, help="Digest size in bytes")
    verify_parser.add_argument("-k", "--key", help="Optional secret key for keyed hashing")

    args = parser.parse_args()

    if args.command == "hash":
        data_val = args.data
        if data_val is None:
            data_val = input("Enter data to hash: ")
        result = hash_data(
            data=data_val,
            variant=args.variant,
            digest_size=args.size,
            key=args.key,
            salt=args.salt,
            person=args.person,
        )
        print(f"Hash: {result}")
    elif args.command == "verify":
        data_val = args.data
        if data_val is None:
            data_val = input("Enter data to verify: ")
        hash_val = args.hash
        if hash_val is None:
            hash_val = input("Enter BLAKE2 hash: ").strip()

        digest_bytes = args.size if args.size is not None else (len(hash_val) // 2)

        matched = verify_hash(
            data=data_val,
            expected_hash=hash_val,
            variant=args.variant,
            digest_size=digest_bytes,
            key=args.key,
        )
        if matched:
            print("[+] MATCH: Hash matches input data.")
        else:
            print("[-] NO MATCH: Hash does not match input data.")
            sys.exit(1)
    else:
        # If no CLI subcommands provided, enter interactive mode
        interactive_menu()


if __name__ == "__main__":
    main()
