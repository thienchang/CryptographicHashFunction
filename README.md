# Cryptographic Hash Functions: Bcrypt, Argon2 & BLAKE2

This project implements modern cryptographic hashing, key-derivation, and verification algorithms:
- **bcrypt** (`bcrypt.py`): Blowfish-based adaptive hashing algorithm.
- **Argon2** (`argon2.py`): Winner of the Password Hashing Competition (PHC, 2015), offering memory-hard security.
- **BLAKE2** (`BLAKE2.py`): High-speed cryptographic hash specified in RFC 7693, faster than MD5/SHA while offering maximum 256/512-bit security and native keyed MAC support.

---

## Prerequisites

Install dependencies:

```bash
pip install -r requirements.txt
```

*(Note: `BLAKE2` uses Python's standard library `hashlib` and requires no additional packages).*

---

## 1. Bcrypt (`bcrypt.py`)

### Interactive Mode:
```bash
python bcrypt.py
```

### CLI Arguments Mode:
* **Hash:**
  ```bash
  python bcrypt.py hash -p "MyPassword123" -c 12
  ```
* **Verify:**
  ```bash
  python bcrypt.py verify -p "MyPassword123" -H "$2b$12$..."
  ```

---

## 2. Argon2 (`argon2.py`)

Supports `Argon2id` (recommended hybrid), `Argon2i` (side-channel resistant), and `Argon2d` (GPU-cracking resistant).

### Interactive Mode:
```bash
python argon2.py
```

### CLI Arguments Mode:
* **Hash:**
  ```bash
  python argon2.py hash -p "MyPassword123" --variant argon2id -t 3 -m 65536 -k 4
  ```
* **Verify:**
  ```bash
  python argon2.py verify -p "MyPassword123" -H "$argon2id$v=19$m=65536,t=3,p=4$..."
  ```

---

## 3. BLAKE2 (`BLAKE2.py`)

Supports `BLAKE2b` (64-bit optimized, up to 64-byte digest) and `BLAKE2s` (8-32 bit optimized, up to 32-byte digest), plus optional keyed hashing (MAC).

### Interactive Mode:
```bash
python BLAKE2.py
```

### CLI Arguments Mode:
* **Hash (standard unkeyed):**
  ```bash
  python BLAKE2.py hash -d "MyMessageOrPassword" --variant blake2b -s 64
  ```

* **Hash (keyed MAC):**
  ```bash
  python BLAKE2.py hash -d "MyMessage" --variant blake2b -k "MySecretKey"
  ```

* **Verify:**
  ```bash
  python BLAKE2.py verify -d "MyMessageOrPassword" -H "f6dea6a3803e..." --variant blake2b
  ```
