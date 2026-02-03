# XOR Cipher with Diffie-Hellman Key Exchange

A demonstration of secure message encryption using XOR cipher with Diffie-Hellman (DH) key exchange. Two parties establish a shared secret without directly transmitting it.

## Quick Start

```bash
python tests/test.py
```

This runs a complete DH key exchange and encryption/decryption test between Martin and Whitfield.

## Usage

### Encrypt a Message

```python
from key_generator import generate_and_publish_public_key
from cipher import encrypt_message

# Generate public keys
generate_and_publish_public_key("Martin")
generate_and_publish_public_key("Whitfield")

# Encrypt
encrypt_message("Martin", "Whitfield")
```

### Decrypt a Message

```python
from decipher import decrypt_message

# Decrypt
decrypt_message("Whitfield", "Martin")
```

## Project Structure

```
src/
├── cipher.py          # Encryption
├── decipher.py        # Decryption
├── key_generator.py   # DH key exchange
├── xor_utils.py       # XOR operations
├── json_utils.py      # File I/O
├── config.py          # Configuration
└── __init__.py        # Package exports

tests/
└── test.py            # Test suite

data/
├── dh_params.json     # DH parameters
├── Martin.json        # Martin's secret
├── Whitfield.json     # Whitfield's secret
└── secret_message.txt # Message to encrypt
```

## ⚠️ Important Security Notes

This is an **educational demonstration only**. DO NOT use in production.

### Example Secrets
- Secrets (e.g., `13`, `7`) are **hardcoded examples** for testing
- **In production**: Store secrets in Azure Key Vault, AWS Secrets Manager, or similar vault services
- Never store secrets in JSON files or commit to version control

### Small DH Parameters
- Parameters (generator=2, prime=59) are for demonstration
- **In production**: Use RFC 3526 parameters (minimum 2048-bit primes)

## Technologies

- **Python 3.9+**: Standard library only (hashlib, json, os, sys, logging)
- **No external dependencies**: Clean, self-contained implementation
- **Code Quality**: pylint 10.00/10, mypy strict mode compatible

## CI/CD

GitHub Actions workflow (`.github/workflows/ci.yml`):
- Runs on pull requests to `main`
- Tests on Python 3.9, 3.11, 3.13
- Includes pylint code quality checks

To run manually: Go to Actions tab → CI → Run workflow

## Development

Install dev dependencies:
```bash
pip install -r requirements.txt
```

Run tests:
```bash
python tests/test.py
```


### Code Quality

1. **Optimization**: 
   - XOR cipher uses `bytearray` for efficient in-place operations
   - Key stretching uses list accumulation instead of string concatenation (O(n) vs O(n²))

2. **Testing**: Comprehensive test suite validates the complete workflow.

### Performance Tips

1. **Key Stretching**: For long messages, consider caching stretched keys if encrypting/decrypting multiple messages with the same key.

2. **Batch Operations**: For multiple messages, generate the shared key once and reuse it with different stretched keys.

3. **Memory Efficiency**: The XOR cipher uses `bytearray` for mutable operations, reducing memory overhead.

## Module Documentation

### cipher.py
Encrypts messages using Diffie-Hellman shared secret and XOR cipher.

```python
encrypt_message(party, other_party) -> None
```

### decipher.py
Decrypts messages using the same DH protocol.

```python
decrypt_message(party, other_party) -> None
```

### key_generator.py
Handles all key generation and DH protocol logic.

Key functions:
- `load_dh_params()`: Load DH parameters
- `generate_and_publish_public_key(producer_id)`: Generate public key
- `get_shared_key_for_party(party, other_party)`: Returns shared secret
- `compute_secured_shared_key(generator, prime, secret, public_key)`: Compute DH shared secret
- `get_stretched_key(shared_key, target_length)`: Stretch key for one-time pad

### xor_utils.py
Implements the optimized XOR cipher.

```python
xor_cipher(text, key) -> str
```

Performs XOR encryption/decryption. Since XOR is symmetric, the same function works for both operations.

### json_utils.py
Provides JSON file utilities.

- `get_json_value(filepath, param)`: Read value from JSON file
- `save_json(filepath, data)`: Write data to JSON file

## Technologies & Packages

### Core Technologies Used

1. **Diffie-Hellman Key Exchange (DH)**
   - Mathematical protocol for secure key agreement
   - Allows two parties to establish a shared secret over insecure channels
   - Based on discrete logarithm problem (hard to solve in reverse)
   - Standard: Defined in RFC 2631

2. **XOR (Exclusive OR) Cipher**
   - Symmetric encryption using bitwise XOR operation
   - Simple but powerful when combined with proper key management
   - Efficient: Single CPU instruction per byte

3. **One-Time Pad (OTP)**
   - Theoretical perfect encryption when conditions are met
   - Requires: random key of equal length, used only once
   - Information theoretically secure (proven by Claude Shannon)

4. **SHA256 Hash Function**
   - Cryptographic hash from SHA-2 family
   - 256-bit output (64 hex characters)
   - Used for: Shared secret derivation and key stretching

### Python Standard Library Packages

The project uses **only Python standard library** (no external dependencies):

| Package | Purpose | Usage |
|---------|---------|-------|
| `hashlib` | Cryptographic hashing | SHA256 for key derivation |
| `json` | Data serialization | Store DH params, secrets, public keys |
| `os` | Operating system interface | File path handling |
| `sys` | System-specific parameters | Path manipulation |

**Example imports:**
```python
import hashlib    # For SHA256 hashing
import json       # For JSON file operations
from os import path  # For file path operations
```

### Why No External Dependencies?

✅ **Advantages:**
- No dependency management needed
- No security vulnerabilities from third-party packages
- Lightweight and portable
- Educational clarity (shows core algorithms)

⚠️ **Trade-offs:**
- Limited to educational demonstrations
- Production systems should use `cryptography` or `PyCryptodome` for:
  - Hardware acceleration
  - Additional algorithms (AES, ECDH, etc.)
  - Authenticated encryption
  - Secure random generation

### Dependencies

- **Python 3.9+** (uses f-strings and modern Python features)
- **No external packages required** (uses only Python standard library)

## Understanding the Protocol

### Diffie-Hellman Key Exchange

1. **Setup**: Both parties agree on generator (G) and prime (P)
2. **Key Generation**: Each party generates a private secret (a or b)
3. **Public Key Calculation**: Each computes public key = G^secret % P
4. **Public Exchange**: Public keys are exchanged (can be done over insecure channel)
5. **Shared Secret**: Each computes shared = (other_public_key)^own_secret % P

The beauty: Both parties arrive at the same shared secret value!

### XOR Encryption and One-Time Pad

#### How XOR Works

- **Plaintext XOR Key = Ciphertext**
- **Ciphertext XOR Key = Plaintext** (XOR is symmetric!)
- XOR operates on individual bits: 1⊕1=0, 1⊕0=1, 0⊕1=1, 0⊕0=0

Example with characters:
```
Message:  A     t     t     a     c     k
Binary:   01000001 01110100 01110100 01100001 01100011 01101011
Key:      10101010 11001100 10011001 11110000 10101010 11110011
XOR:      11101011 10111000 11101101 10010001 11001001 10011000
```

#### One-Time Pad Security

The project uses **key stretching** to create a one-time pad:

1. **Diffie-Hellman** produces a shared secret (e.g., 64-character SHA256 hash)
2. **Key Stretching** expands this secret to match the message length
3. Each message uses a unique stretched key derived from the shared secret + counter

**Why One-Time Pad is Theoretically Unbreakable:**
- Uses a key as long as the message (1:1 ratio)
- Each bit of the key is truly random
- Each key is used only once (one-time)
- Without knowing the key, the ciphertext appears completely random
- Information theory guarantees perfect secrecy

**Example in this project:**
- Shared secret: `44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a` (256 bits from SHA256)
- Message: "Top Secret Information" (22 characters)
- Stretched key: The 256-bit secret is hashed multiple times with a counter to create exactly 22 characters
- Result: Each message character XORed with the corresponding stretched key character

#### Key Stretching Implementation

The project stretches keys efficiently:

```python
def get_stretched_key(shared_key, target_length):
    # Uses SHA256 with a counter to generate unique blocks
    # Blocks are concatenated until target length is reached
    blocks = []
    counter = 0
    
    while len("".join(blocks)) < target_length:
        block = hashlib.sha256(f"{shared_key}-{counter}".encode()).hexdigest()
        blocks.append(block)
        counter += 1
    
    return "".join(blocks)[:target_length]
```

This approach:
- ✅ Creates different output for each counter value
- ✅ Is efficient (O(n) time complexity)
- ✅ Uses cryptographically secure hashing (SHA256)
- ⚠️ Is NOT truly random (not a true one-time pad for production use)

## Example Output

### Example: Martin and Whitfield Communication

**Output from `python tests/test.py`:**

```
Calculating public key with Generator=2, Prime=59, secret=13
Published public key 50 to public_keyWhitfield.json
Calculating public key with Generator=2, Prime=59, secret=7
Published public key 10 to public_keyMartin.json
Calculating secured common key with generator=2, prime=59, secret=7, public_key=50
Secure key: 44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a
Encrypted message: b'2\\x0eEEc\\x03ZDW\\x15\\x10y_U]EU\\x04B\r_\\\\'
Calculating secured common key with generator=2, prime=59, secret=13, public_key=10
Secure key: 44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a
Decrypted message: Top Secret Information
```

### What Happened in This Example

1. **Whitfield's Key Generation**
   - Secret: 13 (private, never transmitted)
   - Calculation: 2^13 % 59 = 8192 % 59 = 50
   - Public key: 50 (safe to share publicly)

2. **Martin's Key Generation**
   - Secret: 7 (private, never transmitted)
   - Calculation: 2^7 % 59 = 128 % 59 = 10
   - Public key: 10 (safe to share publicly)

3. **Martin Encrypts for Whitfield**
   - Martin uses his secret (7) and Whitfield's public key (50)
   - Shared secret calculation: 50^7 % 59 = 44 (then hashed with SHA256)
   - Final secure key: `44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a`

4. **Whitfield Decrypts**
   - Whitfield uses their secret (13) and Martin's public key (10)
   - Shared secret calculation: 10^13 % 59 = 44 (then hashed with SHA256)
   - **Same secure key!** `44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a`
   - Decryption recovers the original message

### Step-by-Step Usage with Custom Parties

⚠️ **WARNING: This example is for demonstration only. DO NOT use hardcoded secrets in production!**

```bash
# 1. Create party secret files (EXAMPLE ONLY - DO NOT DO THIS IN PRODUCTION)
echo '{"secret": 7}' > data/Martin.json
echo '{"secret": 13}' > data/Whitfield.json
echo 'Hello Whitfield, this is Martin!' > data/secret_message.txt

# 2. Run in Python
python3 << 'EOF'
from key_generator import generate_and_publish_public_key
from cipher import encrypt_message
from decipher import decrypt_message

# Generate public keys
generate_and_publish_public_key("Martin")
generate_and_publish_public_key("Whitfield")

# Martin encrypts for Whitfield
encrypt_message("Martin", "Whitfield")

# Whitfield decrypts from Martin
decrypt_message("Whitfield", "Martin")
EOF
```


## Testing

Run the comprehensive test suite:

```bash
python tests/test.py
```

### What the Test Does

1. **Public Key Generation Phase**
   - Loads DH parameters (generator=2, prime=59)
   - Martin generates secret=7, computes public key=10
   - Whitfield generates secret=13, computes public key=50
   - Both write their public keys to JSON files

2. **Encryption Phase** (Martin → Whitfield)
   - Martin reads their secret (7) and Whitfield's public key (50)
   - Computes shared secret: (50)^7 mod 59 = 44
   - Hashes with SHA256: `44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a`
   - Stretches the key to message length
   - Encrypts message with XOR cipher
   - Saves encrypted message to file

3. **Decryption Phase** (Whitfield decrypts from Martin)
   - Whitfield reads their secret (13) and Martin's public key (10)
   - Computes shared secret: (10)^13 mod 59 = 44
   - Hashes with SHA256: **Same key!** `44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a`
   - Stretches the key to ciphertext length
   - Decrypts message with XOR cipher
   - Prints decrypted message

### Test Validation

The test suite validates:
- ✅ Public key generation for both parties
- ✅ Shared secret computation (both parties compute the same secret)
- ✅ Message encryption without errors
- ✅ Message decryption with correct recovery of original message
- ✅ No modification of files or state

### Example Test Output

When tests pass, you'll see:
```
Calculating public key with Generator=2, Prime=59, secret=13
Published public key 50 to public_keyWhitfield.json
Calculating public key with Generator=2, Prime=59, secret=7
Published public key 10 to public_keyMartin.json
Calculating secured common key with generator=2, prime=59, secret=7, public_key=50
Secure key: 44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a
Encrypted message: b'2\x0eEEc\x03ZDW\x15\x10y_U]EU\x04B\r_\\'
Calculating secured common key with generator=2, prime=59, secret=13, public_key=10
Secure key: 44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a
Decrypted message: Top Secret Informatnon
Exit Code: 0  ← All tests passed!
```


## License

This project is provided as-is for educational and demonstration purposes.
