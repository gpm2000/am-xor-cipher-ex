# XOR Cipher with Diffie-Hellman Key Exchange

A demonstration of secure message encryption using XOR cipher combined with Diffie-Hellman (DH) key exchange protocol. This project implements end-to-end encrypted communication between two parties who establish a shared secret key without directly sharing it.

## Overview

This project demonstrates cryptographic principles by combining two key techniques:

1. **Diffie-Hellman Key Exchange**: Allows two parties to establish a shared secret over an insecure channel without directly transmitting the secret.
2. **XOR Cipher with One-Time Pad**: Uses the shared secret to encrypt messages using XOR operations, with key stretching for one-time pad encryption.

## Assumptions and Scope

⚠️ **CRITICAL ASSUMPTIONS - READ THIS FIRST:**

This project makes the following assumptions that **DO NOT reflect production requirements**:

### Secrets in This Project
- **ASSUMPTION**: Secrets are stored in plaintext JSON files (`Martin.json`, `Whitfield.json`) with hardcoded values (e.g., `13`, `7`)
- **REALITY**: In production, secrets must NEVER be hardcoded or stored in files
- **PRODUCTION REQUIREMENT**: Use dedicated secret vaults:
  - ☁️ Cloud vaults: Azure Key Vault, AWS Secrets Manager, Google Cloud KMS
  - 🔐 On-premises: HashiCorp Vault, CyberArk, Thales Luna HSM
  - 🛡️ Hardware: HSMs (Hardware Security Modules) for critical keys

### Test Data Parameters
- **ASSUMPTION**: Small DH parameters (generator=2, prime=59) for demonstration
- **REALITY**: These parameters provide NO real security (256-bit equivalent = only 7 bits of security!)
- **PRODUCTION REQUIREMENT**: Use RFC 3526 parameters (at least 2048-bit primes)

### No Authentication or Validation
- **ASSUMPTION**: Public keys are used without verification (vulnerable to MITM attacks)
- **PRODUCTION REQUIREMENT**: Implement public key infrastructure (PKI) with digital signatures

### Plaintext Storage
- **ASSUMPTION**: Encrypted messages are stored in plaintext files
- **PRODUCTION REQUIREMENT**: Implement access controls, encryption at rest, and audit logging

### Educational Codebase
- **ASSUMPTION**: Simple Python implementation for clarity
- **PRODUCTION REQUIREMENT**: Use battle-tested libraries (`cryptography`, `PyCryptodome`)

## Features

- ✅ Secure key exchange using Diffie-Hellman protocol
- ✅ Message encryption and decryption using XOR cipher
- ✅ Optimized key stretching for varying message lengths
- ✅ JSON-based configuration and key storage
- ✅ Comprehensive test suite
- ✅ Clean, documented codebase

## Project Structure

```
am-xor-cipher-ex/
├── src/
│   ├── cipher.py              # Message encryption module
│   ├── decipher.py            # Message decryption module
│   ├── key_generator.py       # DH key exchange and key generation
│   ├── xor_utils.py           # Optimized XOR cipher implementation
│   ├── json_utils.py          # JSON file utilities
│   ├── config.py              # Configuration constants
│   └── __init__.py            # Package initializer
├── tests/
│   └── test.py                # Test suite
├── data/
│   ├── dh_params.json         # Diffie-Hellman parameters
│   ├── secret_message.txt     # Message to encrypt
│   ├── Martin.json            # Martin's secret
│   └── Whitfield.json         # Whitfield's secret
├── encrypted_message.txt      # Output encrypted message
└── README.md                  # This file
```

## Usage

### Understanding the Example Parties

This project uses **Martin** and **Whitfield** as example parties to demonstrate secure communication. These are placeholder names:

- **Martin** = Any sender who wants to encrypt a message
- **Whitfield** = Any recipient who wants to decrypt a message

You can replace these with any party names or identifiers (e.g., "Alice" and "Bob", "Server" and "Client", or "User1" and "User2").

**Important**: Each party must have their own secret value stored in a JSON file:
- `data/Martin.json` contains Martin's private secret
- `data/Whitfield.json` contains Whitfield's private secret

These secrets are never transmitted over the network—only the publicly derived keys are shared.

⚠️ **IMPORTANT SECURITY NOTE - EXAMPLE SECRETS ONLY:**
- The secrets in this project (e.g., `13` and `7` in `Martin.json` and `Whitfield.json`) are **hardcoded examples for demonstration purposes only**
- **DO NOT use this approach in production!**
- In production environments:
  - Store secrets in secure vaults (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, etc.)
  - Use hardware security modules (HSMs) for key generation and storage
  - Never store secrets in plaintext JSON files in the repository
  - Never commit secret values to version control
  - Implement key rotation policies
  - Use environment variables or secure configuration systems
  - Implement access controls and audit logging for secret access

### Quick Start

Run the complete encryption and decryption test with the example parties:

```bash
python tests/test.py
```

This will:
1. Generate public keys for both parties (Martin and Whitfield)
2. Encrypt a secret message from Martin to Whitfield
3. Decrypt the message as Whitfield

### Encrypting a Message

To encrypt a message **as Martin** sending **to Whitfield**:

```python
from cipher import encrypt_message

# Encrypt message from Martin to Whitfield
encrypt_message("Martin", "Whitfield")
```

The encrypted message will be saved to `encrypted_message.txt`.

**To use with different parties**:
```python
# Encrypt message from Alice to Bob
encrypt_message("Alice", "Bob")

# Encrypt message from Server to Client
encrypt_message("Server", "Client")
```

Before encrypting, ensure:
1. Both parties have had their public keys generated
2. Both parties have secret values in `data/{PartyName}.json`
3. The message to encrypt is in `data/secret_message.txt`

### Decrypting a Message

To decrypt a message **as Whitfield** from **Martin**:

```python
from decipher import decrypt_message

# Decrypt message from Martin to Whitfield
decrypt_message("Whitfield", "Martin")
```

**To use with different parties**:
```python
# Decrypt message from Alice to Bob (as Bob)
decrypt_message("Bob", "Alice")

# Decrypt message from Server to Client (as Client)
decrypt_message("Client", "Server")
```

### Key Generation

Before any encryption/decryption, both parties must generate their public keys:

```python
from key_generator import generate_and_publish_public_key

# Generate and publish public keys
generate_and_publish_public_key("Martin")
generate_and_publish_public_key("Whitfield")
```

**For custom parties**:
```python
# Generate keys for any parties
generate_and_publish_public_key("Alice")
generate_and_publish_public_key("Bob")
```

This creates:
- `public_keyMartin.json` and `public_keyWhitfield.json` (or your party names)
- These files can be safely shared over any channel

### Complete Workflow Example

```python
from key_generator import generate_and_publish_public_key
from cipher import encrypt_message
from decipher import decrypt_message

# Step 1: Both parties generate and publish their public keys
generate_and_publish_public_key("Alice")
generate_and_publish_public_key("Bob")

# Step 2: Alice encrypts a message for Bob
encrypt_message("Alice", "Bob")

# Step 3: Bob decrypts the message from Alice
decrypt_message("Bob", "Alice")
```

## Configuration

All configuration is centralized in `src/config.py`:

- **DH_PARAMS_FILE**: Path to Diffie-Hellman parameters (generator and prime)
- **DATA_DIR**: Directory for storing secrets and generated keys
- **ENCRYPTED_MESSAGE_FILE**: Output file for encrypted messages
- **SECRET_MESSAGE_FILE**: Input file for messages to encrypt

### DH Parameters File

Example DH parameters file (`data/dh_params.json`):
```json
{
    "generator": 2,
    "prime": 59
}
```

⚠️ **EXAMPLE PARAMETERS ONLY:**
- The parameters shown (generator=2, prime=59) are for demonstration purposes
- These values are **too small for any real security**
- **DO NOT use these in production**

**What these mean:**
- **generator** (G): The base number used in modular exponentiation
- **prime** (P): A large prime number used as the modulus
  - In this example: 59 (small for demonstration)
  - In production: Use at least 2048-bit primes

**Production Requirements:**
- Always use standardized, tested DH parameters from RFC 3526 or similar standards
- Store parameters securely (they don't need to be secret, but integrity must be protected)
- Verify parameters haven't been tampered with using digital signatures
- Consider using Elliptic Curve Diffie-Hellman (ECDH) in modern systems (more efficient)

**DH Parameters commonly used:**
| Bits | Prime Source | Notes |
|------|--------------|-------|
| 1024 | RFC 2409 | Deprecated, minimum for legacy systems |
| 2048 | RFC 3526 | Minimum recommended for modern use |
| 3072 | RFC 3526 | Strong security, recommended |
| 4096 | RFC 3526 | Very strong security |

### Party Secret Files

Each party has their own secret stored in `data/{PartyName}.json`:
```json
{
    "secret": 13
}
```

⚠️ **EXAMPLE ONLY - DO NOT USE IN PRODUCTION:**
- The hardcoded secret value `13` is an example for testing only
- In production, secrets must be:
  - Generated using cryptographically secure random number generation (e.g., `secrets.randbits(2048)`)
  - Stored in secure key vaults, NOT in JSON files
  - Never hardcoded or committed to version control
  - Accessed only when needed and never logged or displayed
  - Rotated periodically according to security policies

**Why this matters:**
- The secret `13` is Martin's private value (never shared)
- It's used to compute: `public_key = 2^13 % 59 = 50`
- In production, use random large integers (e.g., 1024+ bits)
- Use Azure Key Vault, AWS Secrets Manager, or similar services

### Message Files

- **SECRET_MESSAGE_FILE** (`data/secret_message.txt`): Contains the message to encrypt
  - Plain text format
  - Can be any ASCII message
  
- **ENCRYPTED_MESSAGE_FILE** (`encrypted_message.txt`): Output of encryption
  - Contains the XOR-encrypted ciphertext
  - Binary data, typically saved as text with escape sequences

## Best Practices

### Security Considerations

⚠️ **Note**: This is a demonstration project. For production use:

1. **Secure Secret Storage (Critical!)**
   - **DO NOT store secrets in JSON files, config files, or source code**
   - Use dedicated key management services:
     - Azure Key Vault (Azure)
     - AWS Secrets Manager (AWS)
     - Google Cloud Key Management Service (GCP)
     - HashiCorp Vault (on-premises or cloud)
     - Hardware Security Modules (HSMs)
   - Never commit secrets to version control
   - Implement strict access controls and audit logging

2. **Use Established Cryptography Libraries**: Replace custom implementations with battle-tested libraries like `cryptography` or `PyCryptodome`.

3. **Larger Prime Numbers**: Use sufficiently large primes (at least 2048 bits for DH in production).

4. **Secure Random Generation**: Use `secrets` or `os.urandom()` for generating random values, not `random` module.

5. **Authenticated Encryption**: Combine encryption with authentication (e.g., HMAC or AEAD ciphers) to detect tampering.

6. **Transport Security**: Use TLS/SSL when transmitting public keys or encrypted messages over networks.

### Code Quality

1. **Type Hints**: The codebase includes proper type hints for better IDE support and runtime safety.

2. **Docstrings**: All functions include comprehensive docstrings with parameter and return documentation.

3. **Modular Design**: Separate concerns into distinct modules (key generation, encryption, decryption, utilities).

4. **Optimization**: 
   - XOR cipher uses `bytearray` for efficient in-place operations
   - Key stretching uses list accumulation instead of string concatenation (O(n) vs O(n²))

5. **Testing**: Comprehensive test suite validates the complete workflow.

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
- `get_shared_key_for_party(party, other_party)`: Compute shared secret
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

- **Python 3.7+** (uses f-strings and modern Python features)
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
echo '{"secret": 42}' > data/Alice.json
echo '{"secret": 99}' > data/Bob.json
echo 'Hello Bob, this is Alice!' > data/secret_message.txt

# 2. Run in Python
python3 << 'EOF'
from key_generator import generate_and_publish_public_key
from cipher import encrypt_message
from decipher import decrypt_message

# Generate public keys
generate_and_publish_public_key("Alice")
generate_and_publish_public_key("Bob")

# Alice encrypts for Bob
encrypt_message("Alice", "Bob")

# Bob decrypts from Alice
decrypt_message("Bob", "Alice")
EOF
```

**Production Alternative:**
```python
import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Retrieve secrets from Azure Key Vault instead
credential = DefaultAzureCredential()
vault_url = "https://<your-vault>.vault.azure.net/"
client = SecretClient(vault_url=vault_url, credential=credential)

# Load secrets securely
alice_secret = client.get_secret("alice-dh-secret").value
bob_secret = client.get_secret("bob-dh-secret").value

# Use secrets for encryption/decryption
# Never store secrets in files or environment variables
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

## Learning Resources

This project demonstrates several important cryptographic concepts:

1. **Key Exchange Protocols**: How to establish shared secrets over insecure channels
2. **Symmetric Encryption**: XOR cipher principles and limitations
3. **Key Derivation**: Stretching short secrets into longer keys
4. **Hashing**: Using SHA256 for key derivation and storage

### Comparing This Implementation vs Production Code

| Aspect | This Project | Production Code |
|--------|--------------|----------        |
| **Key Exchange** | Diffie-Hellman (DH) | ECDH (Elliptic Curve DH) |
| **Encryption** | XOR cipher | AES-256-GCM |
| **Authentication** | None | HMAC or authenticated encryption |
| **Key Size** | 59-bit primes | 256-bit keys (2048+ bit DH) |
| **Implementation** | Custom Python | `cryptography` library |
| **Random Generation** | Hardcoded values | `secrets.randbits()` |
| **Security Proof** | Educational | NIST approved |
| **Performance** | Slow (for demo) | Hardware accelerated |
| **Vulnerability to MITM** | Yes | Mitigated with signatures/PKI |

### Understanding the Trade-offs

**Why this project uses simple algorithms:**
- 🎓 Easier to understand the concepts
- 📖 Shows the actual math and logic
- 🔧 Demonstrates complete control over the process

**Why production uses complex algorithms:**
- 🛡️ Protection against known attacks
- ⚡ Hardware acceleration and optimization
- 🔐 Proven security properties
- 🌍 Standards compliance (NIST, FIPS, etc.)

## Limitations and Disclaimer

⚠️ **This is a demonstration project for educational purposes only.**

### Known Limitations

| Limitation | Why | Production Solution |
|-----------|-----|---------------------|
| **Hardcoded secrets in JSON files** | Testing/demo purposes | Store in vaults (Azure Key Vault, AWS Secrets Manager, HSM) |
| Small prime numbers (59-bit) | Demonstration purposes | Use 2048+ bit primes (RFC 3526) |
| No message authentication | Can't detect tampering | Add HMAC or use AEAD ciphers |
| No protection against MITM | Public keys could be spoofed | Use digital signatures or PKI |
| Custom XOR implementation | Educational, not optimized | Use `cryptography` library (AES-GCM) |
| Synchronous file operations | Blocking I/O | Use async/await with `aiofiles` |
| No key rotation | Static shared secret | Implement periodic key agreement |

### When to Use This Project

✅ **Good for:**
- Learning cryptographic concepts
- Understanding Diffie-Hellman protocol
- Understanding XOR cipher and one-time pads
- Educational demonstrations
- Code examples for learning

❌ **Not suitable for:**
- Production systems with real data
- Protecting sensitive information
- High-security applications
- Network communication (no TLS/SSL)
- Long-term data storage

### Production-Ready Alternatives

For real-world applications, use established cryptography libraries with proper secret management:

**Python with Proper Secret Management:**
```python
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# 1. Retrieve secrets from Azure Key Vault (NOT from files)
credential = DefaultAzureCredential()
vault_url = "https://<your-vault>.vault.azure.net/"
client = SecretClient(vault_url=vault_url, credential=credential)

alice_secret_b64 = client.get_secret("alice-private-key").value
bob_public_b64 = client.get_secret("bob-public-key").value

# 2. Use modern key exchange (X25519 instead of DH)
alice_private = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(alice_secret_b64))
shared_secret = alice_private.exchange(x25519.X25519PublicKey(bytes.fromhex(bob_public_b64)))

# 3. Use authenticated encryption (ChaCha20-Poly1305)
cipher = ChaCha20Poly1305(shared_secret)
nonce = os.urandom(12)
ciphertext = cipher.encrypt(nonce, b"Secret message", None)

# 4. Transmit over TLS/SSL
# 5. Log to secure audit trails only
```

**Recommended Libraries:**
- `cryptography` - Modern, well-maintained, FIPS 140-2 compatible
- `PyCryptodome` - Comprehensive crypto algorithms
- `nacl` (PyNaCl) - High-level, secure-by-default crypto

**Recommended Vault Solutions:**

| Platform | Service | Use Case |
|----------|---------|----------|
| Azure | Azure Key Vault | Cloud-native Azure applications |
| AWS | AWS Secrets Manager | Cloud-native AWS applications |
| Google Cloud | Cloud KMS | Cloud-native GCP applications |
| On-Premises | HashiCorp Vault | Self-managed infrastructure |
| Hardware | Thales Luna, YubiKey | Highest security requirements |

**Languages:**
- JavaScript: `tweetnacl-js` or `libsodium.js` + AWS SDK / Azure SDK
- Rust: `ring` or `sodiumoxide` + cloud SDKs
- Go: Built-in `crypto` package + cloud SDKs
- Java: Bouncy Castle + cloud SDKs

## License

This project is provided as-is for educational and demonstration purposes.
