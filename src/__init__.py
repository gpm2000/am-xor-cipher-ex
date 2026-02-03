"""
XOR Cipher Example - Educational Diffie-Hellman Key Exchange Implementation.

This package demonstrates the Diffie-Hellman key exchange protocol and 
XOR-based encryption/decryption for educational purposes.

Note: In production, cryptographic keys and secrets should be stored in 
a secure key vault. This implementation is for demonstration only.

Modules:
    config: Centralized configuration (party names, file paths)
    json_utils: JSON file I/O utilities
    key_generator: Diffie-Hellman key exchange functions
    xor_utils: XOR cipher implementation
    cipher: Encryption module (Phase 2 for Whitfield)
    decipher: Decryption module (Phase 2 for Martin)
    generate_key_martin: Phase 1 key generation for Martin
    generate_key_whitfield: Phase 1 key generation for Whitfield
"""

__version__ = "1.0.0"
__author__ = "Education"
__all__ = [
    "config",
    "json_utils",
    "key_generator",
    "xor_utils",
    "cipher",
    "decipher",
]
