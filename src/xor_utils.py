"""XOR cipher utility functions.

Provides optimized XOR cipher implementation for encryption and decryption.
The XOR operation is symmetric, so the same function can be used for both.
"""

import logging

logger = logging.getLogger(__name__)

def xor_cipher(text, key):
    """
    XOR cipher implementation.

    Encrypts or decrypts text using XOR operation with a given key.
    Works with UTF-8 encoded text. For encryption, encodes text as UTF-8 bytes,
    XORs with key, and returns binary result. For decryption, assumes binary
    input (as string with latin-1 encoding), XORs with key, and returns binary.
    
    Args:
        text: The plaintext string to encrypt or ciphertext string (latin-1 encoded binary).
        key: The encryption/decryption key string.
        
    Returns:
        Bytes object containing XORed binary data.
        
    Raises:
        ValueError: If key is empty or inputs are not strings.
    """
    # Validate inputs
    if not isinstance(text, str):
        raise ValueError(f"Text must be a string, got {type(text).__name__}")
    if not isinstance(key, str):
        raise ValueError(f"Key must be a string, got {type(key).__name__}")
    if not key:
        raise ValueError("Encryption key cannot be empty")
    if not text:
        logger.warning("Empty text provided to xor_cipher")
        return b""

    key_length = len(key)
    key_bytes = [ord(k) for k in key]  # Convert key to byte values

    # Always use latin-1 for encoding/decoding to preserve all byte values (0-255)
    # This is necessary because after XOR, we may have arbitrary byte values
    try:
        text_bytes = bytearray(text.encode('latin-1'))
    except UnicodeEncodeError as exc:
        logger.error("Failed to encode text as latin-1: %s", exc)
        raise ValueError(f"Text contains characters outside latin-1 range: {exc}") from exc

    # Perform XOR operation
    for index, _ in enumerate(text_bytes):
        text_bytes[index] ^= key_bytes[index % key_length]  # XOR with the key

    return bytes(text_bytes)  # Return as bytes
