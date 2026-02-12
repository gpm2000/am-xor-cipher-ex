"""XOR cipher utility functions.

Provides optimized XOR cipher implementation for encryption and decryption.
The XOR operation is symmetric, so the same function can be used for both.
"""

import logging

logger = logging.getLogger(__name__)

def xor_cipher_bytes(data, key):
    """
    XOR cipher implementation for bytes.

    Encrypts or decrypts binary data using XOR operation with a given key.

    Args:
        data: Bytes or bytearray to encrypt or decrypt.
        key: The encryption/decryption key string.

    Returns:
        Bytes object containing XORed binary data.

    Raises:
        ValueError: If key is empty or inputs are not valid types.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError(f"Data must be bytes or bytearray, got {type(data).__name__}")
    if not isinstance(key, str):
        raise ValueError(f"Key must be a string, got {type(key).__name__}")
    if not key:
        raise ValueError("Encryption key cannot be empty")
    if not data:
        logger.warning("Empty data provided to xor_cipher_bytes")
        return b""

    key_length = len(key)
    key_bytes = [ord(k) for k in key]  # Convert key to byte values
    data_bytes = bytearray(data)

    for index, _ in enumerate(data_bytes):
        data_bytes[index] ^= key_bytes[index % key_length]

    return bytes(data_bytes)
