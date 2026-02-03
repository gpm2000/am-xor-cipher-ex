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
    The key is repeated cyclically to match the text length. Since XOR
    is its own inverse, the same function works for both encryption and decryption.
    
    Args:
        text: The plaintext string to encrypt or ciphertext to decrypt.
        key: The encryption/decryption key string.
        
    Returns:
        The encrypted or decrypted string.
        
    Raises:
        ValueError: If key is empty or inputs are not strings.
        UnicodeDecodeError: If XOR result cannot be decoded as UTF-8.
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
        return text
    
    key_length = len(key)
    key_int = [ord(k) for k in key]  # Convert key to integers once
    
    try:
        text_int = bytearray(text, 'utf-8')  # Convert text to bytearray for mutability
    except UnicodeEncodeError as e:
        logger.error(f"Failed to encode text as UTF-8: {e}")
        raise ValueError(f"Text contains invalid characters: {e}")

    # Perform XOR operation
    for i in range(len(text_int)):
        text_int[i] ^= key_int[i % key_length]  # XOR with the key

    try:
        return text_int.decode('utf-8')  # Convert back to string
    except UnicodeDecodeError as e:
        logger.error(f"XOR result is not valid UTF-8: {e}")
        raise UnicodeDecodeError(
            'utf-8', text_int, 0, len(text_int),
            f"XOR cipher produced invalid UTF-8 bytes. This may indicate key mismatch or corrupted data: {e}"
        )
