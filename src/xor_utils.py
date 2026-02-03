"""XOR cipher utility functions.

Provides optimized XOR cipher implementation for encryption and decryption.
The XOR operation is symmetric, so the same function can be used for both.
"""

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
    """
    key_length = len(key)
    key_int = [ord(k) for k in key]  # Convert key to integers once
    text_int = bytearray(text, 'utf-8')  # Convert text to bytearray for mutability

    # Perform XOR operation
    for i in range(len(text_int)):
        text_int[i] ^= key_int[i % key_length]  # XOR with the key

    return text_int.decode('utf-8')  # Convert back to string
