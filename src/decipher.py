"""Message decryption module using Diffie-Hellman key exchange and XOR cipher.

This module provides functionality to decrypt messages using a shared secret
derived from Diffie-Hellman key exchange combined with XOR cipher decryption.

⚠️ SECURITY WARNING:
    This module demonstrates decryption but handles secrets insecurely for
    demonstration purposes. In production:
    
    - Load secrets from secure vaults (Key Vault, Secrets Manager, HSM)
    - Verify message authentication (HMAC, digital signatures)
    - Never log, display, or print decrypted content to insecure logs
    - Implement strict access controls on decryption operations
    - Use TLS/SSL for network transmission
    - Implement rate limiting to prevent brute force attacks
"""

from key_generator import get_shared_key_for_party, get_stretched_key
from xor_utils import xor_cipher
from config import ENCRYPTED_MESSAGE_FILE
from os import path

def decrypt_message(party, other_party) -> None:
    """Decrypt message using Diffie-Hellman shared secret.
    
    Reads an encrypted message from file, derives the same shared key using
    DH key exchange, stretches the key to match message length, and decrypts
    using XOR cipher (XOR is its own inverse).
    
    Args:
        party: Identifier of the decrypting party.
        other_party: Identifier of the sender party.
        
    Returns:
        None. Prints the decrypted message.
    """
    # Compute shared secret key
    secure_key = get_shared_key_for_party(party, other_party)
    if secure_key is None:
        return
    
    # Read encrypted message from file
    if not path.exists(ENCRYPTED_MESSAGE_FILE):
        print(f"Encrypted message file not found: {ENCRYPTED_MESSAGE_FILE}")
        return
    
    with open(ENCRYPTED_MESSAGE_FILE, "r") as file:
        encrypted_message = file.read()
    
    # Decrypt message using XOR cipher with stretched key
    otp_key = get_stretched_key(secure_key, len(encrypted_message))
    decrypted_message = xor_cipher(encrypted_message, otp_key)
    print(f"Decrypted message: {decrypted_message}")
