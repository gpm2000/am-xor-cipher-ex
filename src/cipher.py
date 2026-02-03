"""Message encryption module using Diffie-Hellman key exchange and XOR cipher.

This module provides functionality to encrypt messages using a shared secret
derived from Diffie-Hellman key exchange combined with XOR cipher encryption.

⚠️ SECURITY WARNING:
    This module demonstrates encryption but handles secrets insecurely for
    demonstration purposes. In production:
    
    - Load secrets from secure vaults (Key Vault, Secrets Manager, HSM)
    - Never log, display, or print secret values
    - Use authenticated encryption (HMAC-SHA256, AES-GCM)
    - Implement key rotation policies
    - Use TLS/SSL for network transmission
    - Validate message integrity and authenticity
"""

import logging
from key_generator import get_shared_key_for_party, get_stretched_key
from xor_utils import xor_cipher
from config import ENCRYPTED_MESSAGE_FILE, SECRET_MESSAGE_FILE, DATA_DIR
from os import path

logger = logging.getLogger(__name__)

def encrypt_message(party, other_party) -> None:
    """Encrypt message using Diffie-Hellman shared secret.
    
    Reads a secret message from file, derives a shared key using DH key exchange,
    stretches the key to match message length, and encrypts using XOR cipher.
    The encrypted message is saved to a file.
    
    Args:
        party: Identifier of the encrypting party.
        other_party: Identifier of the recipient party.
        
    Returns:
        None. Prints encryption status and writes encrypted message to file.
        
    Raises:
        RuntimeError: If shared key computation fails.
        FileNotFoundError: If secret message file doesn't exist.
        PermissionError: If cannot read/write files.
    """
    logger.info(f"Encrypting message from {party} to {other_party}")
    
    # Compute shared secret key
    secure_key = get_shared_key_for_party(party, other_party)
    if secure_key is None:
        logger.error(f"Failed to compute shared key - check that {other_party}'s public key exists")
        raise RuntimeError(f"Cannot encrypt: {other_party}'s public key not available")
    
    # Read secret message from file
    try:
        logger.debug(f"Reading secret message from {SECRET_MESSAGE_FILE}")
        with open(SECRET_MESSAGE_FILE, "r") as file:
            secret_message = file.read()
        
        if not secret_message:
            logger.warning("Secret message file is empty")
    except FileNotFoundError:
        logger.error(f"Secret message file not found: {SECRET_MESSAGE_FILE}")
        raise FileNotFoundError(f"Secret message file not found: {SECRET_MESSAGE_FILE}")
    except PermissionError:
        logger.error(f"Permission denied reading: {SECRET_MESSAGE_FILE}")
        raise PermissionError(f"Cannot read secret message file: {SECRET_MESSAGE_FILE}")

    
    otp_key = get_stretched_key(secure_key, len(secret_message))
    encrypted_message = xor_cipher(secret_message, otp_key)
    print(f"Encrypted message: {encrypted_message.encode('unicode_escape')}")
    
    # Save encrypted message to file
    try:
        logger.debug(f"Writing encrypted message to {ENCRYPTED_MESSAGE_FILE}")
        with open(ENCRYPTED_MESSAGE_FILE, "w") as file:
            file.write(encrypted_message)
        logger.info("Encryption completed successfully")
    except PermissionError:
        logger.error(f"Permission denied writing to: {ENCRYPTED_MESSAGE_FILE}")
        raise PermissionError(f"Cannot write encrypted message file: {ENCRYPTED_MESSAGE_FILE}")
    except OSError as e:
        logger.error(f"OS error writing encrypted message: {e}")
        raise OSError(f"Failed to write encrypted message: {e}")
