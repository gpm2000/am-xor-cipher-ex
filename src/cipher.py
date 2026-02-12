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

# pylint: disable=duplicate-code

import logging

from src.config import ENCRYPTED_MESSAGE_FILE, SECRET_MESSAGE_FILE
from src.io_utils import read_text_file_utf8_bytes, write_base64_file
from src.key_generator import get_shared_key_for_party, get_stretched_key
from src.xor_utils import xor_cipher_bytes

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
    logger.info("Encrypting message from %s to %s", party, other_party)

    # Compute shared secret key
    secure_key = get_shared_key_for_party(party, other_party)
    if secure_key is None:
        logger.error(
            "Failed to compute shared key - check that %s's public key exists",
            other_party,
        )
        error_message = (
            f"Cannot encrypt: {other_party}'s public key not available"
        )
        raise RuntimeError(error_message)

    # Read secret message from file
    secret_message_bytes = read_text_file_utf8_bytes(SECRET_MESSAGE_FILE)
    if not secret_message_bytes:
        logger.warning("Secret message file is empty")
    otp_key = get_stretched_key(secure_key, len(secret_message_bytes))
    encrypted_bytes = xor_cipher_bytes(secret_message_bytes, otp_key)
    print(f"Encrypted message: {encrypted_bytes[:50]}...")  # Show first 50 bytes

    # Save encrypted message to file as Base64 (binary-safe encoding)
    logger.debug("Writing encrypted message to %s", ENCRYPTED_MESSAGE_FILE)
    write_base64_file(ENCRYPTED_MESSAGE_FILE, encrypted_bytes)
    logger.info("Encryption completed successfully")
