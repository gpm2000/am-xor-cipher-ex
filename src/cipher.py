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

# pylint: disable=import-error,duplicate-code

import base64
import logging

from config import ENCRYPTED_MESSAGE_FILE, SECRET_MESSAGE_FILE
from key_generator import get_shared_key_for_party, get_stretched_key
from xor_utils import xor_cipher

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
    try:
        logger.debug("Reading secret message from %s", SECRET_MESSAGE_FILE)
        with open(SECRET_MESSAGE_FILE, "r", encoding="utf-8") as file:
            secret_message = file.read()

        if not secret_message:
            logger.warning("Secret message file is empty")
    except FileNotFoundError as exc:
        logger.error("Secret message file not found: %s", SECRET_MESSAGE_FILE)
        error_message = (
            f"Secret message file not found: {SECRET_MESSAGE_FILE}"
        )
        raise FileNotFoundError(error_message) from exc
    except PermissionError as exc:
        logger.error("Permission denied reading: %s", SECRET_MESSAGE_FILE)
        error_message = (
            f"Cannot read secret message file: {SECRET_MESSAGE_FILE}"
        )
        raise PermissionError(error_message) from exc

    otp_key = get_stretched_key(secure_key, len(secret_message.encode('utf-8')))
    # Convert UTF-8 bytes to latin-1 string for XOR processing
    secret_message_latin1 = secret_message.encode('utf-8').decode('latin-1')
    encrypted_bytes = xor_cipher(secret_message_latin1, otp_key)
    print(f"Encrypted message: {encrypted_bytes[:50]}...")  # Show first 50 bytes

    # Save encrypted message to file as Base64 (binary-safe encoding)
    try:
        logger.debug("Writing encrypted message to %s", ENCRYPTED_MESSAGE_FILE)
        # Encode encrypted bytes as Base64 for safe text file storage
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode('ascii')
        with open(ENCRYPTED_MESSAGE_FILE, "w", encoding="utf-8") as file:
            file.write(encrypted_b64)
        logger.info("Encryption completed successfully")
    except PermissionError as exc:
        logger.error("Permission denied writing to: %s", ENCRYPTED_MESSAGE_FILE)
        error_message = (
            f"Cannot write encrypted message file: {ENCRYPTED_MESSAGE_FILE}"
        )
        raise PermissionError(error_message) from exc
    except OSError as exc:
        logger.error("OS error writing encrypted message: %s", exc)
        raise OSError(f"Failed to write encrypted message: {exc}") from exc
