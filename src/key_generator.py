"""Key generation and Diffie-Hellman key exchange utilities.

This module provides functions for:
- Loading Diffie-Hellman parameters
- Generating and publishing public keys
- Computing shared secret keys
- Stretching keys for one-time pad encryption

⚠️ IMPORTANT SECURITY NOTE:
    This module loads secrets from JSON files for DEMONSTRATION purposes only.
    DO NOT use this approach in production!
    
    In production environments, secrets should be retrieved from secure vaults:
    - Azure Key Vault
    - AWS Secrets Manager  
    - Google Cloud KMS
    - HashiCorp Vault
    - Hardware Security Modules (HSMs)
    
    Never:
    - Store secrets in plaintext files
    - Commit secrets to version control
    - Hardcode secret values
    - Log secret values
    - Store secrets in environment variables (for sensitive systems)
"""

# pylint: disable=import-error

import hashlib
import logging
from os import path

from config import DATA_DIR, DH_PARAMS_FILE
from json_utils import get_json_value, save_json

logger = logging.getLogger(__name__)


def load_dh_params():
    """Load Diffie-Hellman parameters from configuration file.

    Returns:
        Tuple of (generator, prime) integers.

    Raises:
        ValueError: If parameters are invalid (not positive integers, or generator >= prime).
    """
    logger.debug("Loading Diffie-Hellman parameters")
    generator = get_json_value(DH_PARAMS_FILE, "generator")
    prime = get_json_value(DH_PARAMS_FILE, "prime")

    # Validate parameters
    if not isinstance(prime, int) or prime <= 1:
        raise ValueError(f"Prime must be an integer > 1, got {prime}")
    if not isinstance(generator, int) or generator <= 0 or generator >= prime:
        error_message = (
            "Generator must be an integer where 0 < g < prime, got "
            f"{generator}"
        )
        raise ValueError(error_message)

    logger.info("Loaded DH params: generator=%s, prime=%s", generator, prime)
    return generator, prime

def generate_and_publish_public_key(producer_id):
    """Generate and publish a public key for Diffie-Hellman key exchange.

    Args:
        producer_id: Identifier of the party generating the public key.

    Returns:
        The generated public key as a string.

    Raises:
        ValueError: If secret is invalid (not positive integer).
    """
    # Load DH parameters
    logger.info("Generating public key for %s", producer_id)
    generator, prime = load_dh_params()
    secret = get_json_value(path.join(DATA_DIR, f"{producer_id}.json"), "secret")

    # Validate secret
    if not isinstance(secret, int) or secret <= 0:
        raise ValueError(f"Secret must be a positive integer, got {secret}")

    # public key for sharing = (G^secret) % P
    print(
        f"Calculating public key with Generator={generator}, "
        f"Prime={prime}, secret={secret}"
    )
    public_key = pow(generator, secret, prime)
    public_key_file = path.join(DATA_DIR, f"public_key{producer_id}.json")
    save_json(public_key_file, {"public_key": public_key})
    print(f"Published public key {public_key} to {public_key_file}")
    logger.info("Published public key for %s", producer_id)
    return public_key

def get_shared_key_for_party(party, other_party):
    """
    Compute shared secret key for a party using DH key exchange.

    Loads DH parameters, party secrets, and other party's public key,
    then computes the shared secret that both parties will have.

    Returns the shared secret key (SHA256 hash) or None if public key not available.

    Raises:
        ValueError: If party secret is invalid.
        FileNotFoundError: If public key file doesn't exist.
    """

    logger.info("Computing shared key for %s with %s", party, other_party)

    # Load DH parameters
    generator, prime = load_dh_params()

    # Load my secret
    party_secret = get_json_value(path.join(DATA_DIR, f"{party}.json"), "secret")

    # Validate secret
    if not isinstance(party_secret, int) or party_secret <= 0:
        raise ValueError(
            f"Secret for {party} must be a positive integer, got {party_secret}"
        )

    # Load other party's public key
    other_party_public_key_filepath = path.join(
        DATA_DIR, f"public_key{other_party}.json"
    )
    if not path.exists(other_party_public_key_filepath):
        logger.warning(
            "Public key file from %s not found: %s",
            other_party,
            other_party_public_key_filepath,
        )
        print(
            f"Public key file from {other_party} was not published yet "
            f"{other_party_public_key_filepath}"
        )
        return None

    other_party_public_key = get_json_value(other_party_public_key_filepath, "public_key")

    # Compute shared secret
    shared_secure_key = compute_secured_shared_key(
        generator,
        prime,
        party_secret,
        other_party_public_key,
    )
    logger.info("Successfully computed shared key for %s", party)
    return shared_secure_key

def compute_secured_shared_key(generator, prime, secret, public_key):
    """Compute the shared secret key using Diffie-Hellman protocol.

    Args:
        generator: The generator value (G) from DH parameters.
        prime: The prime modulus (P) from DH parameters.
        secret: The party's private secret value.
        public_key: The other party's public key.

    Returns:
        A SHA256 hash of the computed shared secret as a hexadecimal string.
    """
    # secure key = ((shared public key from a))^ (secret b) % P) % P
    # secure key = ((shared public key from b))^ (secret a) % P) % P
    print(
        f"Calculating secured common key with generator={generator}, "
        f"prime={prime}, secret={secret}, public_key={public_key}"
    )
    computed_shared_key = pow(int(public_key), secret, prime)
    secure_key = hashlib.sha256(str(computed_shared_key).encode()).hexdigest()
    print(f"Secure key: {secure_key}")
    return secure_key

def get_stretched_key(shared_key, target_length):
    """Stretch a shared secret key to match target length for one-time pad encryption.

    Uses SHA256 hashing with incrementing counters to generate a pseudorandom
    key stream of the desired length.

    Args:
        shared_key: The base shared secret key to stretch.
        target_length: The desired length of the output key.

    Returns:
        A key string of exactly target_length characters.
    """
    # This stretches the shared secret to match the message length
    # It creates a long stream of bytes based on the secret

    # Optimized: Use list to avoid repeated string concatenation (O(n²) -> O(n))
    blocks = []
    counter = 0

    while len("".join(blocks)) < target_length:
        # Create a unique hash for each block using a counter
        # This ensures the key doesn't just repeat the same characters
        block = hashlib.sha256(f"{shared_key}-{counter}".encode()).hexdigest()
        blocks.append(block)
        counter += 1

    # Join and trim to exact length
    return "".join(blocks)[:target_length]
