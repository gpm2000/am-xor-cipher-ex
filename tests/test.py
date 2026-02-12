"""Test suite for XOR cipher Diffie-Hellman key exchange demonstration.

Runs a complete test of the key exchange protocol including:
1. Public key generation for both parties
2. Message encryption by one party
3. Message decryption by the other party
"""

import sys
import os
import logging

# pylint: disable=wrong-import-position
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.cipher import encrypt_message
from src.decipher import decrypt_message
from src.io_utils import cleanup_runtime_files
from src.key_generator import generate_and_publish_public_key
# pylint: enable=wrong-import-position

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main() -> int:
    """Run the complete Diffie-Hellman key exchange and encryption test.

    Generates public keys for both parties (Whitfield and Martin),
    encrypts a message from Martin to Whitfield, and decrypts it
    as Whitfield using the shared secret.

    Returns:
        int: Exit code (0 for success, 1 for failure)
    """
    try:
        logger.info("Starting XOR cipher test suite")

        logger.info("Step 1: Generating public keys")
        generate_and_publish_public_key("Whitfield")
        generate_and_publish_public_key("Martin")

        logger.info("Step 2: Encrypting message")
        encrypt_message("Martin", "Whitfield")

        logger.info("Step 3: Decrypting message")
        decrypt_message("Whitfield", "Martin")

        logger.info("✅ All tests completed successfully!")
        print("\n✅ All tests passed!")
        return 0

    except FileNotFoundError as exc:
        logger.error("❌ File not found: %s", exc)
        print(f"\n❌ Test failed: {exc}")
        return 1

    except ValueError as exc:
        logger.error("❌ Invalid value: %s", exc)
        print(f"\n❌ Test failed: {exc}")
        return 1

    except RuntimeError as exc:
        logger.error("❌ Runtime error: %s", exc)
        print(f"\n❌ Test failed: {exc}")
        return 1

    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("❌ Unexpected error: %s: %s",
                     type(exc).__name__, exc, exc_info=True)
        print(f"\n❌ Test failed with unexpected error: {type(exc).__name__}: {exc}")
        return 1
    finally:
        try:
            cleanup_runtime_files()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error("Cleanup failed: %s", exc)

if __name__ == "__main__":
    EXIT_CODE = main()
    sys.exit(EXIT_CODE)
