"""Test suite for XOR cipher Diffie-Hellman key exchange demonstration.

Runs a complete test of the key exchange protocol including:
1. Public key generation for both parties
2. Message encryption by one party
3. Message decryption by the other party
"""

import sys
import os
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Configure logging
logging.basicConfig(
	level=logging.INFO,
	format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

from cipher import encrypt_message
from decipher import decrypt_message
from key_generator import generate_and_publish_public_key

def main() -> None:
	"""Run the complete Diffie-Hellman key exchange and encryption test.
	
	Generates public keys for both parties (Whitfield and Martin),
	encrypts a message from Martin to Whitfield, and decrypts it
	as Whitfield using the shared secret.
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
		
	except FileNotFoundError as e:
		logger.error(f"❌ File not found: {e}")
		print(f"\n❌ Test failed: {e}")
		return 1
		
	except ValueError as e:
		logger.error(f"❌ Invalid value: {e}")
		print(f"\n❌ Test failed: {e}")
		return 1
		
	except RuntimeError as e:
		logger.error(f"❌ Runtime error: {e}")
		print(f"\n❌ Test failed: {e}")
		return 1
		
	except Exception as e:
		logger.error(f"❌ Unexpected error: {type(e).__name__}: {e}", exc_info=True)
		print(f"\n❌ Test failed with unexpected error: {type(e).__name__}: {e}")
		return 1

if __name__ == "__main__":
	exit_code = main()
	sys.exit(exit_code)
