"""Test suite for XOR cipher Diffie-Hellman key exchange demonstration.

Runs a complete test of the key exchange protocol including:
1. Public key generation for both parties
2. Message encryption by one party
3. Message decryption by the other party
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from cipher import encrypt_message
from decipher import decrypt_message
from key_generator import generate_and_publish_public_key

def main() -> None:
	"""Run the complete Diffie-Hellman key exchange and encryption test.
	
	Generates public keys for both parties (Whitfield and Martin),
	encrypts a message from Martin to Whitfield, and decrypts it
	as Whitfield using the shared secret.
	"""

	generate_and_publish_public_key("Whitfield")
	generate_and_publish_public_key("Martin")
	encrypt_message("Martin", "Whitfield")
	decrypt_message("Whitfield", "Martin")

if __name__ == "__main__":
	main()
