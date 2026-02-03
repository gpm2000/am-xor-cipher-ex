"""
Configuration for XOR Cipher Diffie-Hellman key exchange demonstration.

This module centralizes all configuration constants including party names,
file paths, and parameter locations for the DH key exchange protocol.

Note: For demonstration purposes only. In production, use environment 
variables or a secure configuration system for sensitive data.
"""

# Party configuration - centralized to avoid magic strings
PARTIES = {
    "MARTIN": "Martin",
    "WHITFIELD": "Whitfield"
}

# File paths for Diffie-Hellman parameters (relative to project root)
DH_PARAMS_FILE = r".\data\dh_params.json"
DATA_DIR = r".\data"

# Message to encrypt (for demonstration)
ENCRYPTED_MESSAGE_FILE = "encrypted_message.txt"
SECRET_MESSAGE_FILE = r".\data\secret_message.txt"