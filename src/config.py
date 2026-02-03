"""
Configuration for XOR Cipher Diffie-Hellman key exchange demonstration.

This module centralizes all configuration constants including party names,
file paths, and parameter locations for the DH key exchange protocol.

Note: For demonstration purposes only. In production, use environment 
variables or a secure configuration system for sensitive data.
"""

import os

# Party configuration - centralized to avoid magic strings
PARTIES = {
    "MARTIN": "Martin",
    "WHITFIELD": "Whitfield"
}

# File paths for Diffie-Hellman parameters (cross-platform)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
DH_PARAMS_FILE = os.path.join(DATA_DIR, "dh_params.json")

# Message files (for demonstration)
ENCRYPTED_MESSAGE_FILE = os.path.join(PROJECT_ROOT, "encrypted_message.txt")
SECRET_MESSAGE_FILE = os.path.join(DATA_DIR, "secret_message.txt")
