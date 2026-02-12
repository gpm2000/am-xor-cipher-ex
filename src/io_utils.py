"""I/O utility functions.

Provides JSON helpers and Base64 file helpers used by the cipher workflow.
"""

import base64
import binascii
import json
import logging
import os

from src.config import DATA_DIR, ENCRYPTED_MESSAGE_FILE, PARTIES

logger = logging.getLogger(__name__)

def get_json_value(filepath, param):
    """Load a specific value from a JSON file.
    
    Args:
        filepath: Path to the JSON file to read.
        param: The key name of the value to retrieve.
        
    Returns:
        The value associated with the specified key.
        
    Raises:
        FileNotFoundError: If the specified file doesn't exist.
        KeyError: If the specified parameter doesn't exist in the JSON.
        ValueError: If JSON is malformed or cannot be parsed.
    """
    try:
        logger.debug("Reading '%s' from %s", param, filepath)
        with open(filepath, 'r', encoding='utf-8') as f:
            value = json.load(f)
            if param not in value:
                raise KeyError(f"Missing key '{param}' in {filepath}")
            return value[param]
    except FileNotFoundError as exc:
        logger.error("File not found: %s", filepath)
        raise FileNotFoundError(f"Configuration file not found: {filepath}") from exc
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in %s: %s", filepath, exc)
        raise ValueError(f"Invalid JSON format in {filepath}: {exc}") from exc
    except PermissionError as exc:
        logger.error("Permission denied: %s", filepath)
        raise PermissionError(f"Cannot read file (permission denied): {filepath}") from exc

def save_json(filepath, data):
    """Save data to a JSON file with pretty formatting.
    
    Args:
        filepath: Path where the JSON file should be saved.
        data: Dictionary or JSON-serializable object to save.
        
    Returns:
        None. Writes the data to the specified file.
        
    Raises:
        TypeError: If data is not JSON-serializable.
        PermissionError: If cannot write to the file.
    """
    try:
        logger.debug("Saving data to %s", filepath)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
    except TypeError as exc:
        logger.error("Data not JSON-serializable: %s", exc)
        raise TypeError(f"Cannot serialize data to JSON: {exc}") from exc
    except PermissionError as exc:
        logger.error("Permission denied writing to: %s", filepath)
        raise PermissionError(f"Cannot write file (permission denied): {filepath}") from exc
    except OSError as exc:
        logger.error("OS error writing to %s: %s", filepath, exc)
        raise OSError(f"Failed to write file {filepath}: {exc}") from exc

def read_base64_file(filepath):
    """Read a Base64-encoded text file and return decoded bytes."""
    try:
        logger.debug("Reading Base64 data from %s", filepath)
        with open(filepath, 'r', encoding='utf-8') as file:
            encoded_text = file.read()

        if not encoded_text:
            logger.warning("Base64 file is empty: %s", filepath)
            raise ValueError(f"Base64 file is empty: {filepath}")

        try:
            return base64.b64decode(encoded_text)
        except (ValueError, binascii.Error) as exc:
            logger.error("Invalid Base64 in %s: %s", filepath, exc)
            raise ValueError(f"Invalid Base64 format in {filepath}: {exc}") from exc

    except FileNotFoundError as exc:
        logger.error("File not found: %s", filepath)
        raise FileNotFoundError(f"File not found: {filepath}") from exc
    except PermissionError as exc:
        logger.error("Permission denied reading: %s", filepath)
        raise PermissionError(f"Cannot read file (permission denied): {filepath}") from exc

def read_text_file_utf8(filepath):
    """Read a UTF-8 text file and return its contents as a string."""
    try:
        logger.debug("Reading UTF-8 text from %s", filepath)
        with open(filepath, 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError as exc:
        logger.error("File not found: %s", filepath)
        raise FileNotFoundError(f"File not found: {filepath}") from exc
    except PermissionError as exc:
        logger.error("Permission denied reading: %s", filepath)
        raise PermissionError(f"Cannot read file (permission denied): {filepath}") from exc

def read_text_file_utf8_bytes(filepath):
    """Read a UTF-8 text file and return its contents as bytes."""
    text = read_text_file_utf8(filepath)
    return text.encode('utf-8')

def write_base64_file(filepath, data):
    """Write bytes to a text file as Base64."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Data must be bytes or bytearray, got {type(data).__name__}")

    try:
        logger.debug("Writing Base64 data to %s", filepath)
        encoded_text = base64.b64encode(bytes(data)).decode('ascii')
        with open(filepath, 'w', encoding='utf-8') as file:
            file.write(encoded_text)
    except PermissionError as exc:
        logger.error("Permission denied writing to: %s", filepath)
        raise PermissionError(f"Cannot write file (permission denied): {filepath}") from exc
    except OSError as exc:
        logger.error("OS error writing to %s: %s", filepath, exc)
        raise OSError(f"Failed to write file {filepath}: {exc}") from exc

def cleanup_runtime_files():
    """Remove generated runtime files to keep the workspace clean."""
    generated_files = [ENCRYPTED_MESSAGE_FILE]
    for party in PARTIES.values():
        generated_files.append(os.path.join(DATA_DIR, f"public_key{party}.json"))

    for filepath in generated_files:
        if not os.path.exists(filepath):
            continue
        try:
            logger.debug("Removing generated file: %s", filepath)
            os.remove(filepath)
        except PermissionError as exc:
            logger.error("Permission denied deleting: %s", filepath)
            raise PermissionError(
                f"Cannot delete file (permission denied): {filepath}"
            ) from exc
        except OSError as exc:
            logger.error("OS error deleting %s: %s", filepath, exc)
            raise OSError(f"Failed to delete file {filepath}: {exc}") from exc
