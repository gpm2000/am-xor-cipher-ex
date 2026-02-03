"""JSON file utility functions.

Provides convenience functions for reading and writing JSON files,
used for storing DH parameters, secrets, and public keys.
"""

import json
import logging

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
