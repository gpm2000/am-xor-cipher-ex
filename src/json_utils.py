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
        logger.debug(f"Reading '{param}' from {filepath}")
        with open(filepath, 'r') as f:
            value = json.load(f)
            if param not in value:
                raise KeyError(f"Missing key '{param}' in {filepath}")
            return value[param]
    except FileNotFoundError:
        logger.error(f"File not found: {filepath}")
        raise FileNotFoundError(f"Configuration file not found: {filepath}")
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {filepath}: {e}")
        raise ValueError(f"Invalid JSON format in {filepath}: {e}")
    except PermissionError:
        logger.error(f"Permission denied: {filepath}")
        raise PermissionError(f"Cannot read file (permission denied): {filepath}")

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
        logger.debug(f"Saving data to {filepath}")
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
    except TypeError as e:
        logger.error(f"Data not JSON-serializable: {e}")
        raise TypeError(f"Cannot serialize data to JSON: {e}")
    except PermissionError:
        logger.error(f"Permission denied writing to: {filepath}")
        raise PermissionError(f"Cannot write file (permission denied): {filepath}")
    except OSError as e:
        logger.error(f"OS error writing to {filepath}: {e}")
        raise OSError(f"Failed to write file {filepath}: {e}")
