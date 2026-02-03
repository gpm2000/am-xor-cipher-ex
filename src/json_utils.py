"""JSON file utility functions.

Provides convenience functions for reading and writing JSON files,
used for storing DH parameters, secrets, and public keys.
"""

import json

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
    """
    with open(filepath, 'r') as f:
        value = json.load(f)
        return value[param]

def save_json(filepath, data):
    """Save data to a JSON file with pretty formatting.
    
    Args:
        filepath: Path where the JSON file should be saved.
        data: Dictionary or JSON-serializable object to save.
        
    Returns:
        None. Writes the data to the specified file.
    """
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
