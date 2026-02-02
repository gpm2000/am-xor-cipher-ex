from secured_key import get_secured_diffie_hellman_key

def xor_cipher(text, key):
    return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))


message = "Top Secret Information"
secure_key = get_secured_diffie_hellman_key()


encrypted = xor_cipher(message, secure_key)
print(f"Encrypted message: {encrypted.encode('unicode_escape')}") # Encoding for display

# Test it decipher back
decrypted_correct = xor_cipher(encrypted, secure_key)
print(f"Decryption with correct key: {decrypted_correct}")

"""
def xor_cipher_split(text, key_input):
    # Ensure the key is treated as a string to allow indexing
    key_string = str(key_input)
    key_length = len(key_string)

    # Check for empty key to prevent ZeroDivisionError in modulo logic
    if key_length == 0:
        raise ValueError("Key cannot be empty")

    result_list = []

    # Iterate through the text, getting the index (i) and character (c)
    for i, c in enumerate(text):
        # 1. Convert message character to its ASCII integer value
        char_val = ord(c)

        # 2. Find the corresponding character in the key using wrap-around logic
        # This handles keys shorter than the message
        key_index = i % key_length
        key_char = key_string[key_index]

        # 3. Convert key character to its ASCII integer value
        key_val = ord(key_char)

        # 4. Perform the Bitwise XOR operation
        xor_val = char_val ^ key_val

        # 5. Convert the resulting integer back into a character
        new_char = chr(xor_val)

        # Add the character to our list
        result_list.append(new_char)

        # Optional: Print debug info for each step
        # print(f"Index {i}: '{c}'({char_val}) XOR '{key_char}'({key_val}) = {xor_val} -> '{new_char}'")

    # 6. Join the list of characters back into a single string
    final_string = "".join(result_list)
    return final_string
"""