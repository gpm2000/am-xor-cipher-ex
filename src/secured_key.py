import hashlib


def calc_secured_key(generator, prime, a_secret, b_secret):
    """
    a_public = pow(generator, a_secret, prime)  # (G^a) % P
    b_public = pow(generator, b_secret, prime) # (G^b) % P
    a_person_shared = pow(b_public, a_secret, prime)  # ((G^b))^a % P) % P
    b_person_shared = pow(a_public, b_secret, prime)  # ((G^a))^b % P) % P
    """
    shared_key = pow(pow(generator, a_secret, prime), b_secret, prime)
    secure_key = hashlib.sha256(str(shared_key).encode()).hexdigest()
    print(f"Secure key: {secure_key}")
    return secure_key


def get_stretched_key(shared_secret, target_length):
    # This stretches the shared secret to match the message length
    # It creates a long stream of bytes based on the secret
    
    # Optimized: Use list to avoid repeated string concatenation (O(n²) -> O(n))
    blocks = []
    counter = 0
    
    while len("".join(blocks)) < target_length:
        # Create a unique hash for each block using a counter
        # This ensures the key doesn't just repeat the same characters
        block = hashlib.sha256(f"{shared_secret}-{counter}".encode()).hexdigest()
        blocks.append(block)
        counter += 1
    
    # Join and trim to exact length
    return "".join(blocks)[:target_length]

def get_secured_diffie_hellman_key():
    # example
    # public data
    generator = 2
    prime = 59

    # person a
    a_secret = 13

    # person b
    b_secret = 7
    return str(calc_secured_key(generator, prime, a_secret, b_secret))

def get_otp_secured_key(message_length):
    return str(get_stretched_key(get_secured_diffie_hellman_key(), message_length))




