'''
Try using the Elgammal, Schnor asymmetric encryption standard and verify the above
steps. 
'''
import random

# Extended Euclidean Algorithm for finding modular inverse
def mod_inverse(a, m):
    # m is the modulus
    t, new_t = 0, 1
    r, new_r = m, a
    
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    
    if r > 1:
        raise ValueError(f"{a} has no inverse modulo {m}")
    
    if t < 0:
        t = t + m
    
    return t

# ElGamal Key Generation
def generate_keys(p, g):
    private_key = random.randint(1, p - 2)  # Private key is between 1 and p-2
    public_key = pow(g, private_key, p)  # Public key is g^private_key mod p
    return private_key, public_key

# ElGamal Encryption (using public key)
def encrypt(public_key, p, g, message):
    k = random.randint(1, p - 2)  # Random integer k
    c1 = pow(g, k, p)  # g^k mod p
    c2 = (message * pow(public_key, k, p)) % p  # m * public_key^k mod p
    return c1, c2

# ElGamal Decryption (using private key)
def decrypt(private_key, p, c1, c2):
    s = pow(c1, private_key, p)  # c1^private_key mod p
    s_inv = mod_inverse(s, p)  # Inverse of s mod p
    message = (c2 * s_inv) % p  # (c2 * s_inv) mod p
    return message

# Digital Signature Generation (using private key)
def sign(private_key, p, g, message):
    k = random.randint(1, p - 2)  # Random integer k
    r = pow(g, k, p)  # r = g^k mod p
    s = (mod_inverse(k, p - 1) * (message - private_key * r)) % (p - 1)  # s = (k^-1 * (message - private_key * r)) mod (p-1)
    return r, s

# Digital Signature Verification (using public key)
def verify(public_key, p, g, message, r, s):
    if not (0 < r < p and 0 < s < p - 1):
        return False
    
    left = (pow(g, message, p) * pow(r, s, p)) % p  # g^message * r^s mod p
    right = pow(public_key, r, p)  # public_key^r mod p
    
    return left == right  # If they are equal, the signature is valid

# Example Usage
p = 7919  # A prime number (for simplicity, this can be much larger in practice)
g = 2     # A primitive root modulo p

# Generate public and private keys
private_key, public_key = generate_keys(p, g)
print(f"Private Key: {private_key}")
print(f"Public Key: {public_key}")

# Sign a message (message should be an integer)
message = 1234  # This is the message we want to sign
r, s = sign(private_key, p, g, message)
print(f"Signature (r, s): ({r}, {s})")

# Verify the signature
is_valid = verify(public_key, p, g, message, r, s)
print(f"Signature valid: {is_valid}")

# Encrypt a message
c1, c2 = encrypt(public_key, p, g, message)
print(f"Encrypted Message: c1 = {c1}, c2 = {c2}")

# Decrypt the message
decrypted_message = decrypt(private_key, p, c1, c2)
print(f"Decrypted Message: {decrypted_message}")

