'''
Given an ElGamal encryption scheme with a public key (p, g, h) and a private key
x, encrypt the message "Confidential Data". Then decrypt the ciphertext to retrieve
the original message. 

    Parameters:
    - p (int): A prime number
    - alpha (int): A primitive root modulo p
    - r : private key
    - u (int): Public key (alpha^r mod p)
    - m (int): The message to be encrypted

    Returns:
    - (c1, c2): Tuple of cipher texts
'''
import random

from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime


def elgamal_encryption(p, alpha, u, m):
    x = random.randint(1, p - 2)
    c1 = pow(alpha, x, p)
    c2 = (m * pow(u, x, p)) % p
    return c1, c2

def elgamal_decryption(p, r, c1, c2):
    s = pow(c1, r, p)
    m = (c2 * pow(s, -1, p)) % p
    return m

p = getPrime(512)
alpha = 2
r = 123
u = pow(alpha, r, p)
message = "Confidential Data"
m = bytes_to_long(message.encode())

c1, c2 = elgamal_encryption(p, alpha, u, m)
print(f"Encrypted message: c1 = {c1}, c2 = {c2}")

decrypted_m = elgamal_decryption(p, r, c1, c2)
original_message = long_to_bytes(decrypted_m).decode()
print(f"Decrypted message: {original_message}")




