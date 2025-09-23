from Crypto.Util.number import getPrime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes
import numpy as np
import json
import base64
import random

KEYS = {}


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

KEYS = {}

def _blum_prime(bits):
    p = getPrime(bits)
    return p if p % 4 == 3 else _blum_prime(bits)

# Rabin keypair generator
def generate_keypair(bits=512):
    p = _blum_prime(bits // 2)
    q = _blum_prime(bits // 2)
    n = p * q
    return p, q, n

def generate(facility, bits=512):
    p, q, n = generate_keypair(bits)
    KEYS[facility] = {'p': p, 'q': q, 'n': n, 'revoked': False}
    print(f"[+] Generated for {facility}: n={n}")
    print(f"[+] Generated for {facility}: p={p}")
    print(f"[+] Generated for {facility}: q={q}")
    return p, q, n

def rabin_encrypt(message, p):
    message_bytes = message.encode('utf-8')
    m = bytes_to_long(message.encode())
    encrypted = pow(m, 2, p)
    print("Rabin Encrypted message: ", encrypted)

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
    s = (mod_inverse(k, p - 1) * (message - private_key * r)) % (
                p - 1)  # s = (k^-1 * (message - private_key * r)) mod (p-1)
    return r, s

# Digital Signature Verification (using public key)
def verify(public_key, p, g, message, r, s):
    if not (0 < r < p and 0 < s < p - 1):
        return False

    left = (pow(g, message, p) * pow(r, s, p)) % p  # g^message * r^s mod p
    right = pow(public_key, r, p)  # public_key^r mod p

    return left == right  # If they are equal, the signature is valid

if __name__ == "__main__":
    # Generate
    p, q, n = generate("Customer")
    message = "Send 55000 to Bob"

    rabin_encrypt(message, p)
    privateKey, publicKey = generate_keys(p, q)
    m = bytes_to_long(message.encode())
    c1,c2 = encrypt(publicKey, p, q, m)
    print("Ciphers for Elgamal: ", c1, c2)
    message = decrypt(privateKey, publicKey, c1, c2)
    r,s = sign(privateKey, publicKey, c1, c2)
    print("Signature for Elgamal: ", r, s)
    print(verify(publicKey, p,q, m, r, s))

