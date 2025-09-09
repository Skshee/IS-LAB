import random

# Extended Euclidean Algorithm to find modular inverse
def mod_inverse(a, m):
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

# Diffie-Hellman Key Exchange
def diffie_hellman(p, g):
    # Party A private key and public key
    private_key_A = random.randint(1, p-2)  # Private key for party A
    public_key_A = pow(g, private_key_A, p)  # g^private_key_A mod p (public key for A)

    # Party B private key and public key
    private_key_B = random.randint(1, p-2)  # Private key for party B
    public_key_B = pow(g, private_key_B, p)  # g^private_key_B mod p (public key for B)

    # Party A computes shared secret using B's public key
    shared_secret_A = pow(public_key_B, private_key_A, p)

    # Party B computes shared secret using A's public key
    shared_secret_B = pow(public_key_A, private_key_B, p)

    # Check if both parties computed the same shared secret
    assert shared_secret_A == shared_secret_B, "Shared secrets don't match!"

    return private_key_A, public_key_A, private_key_B, public_key_B, shared_secret_A

# Example usage
p = 7919  # Prime number (can be much larger in real-world applications)
g = 2     # Primitive root modulo p (can be any generator modulo p)

# Perform the Diffie-Hellman Key Exchange
private_key_A, public_key_A, private_key_B, public_key_B, shared_secret = diffie_hellman(p, g)

# Display the results
print(f"Private Key A: {private_key_A}")
print(f"Public Key A: {public_key_A}")
print(f"Private Key B: {private_key_B}")
print(f"Public Key B: {public_key_B}")
print(f"Shared Secret: {shared_secret}")
