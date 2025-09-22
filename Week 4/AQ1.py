'''
With the ElGamal public key (p = 7919, g = 2, h = 6465) and the private key x =
2999, encrypt the message "Asymmetric Algorithms". Decrypt the resulting
ciphertext to verify the original message. 
'''
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import random
import base64

p = 7919
g = 2
x = 2999
h = pow(g, x, p)  # ensure consistency

def derive_key_from_shared(shared_int):
    h = SHA256.new()
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7)//8 or 1, 'big')
    h.update(shared_bytes)
    return h.digest()  # 32 bytes -> AES-256

def hybrid_elgamal_encrypt(plaintext_bytes, p, g, h):
    y = random.randint(1, p-2)
    c1 = pow(g, y, p)
    shared = pow(h, y, p)
    key = derive_key_from_shared(shared)
    aes_cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext_bytes)
    return {'c1': c1, 'nonce': aes_cipher.nonce, 'ciphertext': ciphertext, 'tag': tag, 'y': y}

def hybrid_elgamal_decrypt(payload, p, x):
    c1 = payload['c1']
    nonce = payload['nonce']
    ciphertext = payload['ciphertext']
    tag = payload['tag']
    shared = pow(c1, x, p)
    key = derive_key_from_shared(shared)
    aes_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# Demo
random.seed(42)
message = "Asymmetric Algorithms".encode('utf-8')
payload = hybrid_elgamal_encrypt(message, p, g, h)

print("Using consistent public h = g^x mod p =", h)
print("c1:", payload['c1'])
print("nonce (base64):", base64.b64encode(payload['nonce']).decode())
print("ciphertext (base64):", base64.b64encode(payload['ciphertext']).decode())
print("tag (base64):", base64.b64encode(payload['tag']).decode())
# ephemeral y included here only for demonstration transparency:
print("ephemeral y (demo only):", payload['y'])

decrypted = hybrid_elgamal_decrypt(payload, p, x)
print("Decrypted plaintext:", decrypted.decode('utf-8'))
