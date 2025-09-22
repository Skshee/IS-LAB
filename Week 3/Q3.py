'''
Compare the encryption and decryption times for DES and AES-256 for the
message "Performance Testing of Encryption Algorithms". Use a standard
implementation and report your findings.
'''

# Q3: DES vs AES-256 timing comparison
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
import time

msg = ("Performance Testing of Encryption Algorithms " * 2000).strip()
iterations = 200

des_key = b"A1B2C3D4"
aes256_key = b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"[:32]

# DES timing
start = time.perf_counter()
for _ in range(iterations):
    ct = DES.new(des_key, DES.MODE_ECB).encrypt(pad(msg.encode(), DES.block_size))
    DES.new(des_key, DES.MODE_ECB).decrypt(ct)
des_time = time.perf_counter() - start

# AES-256 timing
start = time.perf_counter()
for _ in range(iterations):
    ct = AES.new(aes256_key, AES.MODE_ECB).encrypt(pad(msg.encode(), AES.block_size))
    AES.new(aes256_key, AES.MODE_ECB).decrypt(ct)
aes256_time = time.perf_counter() - start

print(f"DES time (s): {des_time}")
print(f"AES-256 time (s): {aes256_time}")
