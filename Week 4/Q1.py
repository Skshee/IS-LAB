from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes

message = 'Asymmetric Encryption'
p = 857504083339712752489993810777
q = 1029224947942998075080348647219
e = 65537
N = p * q
phi = (p - 1) * (q - 1)

# Private Key
d = inverse(e, phi)

m = bytes_to_long(message.encode())

ciphertext = pow(m, e, N)

decrypted_int = pow(ciphertext, d, N)
decrypted_message = long_to_bytes(decrypted_int).decode()

print("Original Message:", message)
print("Encrypted Integer:", ciphertext)
print("Decrypted Message:", decrypted_message)