from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# AES-128 requires a 16-byte (128-bit) key
key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
iv = bytes.fromhex("00112233445566778899aabbccddeeff")

def encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Using CBC mode
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return encrypted_data

def decrypt(encrypted_data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode()

# Example usage
plaintext = "Sensitive Data"
print("Original Text:", plaintext)

# Encrypt
encrypted = encrypt(plaintext, key, iv)
string_data = base64.b64encode(encrypted).decode('utf-8')
print("Encrypted Data:", string_data)

# Decrypt
decrypted = decrypt(encrypted, key, iv)
print("Decrypted Text:", decrypted)


