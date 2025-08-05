from Crypto.Cipher import DES3
from Crypto import Random
from Crypto.Util.Padding import pad, unpad


key = b'1234567890ABCDEF12345678'
iv = Random.new().read(DES3.block_size)

# Create cipher for encryption
cipher_encrypt = DES3.new(key, DES3.MODE_OFB, iv)


plaintext = b'Classified Text'
padded_plaintext = pad(plaintext, DES3.block_size)

# Encrypt the plaintext
encrypted_text = cipher_encrypt.encrypt(padded_plaintext)

# Create cipher for decryption
cipher_decrypt = DES3.new(key, DES3.MODE_OFB, iv)

# Decrypt the encrypted text
decrypted_padded_text = cipher_decrypt.decrypt(encrypted_text)

# Unpad the decrypted text
decrypted_text = unpad(decrypted_padded_text, DES3.block_size)

print("Encrypted:", encrypted_text)
print("Decrypted:", decrypted_text.decode('utf-8'))
