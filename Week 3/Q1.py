'''
Encrypt the message "Confidential Data" using DES with the following key:
"A1B2C3D4". Then decrypt the ciphertext to verify the original message.
'''

from Crypto.Cipher import DES
import base64

key = b'A1B2C3D4'
plaintext = b'Confidential Data'

# Encrypt
cipher = DES.new(key, DES.MODE_OFB)
msg = cipher.iv + cipher.encrypt(plaintext)
string_data = base64.b64encode(msg).decode('utf-8')
print("Encrypted (base64):", string_data)

# Decrypt
decoded_data = base64.b64decode(string_data)
iv = decoded_data[:8]
ciphertext = decoded_data[8:]
decipher = DES.new(key, DES.MODE_OFB, iv=iv)
decrypted = decipher.decrypt(ciphertext)

print("Decrypted:", decrypted.decode('utf-8'))
