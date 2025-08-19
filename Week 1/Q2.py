def vigenere_encrypt(plaintext, key):
    ciphertext = ""
    Key = []
    for i in range(len(plaintext)):
        Key.append(key[i % len(key)])

    cipher_text = []
    for i in range(len(plaintext)):
        x = ((ord(plaintext[i]) - ord('a') + ord(Key[i]) - ord('a')) % 26) + ord('a')
        cipher_text.append(chr(x))
    return "".join(cipher_text)

def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    Key = []
    for i in range(len(ciphertext)):
        Key.append(key[i % len(key)])

    for i in range(len(ciphertext)):
        x = ((ord(ciphertext[i]) - ord('a') - (ord(Key[i]) - ord('a')) + 26) % 26) + ord('a')
        plaintext += chr(x)
    return plaintext


plaintext = "thehouseisbeingsoldtonight"
ciphertext = vigenere_encrypt(plaintext, "dollars")
print("Vigenere Encrypt : " + vigenere_encrypt(plaintext, "dollars"))
print("Vigenere decrypt : " + vigenere_decrypt(ciphertext, "dollars"))




