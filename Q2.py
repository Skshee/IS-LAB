def vigenere_encrypt(plaintext, key):
    ciphertext = ""
    Key = []
    for i in range(len(plaintext)):
        Key.append(key[i % len(key)])

    for i in range(len(plaintext)):
        ciphertext += chr((ord(plaintext[i]) + ord(Key[i]) - 2 * ord('a')) % 26 + ord('a'))
    return ciphertext

plaintext = "thehouseisbeingsoldtonight"
print("Vigenere Encrypt : " + vigenere_encrypt(plaintext, "dollars"))

