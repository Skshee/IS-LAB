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

def AutokeyEncrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    key_letter = alphabet[key % 26]
    keystream = key_letter + plaintext
    ciphertext = ""

    for i in range(len(plaintext)):
        p = alphabet.index(plaintext[i])
        k = alphabet.index(keystream[i])
        c = (p + k) % 26
        ciphertext += alphabet[c]
    return ciphertext

def AutokeyDecrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key_letter = alphabet[key % 26]
    keystream = key_letter
    plaintext = ""

    for i in range(len(ciphertext)):
        c = alphabet.index(ciphertext[i])
        k = alphabet.index(keystream[i])
        p = (c - k + 26) % 26
        plain_char = alphabet[p]
        plaintext += plain_char
        keystream += plain_char
    return plaintext


plaintext = "thehouseisbeingsoldtonight"
ciphertext = vigenere_encrypt(plaintext, "dollars")
print("Vigenere Encrypt : " + vigenere_encrypt(plaintext, "dollars"))
print("Vigenere decrypt : " + vigenere_decrypt(ciphertext, "dollars"))





