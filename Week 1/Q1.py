def additive_encrypt(text, key):
    ciphertext = ""
    for char in text:
        if char != " ":
            #Uppercase characters
            if (char.isupper()):
                ciphertext += chr((ord(char) + key - 65) % 26 + 65)

            #Lowercase characters
            else:
                ciphertext += chr((ord(char) + key - 97) % 26 + 97)
        else:
            ciphertext += " " # Adding the spaces wherever we encounter them
    return ciphertext

def multiplicative_encrypt(text,key):
    ciphertext = ""
    for char in text:
        if char != " ":
            if(char.islower()):
                ciphertext += chr((((ord(char) - 97) * key) % 26) + 97)
            if(char.isupper()):
                ciphertext += chr((((ord(char) - 65) * key) % 26) + 65)
        else:
            ciphertext += " "
    return ciphertext

def affine_encrypt(text,key1, key2):
    ciphertext = ""
    for char in text:
        if char != " ":
            if(char.islower()):
                ciphertext  += chr(((((ord(char) - 97) * key1) + key2) % 26) + 97)
            if (char.isupper()):
                ciphertext += chr(((((ord(char) - 65) * key1) + key2) % 26) + 65)
        else:
            ciphertext += " "
    return ciphertext

def additive_decrypt(text,key):
    ciphertext = additive_encrypt(text,key)
    plaintext = ""
    for char in ciphertext:
        if char != " ":
            if(char.islower()):
                plaintext += chr((ord(char) - key - 97) % 26 + 97)
            if(char.isupper()):
                plaintext += chr((ord(char) - key - 65) % 26 + 65)
        else:
            plaintext += " "
    return plaintext

def multiplicative_decrypt(text,key):
    ciphertext = multiplicative_encrypt(text,key)
    inverse_key = pow(key, -1, 26)
    plaintext = ""
    for char in ciphertext:
        if char != " ":
            if(char.islower()):
                plaintext += chr((((ord(char) - 97) * inverse_key) % 26) + 97)
            if (char.isupper()):
                plaintext += chr((((ord(char) -65) * inverse_key) % 26) + 65)
        else:
            plaintext += " "
    return plaintext

def affine_decrypt(text,key1, key2):
    ciphertext = affine_encrypt(text,key1,key2)
    plaintext = ""
    inverse_key1 = pow(key1, -1, 26)
    for char in ciphertext:
        if char != " ":
            if(char.islower()):
                plaintext += chr(((inverse_key1 * (ord(char) - 97 - key2)) % 26) + 97)
            if (char.isupper()):
                plaintext += chr(((inverse_key1 * (ord(char) - 65 - key2)) % 26) + 65)
        else:
            plaintext += " "
    return plaintext

text = "I am learning information security"

print("Additive cipher with key = 20 : " + additive_encrypt(text,20))
print("Multiplicative cipher with key = 15 : " + multiplicative_encrypt(text,15))
print("Affine cipher with keys = 15 & 20 : " + affine_encrypt(text,15,20))
print("Additive decrypt with key = 20 : " + additive_decrypt(text,20))
print("Multiplicative decrypt with key = 15 : " + multiplicative_decrypt(text,15))
print("Affine decrypt with keys = 15 & 20 : " + affine_decrypt(text,15,20))



