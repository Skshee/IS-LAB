'''
 Implement the hash function in Python. Your function should start with an initial hash
 value of 5381 and for each character in the input string, multiply the current hash value
 by 33, add the ASCII value of the character, and use bitwise operations to ensure
 thorough mixing of the bits. Finally, ensure the hash value is kept within a 32-bit range
 by applying an appropriate mask.
'''

def custom_hash(input_string):
    hash_value = 5381  # Initial hash value

    for char in input_string:
        # Multiply by 33 and add ASCII value of character
        hash_value = ((hash_value << 5) + hash_value) + ord(char)  # hash * 33 + ord(char)

        # Bitwise mixing: XOR with shifted hash
        hash_value ^= (hash_value >> 13)

    # Ensure 32-bit unsigned integer range
    hash_value &= 0xFFFFFFFF

    return hash_value

print(custom_hash("Hello World!"))