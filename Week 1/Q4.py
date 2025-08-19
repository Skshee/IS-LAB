import numpy as np

def mod_inv(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def matrix_mod_inv(matrix, modulus):
    det = int(round(np.linalg.det(matrix)))  # determinant
    det = det % modulus
    det_inv = mod_inv(det, modulus)
    if det_inv is None:
        raise ValueError("Matrix is not invertible under modulo {}".format(modulus))
    inv_matrix = np.array([[matrix[1,1], -matrix[0,1]],
                           [-matrix[1,0], matrix[0,0]]]) % modulus
    return (det_inv * inv_matrix) % modulus

def hill_cipher(text, key_matrix, mode='encrypt'):
    text = ''.join([c for c in text.upper() if c.isalpha()])  # clean text
    n = key_matrix.shape[0]

    text_values = [ord(char) - ord('A') for char in text]

    # Padding
    if len(text_values) % n != 0:
        text_values += [ord('X') - ord('A')] * (n - len(text_values) % n)

    text_matrix = np.array(text_values).reshape(-1, n)

    if mode == 'encrypt':
        result_matrix = np.dot(text_matrix, key_matrix) % 26
    elif mode == 'decrypt':
        key_matrix_inv = matrix_mod_inv(key_matrix, 26)
        result_matrix = np.dot(text_matrix, key_matrix_inv) % 26
    else:
        raise ValueError("Mode must be 'encrypt' or 'decrypt'")

    result_values = result_matrix.flatten().astype(int)
    result_text = ''.join(chr(value + ord('A')) for value in result_values)

    return result_text

text = 'We live in an insecure world'
key_matrix = np.array([[3, 3], [2, 7]])
encoded_text = hill_cipher(text, key_matrix, mode='encrypt')
print('Encoded Text:', encoded_text)
decoded_text = hill_cipher(encoded_text, key_matrix, mode='decrypt')
print('Decoded Text:', decoded_text)
