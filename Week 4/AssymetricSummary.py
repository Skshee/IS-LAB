"""
This file consolidates cryptographic algorithms from multiple scripts (Q1-Q5, AQ1-AQ5)
into a single class-based structure.

It includes classes for:
- RSAEncryptor: Handles RSA key generation, encryption, and decryption.
  - Includes both "textbook" RSA (from Q1, AQ3) for demonstration.
  - Includes hybrid RSA-KEM (from AQ5) for practical use.
- ECCEncryptor: Handles ECC (ECIES) key generation, encryption, and decryption.
  - Based on the hybrid ECIES (ECDH + AES) scheme (from Q2, AQ2, AQ4, AQ5).
- ElGamalEncryptor: Handles ElGamal key generation, encryption, and decryption.
  - Includes "textbook" ElGamal (from Q3).
  - Includes hybrid ElGamal (from AQ1) for practical use.
- DiffieHellmanPeer: Handles Diffie-Hellman key exchange.
  - Based on the logic from Q5.
"""

# --- Common Imports ---
import os
import random
import time
import hashlib
import secrets
import base64
from typing import Tuple, Dict, Any, Optional

# --- PyCryptodome Imports (used in Q1, Q2, Q3, Q4, AQ1, AQ5) ---
try:
    from Crypto.PublicKey import RSA, ECC
    from Crypto.Cipher import PKCS1_OAEP, AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import HKDF
    from Crypto.Random import get_random_bytes
    from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes, getPrime
except ImportError:
    print("PyCryptodome library not found. Please install with: pip install pycryptodomex")
    # Define stubs or raise error if critical
    class RSA:
        @staticmethod
        def generate(bits): pass
    class ECC:
        @staticmethod
        def generate(curve): pass
    # ... and so on

# --- Cryptography Imports (used in AQ2, AQ4, AQ5) ---
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as CryptoHKDF
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("Cryptography library not found. Please install with: pip install cryptography")


# === Class 1: RSA Encryptor ===
class RSAEncryptor:
    """
    Encapsulates RSA key generation, encryption, and decryption.
    """
    
    def __init__(self, key_bits: int = 2048):
        """Initializes the class, optionally generating a new key."""
        self.key_bits = key_bits
        self.key_pair: Optional[RSA.RsaKey] = None
        self.public_key: Optional[RSA.RsaKey] = None

    def generate_keys(self):
        """
        Generates a new RSA key pair.
        Based on logic from Q4.py and AQ5.py
        """
        print(f"Generating {self.key_bits}-bit RSA key...")
        self.key_pair = RSA.generate(self.key_bits)
        self.public_key = self.key_pair.publickey()
        print("RSA keys generated.")

    # --- Hybrid Encryption (Practical & Secure, from AQ5, Q4) ---
    
    def encrypt_hybrid(self, plaintext_bytes: bytes) -> Dict[str, bytes]:
        """
        Encrypts data using a hybrid RSA-KEM + AES-GCM scheme.
        The RSA key is used to encrypt a symmetric AES key.
        Based on logic from AQ5.py and Q4.py.
        
        Returns:
            A dictionary containing 'enc_aes_key', 'nonce', 'tag', 'ciphertext'.
        """
        if not self.public_key:
            raise ValueError("Public key not available. Call generate_keys() first.")
            
        # 1. Generate a symmetric AES key for this message
        aes_key = get_random_bytes(32) # AES-256
        
        # 2. Encrypt the AES key with the RSA public key
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        enc_aes_key = cipher_rsa.encrypt(aes_key)
        
        # 3. Encrypt the data with the AES key
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext_bytes)
        
        return {
            'enc_aes_key': enc_aes_key,
            'nonce': cipher_aes.nonce,
            'tag': tag,
            'ciphertext': ciphertext
        }

    def decrypt_hybrid(self, encrypted_payload: Dict[str, bytes]) -> bytes:
        """
        Decrypts data from a hybrid RSA-KEM + AES-GCM scheme.
        Based on logic from AQ5.py and Q4.py.
        """
        if not self.key_pair:
            raise ValueError("Private key not available. Call generate_keys() first.")

        # 1. Decrypt the AES key with the RSA private key
        cipher_rsa = PKCS1_OAEP.new(self.key_pair)
        aes_key = cipher_rsa.decrypt(encrypted_payload['enc_aes_key'])
        
        # 2. Decrypt the data with the AES key
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=encrypted_payload['nonce'])
        plaintext_bytes = cipher_aes.decrypt_and_verify(
            encrypted_payload['ciphertext'],
            encrypted_payload['tag']
        )
        
        return plaintext_bytes

    # --- Hybrid Encryption (CFB Mode, from AQ5.py) ---
    
    def encrypt_hybrid_cfb(self, plaintext_bytes: bytes) -> Dict[str, bytes]:
        """
        Encrypts data using a hybrid RSA-KEM + AES-CFB scheme.
        Based on logic from AQ5.py.
        
        Returns:
            A dictionary containing 'enc_aes_key', 'iv', 'ciphertext'.
        """
        if not self.public_key:
            raise ValueError("Public key not available. Call generate_keys() first.")
            
        # 1. Generate a symmetric AES key for this message
        aes_key = get_random_bytes(32) # AES-256
        
        # 2. Encrypt the AES key with the RSA public key
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        enc_aes_key = cipher_rsa.encrypt(aes_key)
        
        # 3. Encrypt the data with the AES key (CFB mode)
        iv = get_random_bytes(16) # AES block size for CFB IV
        cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv=iv)
        ciphertext = cipher_aes.encrypt(plaintext_bytes)
        
        return {
            'enc_aes_key': enc_aes_key,
            'iv': iv,
            'ciphertext': ciphertext
        }

    def decrypt_hybrid_cfb(self, encrypted_payload: Dict[str, bytes]) -> bytes:
        """
        Decrypts data from a hybrid RSA-KEM + AES-CFB scheme.
        Based on logic from AQ5.py.
        """
        if not self.key_pair:
            raise ValueError("Private key not available. Call generate_keys() first.")

        # 1. Decrypt the AES key with the RSA private key
        cipher_rsa = PKCS1_OAEP.new(self.key_pair)
        aes_key = cipher_rsa.decrypt(encrypted_payload['enc_aes_key'])
        
        # 2. Decrypt the data with the AES key (CFB mode)
        cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv=encrypted_payload['iv'])
        plaintext_bytes = cipher_aes.decrypt(encrypted_payload['ciphertext'])
        
        return plaintext_bytes

    # --- Textbook RSA (Insecure for large data, from Q1, AQ3) ---
    
    @staticmethod
    def encrypt_textbook(message: str, e: int, n: int) -> int:
        """
        Encrypts a message using textbook RSA.
        Based on Q1.py. Note: This is insecure for real-world use.
        It can only encrypt data smaller than 'n'.
        """
        m = bytes_to_long(message.encode('utf-8'))
        if m >= n:
            raise ValueError("Message is too large for this textbook RSA key.")
        return pow(m, e, n)

    @staticmethod
    def decrypt_textbook(ciphertext: int, d: int, n: int) -> str:
        """
        Decrypts a ciphertext using textbook RSA.
        Based on Q1.py.
        """
        m = pow(ciphertext, d, n)
        return long_to_bytes(m).decode('utf-8')
        
    @staticmethod
    def encrypt_textbook_chunked(message: str, e: int, n: int) -> list[int]:
        """
        Encrypts a message by breaking it into 1-byte chunks.
        Based on AQ3.py. This is also insecure but demonstrates
        handling messages larger than 'n' (where n is small).
        """
        msg_bytes = message.encode('utf-8')
        encrypted_chunks = []
        for byte in msg_bytes:
            # pow(byte, e, n)
            encrypted_chunks.append(pow(byte, e, n))
        return encrypted_chunks

    @staticmethod
    def decrypt_textbook_chunked(encrypted_chunks: list[int], d: int, n: int) -> str:
        """
        Decrypts 1-byte chunks.
        Based on AQ3.py.
        """
        decrypted_bytes = bytearray()
        for c in encrypted_chunks:
            m_int = pow(c, d, n)
            # Assuming 1-byte chunks
            decrypted_bytes.append(m_int)
        return decrypted_bytes.decode('utf-8')


# === Class 2: ECC Encryptor ===
class ECCEncryptor:
    """
    Encapsulates ECC (ECIES) key generation, encryption, and decryption.
    This implementation uses the 'cryptography' library (from AQ2, AQ4, AQ5).
    """
    
    def __init__(self, curve=ec.SECP256R1()):
        """Initializes the class, generating a new private key."""
        self.curve = curve
        print(f"Generating ECC key on curve {self.curve.name}...")
        self.private_key = ec.generate_private_key(self.curve)
        self.public_key = self.private_key.public_key()
        print("ECC key generated.")

    def get_public_key_bytes(self) -> bytes:
        """
        Returns the public key in a serialized format.
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    @staticmethod
    def encrypt(recipient_public_key_bytes: bytes, plaintext_bytes: bytes) -> Dict[str, bytes]:
        """
        Encrypts data using ECIES (ECDH + KDF + AES-GCM).
        This is a static method as it only needs the recipient's public key.
        Based on logic from AQ2.py, AQ4.py, AQ5.py.
        
        Args:
            recipient_public_key_bytes: The serialized public key of the recipient.
            plaintext_bytes: The data to encrypt.

        Returns:
            A dictionary containing 'ephemeral_pub_bytes', 'iv', 'tag', 'ciphertext'.
        """
        # Load the recipient's public key
        recipient_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), # Assuming P-256 / secp256r1
            recipient_public_key_bytes
        )

        # 1. Generate an ephemeral key pair for this message
        ephemeral_private = ec.generate_private_key(recipient_public_key.curve)
        ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint
        )
        
        # 2. Perform ECDH to get a shared secret
        shared_secret = ephemeral_private.exchange(ec.ECDH(), recipient_public_key)
        
        # 3. Derive a symmetric key from the shared secret
        derived_key = CryptoHKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecc-hybrid-encryption', # Standardized info parameter
        ).derive(shared_secret)
        
        # 4. Encrypt the data with AES-GCM
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(derived_key), modes.GCM(iv)).encryptor()
        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
        tag = encryptor.tag
        
        return {
            'ephemeral_pub_bytes': ephemeral_public_bytes,
            'iv': iv,
            'tag': tag,
            'ciphertext': ciphertext
        }

    def decrypt(self, encrypted_payload: Dict[str, bytes]) -> bytes:
        """
        Decrypts an ECIES payload using the instance's private key.
        Based on logic from AQ2.py, AQ4.py, AQ5.py.
        """
        # 1. Load the ephemeral public key
        ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
            self.curve,
            encrypted_payload['ephemeral_pub_bytes']
        )
        
        # 2. Perform ECDH with our private key
        shared_secret = self.private_key.exchange(ec.ECDH(), ephemeral_public)
        
        # 3. Derive the *same* symmetric key
        derived_key = CryptoHKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecc-hybrid-encryption', # Standardized info parameter
        ).derive(shared_secret)
        
        # 4. Decrypt the data
        decryptor = Cipher(algorithms.AES(derived_key), modes.GCM(
            encrypted_payload['iv'],
            encrypted_payload['tag']
        )).decryptor()
        
        plaintext = decryptor.update(encrypted_payload['ciphertext']) + decryptor.finalize()
        return plaintext


# === Class 3: ElGamal Encryptor ===
class ElGamalEncryptor:
    """
    Encapsulates ElGamal key generation, encryption, and decryption.
    """
    
    def __init__(self, p: int, g: int, x: Optional[int] = None):
        """
        Initializes with group parameters (p, g) and an optional private key (x).
        """
        self.p = p
        self.g = g
        if x:
            self.x = x
        else:
            print("Generating ElGamal private key...")
            self.x = random.randint(1, self.p - 2)
        
        # Public key h = g^x mod p
        self.h = pow(self.g, self.x, self.p)
        print(f"ElGamal Setup Complete:\np={p}\ng={g}\nx={x}\nh={self.h}")

    # --- Hybrid Encryption (Practical & Secure, from AQ1) ---
    
    @staticmethod
    def _derive_key_from_shared(shared_int: int) -> bytes:
        """Helper to hash the shared secret to an AES key."""
        h = SHA256.new()
        # Ensure shared_int is converted to bytes correctly
        shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7)//8 or 1, 'big')
        h.update(shared_bytes)
        return h.digest() # 32 bytes for AES-256

    def encrypt_hybrid(self, plaintext_bytes: bytes) -> Dict[str, Any]:
        """
        Encrypts data using a hybrid ElGamal + AES-GCM scheme.
        Based on logic from AQ1.py.
        """
        # 1. Generate ephemeral key 'y'
        y = random.randint(1, self.p - 2)
        
        # 2. Compute c1 and shared secret 's'
        c1 = pow(self.g, y, self.p)
        shared_secret = pow(self.h, y, self.p) # s = h^y mod p
        
        # 3. Derive AES key
        key = self._derive_key_from_shared(shared_secret)
        
        # 4. Encrypt with AES
        aes_cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext_bytes)
        
        return {
            'c1': c1, 
            'nonce': aes_cipher.nonce, 
            'ciphertext': ciphertext, 
            'tag': tag
        }

    def decrypt_hybrid(self, payload: Dict[str, Any]) -> bytes:
        """
        Decrypts a hybrid ElGamal payload.
        Based on logic from AQ1.py.
        """
        c1 = payload['c1']
        
        # 1. Compute shared secret 's'
        shared_secret = pow(c1, self.x, self.p) # s = c1^x mod p
        
        # 2. Derive the *same* AES key
        key = self._derive_key_from_shared(shared_secret)
        
        # 3. Decrypt with AES
        aes_cipher = AES.new(key, AES.MODE_GCM, nonce=payload['nonce'])
        plaintext = aes_cipher.decrypt_and_verify(
            payload['ciphertext'],
            payload['tag']
        )
        return plaintext

    # --- Textbook ElGamal (Insecure, from Q3) ---
    
    def encrypt_textbook(self, message_int: int) -> Tuple[int, int]:
        """
        Encrypts a message (as an integer) using textbook ElGamal.
        Based on Q3.py. Note: This is insecure.
        """
        if message_int >= self.p:
            raise ValueError("Message integer must be less than p.")
            
        # 1. Generate ephemeral key 'x' (confusingly named 'x' in Q3, 'y' in AQ1)
        k = random.randint(1, self.p - 2)
        
        # 2. Compute c1 and c2
        c1 = pow(self.g, k, self.p)
        c2 = (message_int * pow(self.h, k, self.p)) % self.p
        return c1, c2

    def decrypt_textbook(self, c1: int, c2: int) -> int:
        """
        Decrypts textbook ElGamal ciphertext.
        Based on Q3.py.
        """
        # s = c1^x mod p
        s = pow(c1, self.x, self.p)
        # m = c2 * s^-1 mod p
        s_inv = inverse(s, self.p)
        m = (c2 * s_inv) % self.p
        return m


# === Class 4: Diffie-Hellman Peer ===
class DiffieHellmanPeer:
    """
    Encapsulates one side of a Diffie-Hellman key exchange.
    Based on logic from Q5.py.
    """
    
    # 2048-bit MODP Group prime from RFC 3526 (group 14)
    RFC3526_P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
        "FFFFFFFFFFFFFFFF", 16
    )
    RFC3526_G = 2

    def __init__(self, p: int = RFC3526_P, g: int = RFC3526_G, private_key_bits: int = 384):
        """Initializes the peer with group parameters and generates keys."""
        self.p = p
        self.g = g
        print("Generating DH private key...")
        # Generate a private key
        self.private_key = secrets.randbits(private_key_bits) | (1 << (private_key_bits - 1)) | 1
        # Compute public key
        self.public_key = pow(self.g, self.private_key, self.p)
        print("DH Peer initialized with public key.")

    def get_public_key(self) -> int:
        """Returns this peer's public key."""
        return self.public_key

    def compute_shared_secret(self, other_peer_public_key: int) -> int:
        """
        Computes the shared secret given the other peer's public key.
        """
        print("Computing shared secret...")
        shared_secret = pow(other_peer_public_key, self.private_key, self.p)
        return shared_secret

    @staticmethod
    def derive_symmetric_key(shared_secret_int: int) -> bytes:
        """
        Derives a symmetric key (e.g., for AES) by hashing the shared secret.
        Based on Q5.py.
        """
        # Convert integer to big-endian bytes
        # Size should be based on P, but for simplicity we'll use bit_length
        size_bytes = (shared_secret_int.bit_length() + 7) // 8
        shared_bytes = shared_secret_int.to_bytes(size_bytes, byteorder='big')
        return hashlib.sha256(shared_bytes).digest()


# === Main execution block to demonstrate all classes ===

def get_input(prompt: str) -> str:
    """Helper function to get non-empty user input."""
    while True:
        val = input(prompt).strip()
        if val:
            return val
        print("Input cannot be empty.")

def demo_rsa():
    """Interactive demo for the RSAEncryptor class."""
    print("\n--- RSA Encryptor Demo ---")
    rsa_encryptor = RSAEncryptor(key_bits=2048)
    rsa_encryptor.generate_keys()
    
    while True:
        print("\nRSA Demo Options:")
        print("  1. Hybrid Encryption (GCM Mode - Secure)")
        print("  2. Hybrid Encryption (CFB Mode - from AQ5)")
        print("  3. Textbook Encryption (Chunked - from AQ3, Insecure)")
        print("  4. Back to Main Menu")
        choice = input("Enter choice: ").strip()

        if choice == '1':
            try:
                msg_str = get_input("Enter message to encrypt (GCM): ")
                msg_bytes = msg_str.encode('utf-8')
                
                encrypted_rsa = rsa_encryptor.encrypt_hybrid(msg_bytes)
                print(f"  > Encrypted payload (ciphertext sample): {encrypted_rsa['ciphertext'][:20]}...")
                
                decrypted_rsa = rsa_encryptor.decrypt_hybrid(encrypted_rsa)
                print(f"  > Decrypted message: {decrypted_rsa.decode()}")
                assert msg_bytes == decrypted_rsa
                print("  > SUCCESS: GCM Decryption matched original.")
            except Exception as e:
                print(f"An error occurred: {e}")

        elif choice == '2':
            try:
                msg_str = get_input("Enter message to encrypt (CFB): ")
                msg_bytes = msg_str.encode('utf-8')

                encrypted_rsa_cfb = rsa_encryptor.encrypt_hybrid_cfb(msg_bytes)
                print(f"  > Encrypted payload (ciphertext sample): {encrypted_rsa_cfb['ciphertext'][:20]}...")
                
                decrypted_rsa_cfb = rsa_encryptor.decrypt_hybrid_cfb(encrypted_rsa_cfb)
                print(f"  > Decrypted message: {decrypted_rsa_cfb.decode()}")
                assert msg_bytes == decrypted_rsa_cfb
                print("  > SUCCESS: CFB Decryption matched original.")
            except Exception as e:
                print(f"An error occurred: {e}")
        
        elif choice == '3':
            # Parameters from AQ3
            n_aq3, e_aq3, d_aq3 = 323, 5, 173
            print(f"Using textbook RSA with small keys (n={n_aq3}, e={e_aq3})")
            try:
                msg_aq3 = get_input("Enter message to encrypt (Textbook): ")
                
                enc_chunks = RSAEncryptor.encrypt_textbook_chunked(msg_aq3, e_aq3, n_aq3)
                print(f"  > Encrypted chunks (first 5): {enc_chunks[:5]}...")
                
                dec_msg_aq3 = RSAEncryptor.decrypt_textbook_chunked(enc_chunks, d_aq3, n_aq3)
                print(f"  > Decrypted message: {dec_msg_aq3}")
                assert msg_aq3 == dec_msg_aq3
                print("  > SUCCESS: Textbook Decryption matched original.")
            except Exception as e:
                print(f"An error occurred: {e}")

        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")

def demo_ecc():
    """Interactive demo for the ECCEncryptor class."""
    print("\n--- ECC Encryptor (ECIES) Demo ---")
    try:
        # Create a "recipient" who holds the private key
        ecc_recipient = ECCEncryptor()
        recipient_pub_key_bytes = ecc_recipient.get_public_key_bytes()
        print(f"Recipient generated keys (Curve: {ecc_recipient.curve.name})")

        msg_str = get_input("Enter message to encrypt with ECC: ")
        msg_bytes = msg_str.encode('utf-8')
        
        # The sender only needs the recipient's public key
        print("Sender is encrypting message...")
        encrypted_ecc = ECCEncryptor.encrypt(recipient_pub_key_bytes, msg_bytes)
        print(f"  > Encrypted payload (ciphertext sample): {encrypted_ecc['ciphertext'][:20]}...")

        # The recipient uses their private key to decrypt
        print("Recipient is decrypting message...")
        decrypted_ecc = ecc_recipient.decrypt(encrypted_ecc)
        print(f"  > Decrypted message: {decrypted_ecc.decode()}")
        assert msg_bytes == decrypted_ecc
        print("  > SUCCESS: ECC Decryption matched original.")
    except Exception as e:
        print(f"An error occurred: {e}")


def demo_elgamal():
    """Interactive demo for the ElGamalEncryptor class."""
    print("\n--- ElGamal Encryptor Demo ---")
    
    while True:
        print("\nElGamal Demo Options:")
        print("  1. Hybrid Encryption (from AQ1 params)")
        print("  2. Textbook Encryption (from Q3 params)")
        print("  3. Back to Main Menu")
        choice = input("Enter choice: ").strip()
        
        if choice == '1':
            try:
                # Parameters from AQ1
                p_aq1, g_aq1, x_aq1 = 7919, 2, 2999
                print(f"Using Hybrid ElGamal with params (p={p_aq1}, g={g_aq1})")
                elgamal_hybrid = ElGamalEncryptor(p=p_aq1, g=g_aq1, x=x_aq1)
                
                msg_str = get_input("Enter message to encrypt (Hybrid): ")
                msg_bytes = msg_str.encode('utf-8')
                
                encrypted_elgamal = elgamal_hybrid.encrypt_hybrid(msg_bytes)
                print(f"  > Encrypted payload (c1): {encrypted_elgamal['c1']}")
                
                decrypted_elgamal = elgamal_hybrid.decrypt_hybrid(encrypted_elgamal)
                print(f"  > Decrypted message: {decrypted_elgamal.decode()}")
                assert msg_bytes == decrypted_elgamal
                print("  > SUCCESS: Hybrid ElGamal Decryption matched original.")
            except Exception as e:
                print(f"An error occurred: {e}")

        elif choice == '2':
            try:
                # Generate params for Q3 demo
                p_q3 = getPrime(64) # Small prime for demo
                g_q3 = 2
                x_q3 = random.randint(1, p_q3-2)
                print(f"Using Textbook ElGamal with params (p={p_q3}, g={g_q3})")
                elgamal_textbook = ElGamalEncryptor(p=p_q3, g=g_q3, x=x_q3)
                
                msg_q3_str = get_input("Enter message to encrypt (Textbook): ")
                msg_q3_int = bytes_to_long(msg_q3_str.encode('utf-8'))
                
                # Ensure message < p
                while msg_q3_int >= p_q3:
                    print(f"Message integer ({msg_q3_int}) >= p ({p_q3}). Regenerating larger prime.")
                    p_q3 = getPrime(p_q3.bit_length() + 8)
                    elgamal_textbook = ElGamalEncryptor(p=p_q3, g=g_q3, x=x_q3)
                
                print(f"  > Original message as int: {msg_q3_int}")
                
                c1, c2 = elgamal_textbook.encrypt_textbook(msg_q3_int)
                print(f"  > Encrypted (c1, c2): ({c1}, {c2})")
                
                decrypted_q3_int = elgamal_textbook.decrypt_textbook(c1, c2)
                decrypted_q3_str = long_to_bytes(decrypted_q3_int).decode('utf-8')
                print(f"  > Decrypted message: {decrypted_q3_str} (as int {decrypted_q3_int})")
                assert msg_q3_int == decrypted_q3_int
                print("  > SUCCESS: Textbook ElGamal Decryption matched original.")
            except Exception as e:
                print(f"An error occurred: {e}")

        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

def demo_dh():
    """Interactive demo for the DiffieHellmanPeer class."""
    print("\n--- Diffie-Hellman Key Exchange Demo ---")
    try:
        # Create two peers
        print("Initializing Alice...")
        alice = DiffieHellmanPeer()
        print("Initializing Bob...")
        bob = DiffieHellmanPeer()
        
        print("\nAlice and Bob initialized.")
        
        # Exchange public keys
        alice_pub_key = alice.get_public_key()
        bob_pub_key = bob.get_public_key()
        print(f"  > Alice's Public Key (first 40 digits): {str(alice_pub_key)[:40]}...")
        print(f"  > Bob's Public Key (first 40 digits):   {str(bob_pub_key)[:40]}...")
        
        # Compute shared secrets
        print("\nPeers are computing shared secrets...")
        alice_shared_secret = alice.compute_shared_secret(bob_pub_key)
        bob_shared_secret = bob.compute_shared_secret(alice_pub_key)
        
        print(f"  > Alice's computed secret (first 40 digits): {str(alice_shared_secret)[:40]}...")
        print(f"  > Bob's computed secret (first 40 digits):   {str(bob_shared_secret)[:40]}...")
        
        if alice_shared_secret == bob_shared_secret:
            print("  > SUCCESS: Shared secrets match!")
        else:
            print("  > FAILURE: Shared secrets DO NOT match!")
            return

        # Derive a symmetric key
        print("\nDeriving symmetric keys from shared secret...")
        alice_sym_key = alice.derive_symmetric_key(alice_shared_secret)
        bob_sym_key = bob.derive_symmetric_key(bob_shared_secret)
        
        print(f"  > Alice's derived key (hex): {alice_sym_key.hex()}")
        print(f"  > Bob's derived key (hex):   {bob_sym_key.hex()}")

        if alice_sym_key == bob_sym_key:
            print("  > SUCCESS: Derived symmetric keys match!")
        else:
            print("  > FAILURE: Derived symmetric keys DO NOT match!")
    
    except Exception as e:
        print(f"An error occurred: {e}")

def main_menu():
    """Displays the main menu and runs the selected demo."""
    while True:
        print("\n" + "="*30)
        print("      Cryptographic Classes Demo")
        print("="*30)
        print("  1. RSA Encryption/Decryption")
        print("  2. ECC Encryption/Decryption (ECIES)")
        print("  3. ElGamal Encryption/Decryption")
        print("  4. Diffie-Hellman Key Exchange")
        print("  5. Exit")
        choice = input("Enter your choice [1-5]: ").strip()
        
        if choice == '1':
            demo_rsa()
        elif choice == '2':
            demo_ecc()
        elif choice == '3':
            demo_elgamal()
        elif choice == '4':
            demo_dh()
        elif choice == '5':
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

if __name__ == "__main__":
    main_menu()
