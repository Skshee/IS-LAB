# compiled_crypto_system.py
import random
import hashlib
import hmac

class CryptoUtils:
    """
    A helper class for static cryptographic utility functions,
    like the Extended Euclidean Algorithm for modular inverse.
    """
    
    @staticmethod
    def mod_inverse(a, m):
        """
        Calculates the modular multiplicative inverse of 'a' modulo 'm'
        using the Extended Euclidean Algorithm.
        """
        t, new_t = 0, 1
        r, new_r = m, a
        
        while new_r != 0:
            quotient = r // new_r
            t, new_t = new_t, t - quotient * new_t
            r, new_r = new_r, r - quotient * new_r
        
        if r > 1:
            raise ValueError(f"{a} has no inverse modulo {m}")
        
        if t < 0:
            t = t + m
        
        return t

class CryptoEntity:
    """
    Represents a single entity (like a user, client, or server)
    that can perform a suite of cryptographic operations.
    """
    
    def __init__(self, p, g):
        """
        Initializes the entity with public parameters p (prime) and g (generator).
        """
        if not (isinstance(p, int) and isinstance(g, int)):
            raise TypeError("p and g must be integers.")
        self.p = p
        self.g = g
        self.p_minus_1 = p - 1 # Pre-calculate for signature mod
        
        # ElGamal/Signature keys
        self.elgamal_priv_key = None
        self.elgamal_pub_key = None
        
        # Diffie-Hellman keys
        self.dh_priv_key = None
        self.dh_pub_key = None
        
        # Shared secret and derived HMAC key
        self.shared_secret = None
        self.hmac_key = None

    # --- Key Generation ---

    def generate_elgamal_keys(self):
        """
        Generates ElGamal private and public keys.
        (Also used for ElGamal Signatures)
        """
        # Private key 'a' is in the range [1, p-2]
        self.elgamal_priv_key = random.randint(1, self.p - 2)
        # Public key 'y' = g^a mod p
        self.elgamal_pub_key = pow(self.g, self.elgamal_priv_key, self.p)
        print(f"  > ElGamal Keys Generated: Pub={self.elgamal_pub_key}")

    def generate_dh_keys(self):
        """
        Generates Diffie-Hellman private and public keys.
        """
        # Private key 'x' is in the range [1, p-2]
        self.dh_priv_key = random.randint(1, self.p - 2)
        # Public key 'X' = g^x mod p
        self.dh_pub_key = pow(self.g, self.dh_priv_key, self.p)
        print(f"  > Diffie-Hellman Keys Generated: Pub={self.dh_pub_key}")

    # --- Diffie-Hellman & HMAC ---

    def compute_shared_secret(self, other_dh_pub_key):
        """
        Computes the shared secret K using our private DH key
        and the other party's public DH key.
        K = (Y^x) mod p
        """
        self.shared_secret = pow(other_dh_pub_key, self.dh_priv_key, self.p)
        print(f"  > Shared Secret Computed: {self.shared_secret}")
        self.derive_hmac_key() # Automatically derive HMAC key
        return self.shared_secret

    def derive_hmac_key(self):
        """
        Derives a symmetric HMAC key from the shared secret K.
        Uses the same method as q3server/client.py
        """
        if self.shared_secret is None:
            raise ValueError("Shared secret must be computed first.")
        
        self.hmac_key = hashlib.sha256(str(self.shared_secret).encode()).digest()
        print(f"  > HMAC Key Derived.")

    def create_hmac(self, message: bytes) -> str:
        """
        Creates an HMAC-SHA256 tag for a message.
        """
        if self.hmac_key is None:
            raise ValueError("HMAC key not derived.")
            
        tag = hmac.new(self.hmac_key, message, hashlib.sha256).hexdigest()
        return tag

    def verify_hmac(self, message: bytes, tag: str) -> bool:
        """
        Verifies an HMAC-SHA256 tag for a message.
        """
        if self.hmac_key is None:
            raise ValueError("HMAC key not derived.")
            
        expected_tag = hmac.new(self.hmac_key, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_tag, tag)

    # --- ElGamal Encryption / Decryption ---

    def encrypt(self, message: int, recipient_elgamal_pub_key: int) -> tuple:
        """
        Encrypts an integer message using the recipient's ElGamal public key.
        """
        k = random.randint(1, self.p - 2)  # Ephemeral key
        c1 = pow(self.g, k, self.p)
        # s = y^k mod p
        s = pow(recipient_elgamal_pub_key, k, self.p)
        c2 = (message * s) % self.p
        return (c1, c2)

    def decrypt(self, c1: int, c2: int) -> int:
        """
        Decrypts an ElGamal ciphertext (c1, c2) using our private key.
        """
        if self.elgamal_priv_key is None:
            raise ValueError("ElGamal private key not generated.")
            
        # s = c1^a mod p
        s = pow(c1, self.elgamal_priv_key, self.p)
        # s_inv = s^-1 mod p
        s_inv = CryptoUtils.mod_inverse(s, self.p)
        # m = (c2 * s_inv) mod p
        message = (c2 * s_inv) % self.p
        return message

    # --- ElGamal Signature / Verification ---

    def sign(self, message: int) -> tuple:
        """
        Signs an integer message using our ElGamal private key.
        Note: This scheme requires k to have an inverse mod (p-1).
        """
        if self.elgamal_priv_key is None:
            raise ValueError("ElGamal private key not generated.")

        while True:
            k = random.randint(1, self.p - 2)
            try:
                # Ensure k has an inverse mod (p-1)
                k_inv = CryptoUtils.mod_inverse(k, self.p_minus_1)
                break
            except ValueError:
                continue # Pick a new k
        
        r = pow(self.g, k, self.p)
        
        # s = (k^-1 * (m - a*r)) mod (p-1)
        s = (k_inv * (message - self.elgamal_priv_key * r)) % self.p_minus_1
        
        return (r, s)

    def verify(self, message: int, r: int, s: int, sender_elgamal_pub_key: int) -> bool:
        """
        Verifies an ElGamal signature (r, s) for a message
        using the sender's ElGamal public key.
        """
        if not (0 < r < self.p and 0 < s < self.p_minus_1):
            return False
            
        # Verification check: (y^r * r^s) mod p == g^m mod p
        
        # Left side: (y^r * r^s) mod p
        left = (pow(sender_elgamal_pub_key, r, self.p) * pow(r, s, self.p)) % self.p
        
        # Right side: g^m mod p
        right = pow(self.g, message, self.p)
        
        return left == right


# --- Main Execution ---
if __name__ == "__main__":
    
    # Setup global parameters (from q3server.py)
    p_global = 2087
    g_global = 2
    
    print(f"--- Cryptographic System Simulation ---")
    print(f"Global Parameters: p={p_global}, g={g_global}\n")
    
    # 1. Initialize Entities
    alice = CryptoEntity(p_global, g_global)
    bob = CryptoEntity(p_global, g_global)
    
    # 2. Key Generation
    print("Step 1: Key Generation")
    print(" Alice:")
    alice.generate_elgamal_keys()
    alice.generate_dh_keys()
    print(" Bob:")
    bob.generate_elgamal_keys()
    bob.generate_dh_keys()
    print("-" * 40)
    
    # 3. Diffie-Hellman Key Exchange
    print("Step 2: Diffie-Hellman Key Exchange")
    print(" Alice computes shared secret using Bob's public key:")
    k_alice = alice.compute_shared_secret(bob.dh_pub_key)
    
    print(" Bob computes shared secret using Alice's public key:")
    k_bob = bob.compute_shared_secret(alice.dh_pub_key)
    
    assert k_alice == k_bob
    print(f"\n > Success! Both parties computed the same secret: {k_alice}")
    print("-" * 40)
    
    # 4. Digital Signature & Verification
    print("Step 3: Digital Signature (Alice -> Bob)")
    msg_to_sign = 1234 # Message must be an integer for this scheme
    print(f" Alice signs message: {msg_to_sign}")
    
    r_sig, s_sig = alice.sign(msg_to_sign)
    print(f"  > Signature (r, s): ({r_sig}, {s_sig})")
    
    print(f" Bob verifies signature using Alice's public key...")
    is_valid_sig = bob.verify(msg_to_sign, r_sig, s_sig, alice.elgamal_pub_key)
    print(f"  > Signature valid: {is_valid_sig}")
    assert is_valid_sig
    print("-" * 40)
    
    # 5. ElGamal Encryption & Decryption
    print("Step 4: Encryption (Alice -> Bob)")
    msg_to_encrypt = 5678 # Message must be an integer
    print(f" Alice encrypts message for Bob: {msg_to_encrypt}")
    
    c1, c2 = alice.encrypt(msg_to_encrypt, bob.elgamal_pub_key)
    print(f"  > Ciphertext (c1, c2): ({c1}, {c2})")
    
    print(f" Bob decrypts message using his private key...")
    decrypted_msg = bob.decrypt(c1, c2)
    print(f"  > Decrypted message: {decrypted_msg}")
    assert msg_to_encrypt == decrypted_msg
    print("-" * 40)
    
    # 6. HMAC Message Authentication
    print("Step 5: Message Authentication (HMAC) (Alice -> Bob)")
    msg_to_auth = b"Hello Bob, this is an authenticated message."
    print(f" Alice sends message: {msg_to_auth.decode()}")
    
    tag = alice.create_hmac(msg_to_auth)
    print(f"  > Attaching HMAC tag: {tag}")
    
    print(f" Bob verifies HMAC tag using the shared key...")
    is_valid_hmac = bob.verify_hmac(msg_to_auth, tag)
    print(f"  > HMAC valid (message is authentic): {is_valid_hmac}")
    assert is_valid_hmac
    print("-" * 40)
