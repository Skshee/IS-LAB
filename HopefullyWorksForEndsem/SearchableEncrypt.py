import base64
import hashlib
from collections import defaultdict
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from phe import paillier

# ----------------------------------------------------------------------
# 0. Shared Dataset
# ----------------------------------------------------------------------

# Dataset used by both implementations
DOCUMENTS = {
    "doc1": "the quick brown fox jumps over the lazy dog",
    "doc2": "never jump over the lazy dog quickly",
    "doc3": "bright sun shines over the hills",
    "doc4": "the fox is clever and quick",
    "doc5": "dogs are loyal and friendly animals",
    "doc6": "the hills are alive with the sound of music",
    "doc7": "quick thinking leads to smart decisions",
    "doc8": "music soothes the soul and calms the mind",
    "doc9": "the clever dog outsmarted the fox",
    "doc10": "friendly animals make great companions"
}

# ----------------------------------------------------------------------
# 1. Deterministic AES (ECB) Searchable Encryption (from Q1.py)
# ----------------------------------------------------------------------

class DeterministicAES_SSE:
    """
    Implements a searchable encryption scheme using deterministic AES (ECB mode).
    
    WARNING: ECB mode is not semantically secure and leaks information
    (e.g., if two words are the same, their ciphertexts will be the same).
    This is what makes the direct lookup possible but is insecure in practice.
    """

    def __init__(self, key_bytes, documents):
        """
        Initializes the system with a key and the document set.
        """
        self.documents = documents
        # Use SHA-256 to ensure the key is 32 bytes (AES-256)
        self.key = hashlib.sha256(key_bytes).digest()
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.encrypted_index = {}
        print("AES SSE Initialized. Building index...")
        self._build_index()

    def _pad(self, text):
        """Applies PKCS#7 padding."""
        block_size = AES.block_size  # 16 bytes
        padding_len = block_size - len(text) % block_size
        padding = chr(padding_len) * padding_len
        return text + padding

    def _unpad(self, text):
        """Removes PKCS#7 padding."""
        padding_len = ord(text[-1])
        return text[:-padding_len]

    def _encrypt(self, text):
        """Encrypts a plaintext string using deterministic AES."""
        padded_text = self._pad(text)
        encrypted = self.cipher.encrypt(padded_text.encode())
        return base64.b64encode(encrypted).decode()

    def _decrypt(self, enc_text):
        """Decrypts a base64-encoded ciphertext."""
        try:
            encrypted_bytes = base64.b64decode(enc_text)
            decrypted = self.cipher.decrypt(encrypted_bytes)
            return self._unpad(decrypted.decode())
        except (ValueError, UnicodeDecodeError, IndexError):
            print(f"Error decrypting {enc_text}. Padding or key may be incorrect.")
            return None

    def _build_index(self):
        """
        Builds the inverted index from documents and encrypts both
        the keywords and the document IDs.
        """
        inverted_index = defaultdict(set)
        for doc_id, content in self.documents.items():
            for word in content.lower().split():
                inverted_index[word].add(doc_id)

        # Encrypt the index
        for word, doc_ids in inverted_index.items():
            encrypted_word = self._encrypt(word)
            encrypted_doc_ids = [self._encrypt(doc_id) for doc_id in doc_ids]
            self.encrypted_index[encrypted_word] = encrypted_doc_ids
        print("AES Encrypted index built.")

    def search(self, query):
        """
        Encrypts the query and searches the encrypted index.
        """
        encrypted_query = self._encrypt(query.lower())
        
        print(f"\n--- Search results for '{query}' (AES) ---")
        if encrypted_query in self.encrypted_index:
            encrypted_doc_ids = self.encrypted_index[encrypted_query]
            doc_ids = [self._decrypt(doc_id) for doc_id in encrypted_doc_ids]
            
            for doc_id in doc_ids:
                if doc_id and doc_id in self.documents:
                    print(f"{doc_id}: {self.documents[doc_id]}")
                elif doc_id:
                    print(f"Error: Decrypted ID '{doc_id}' not found in document list.")
        else:
            print("No results found.")

# ----------------------------------------------------------------------
# 2. Paillier-Based Encrypted Index (from Q2.py)
# ----------------------------------------------------------------------

class PaillierEncryptedIndex:
    """
    Implements an encrypted index using Paillier.
    
    NOTE: This implementation (from Q2.py) encrypts *only* the
    document IDs (values), not the keywords (keys). The search query
    is performed in plaintext, which means the server learns what
    is being searched for. This protects the *content* of the
    search results (which doc IDs match) but not the query itself.
    """

    def __init__(self, documents):
        """
        Initializes the system, generates Paillier keys, and builds the index.
        """
        self.documents = documents
        print("\nPaillier Index Initializing. Generating keys...")
        self.public_key, self.private_key = paillier.generate_paillier_keypair()
        
        # Map document names to unique integers for Paillier encryption
        self.doc_id_map = {doc_name: idx + 1 for idx, doc_name in enumerate(documents.keys())}
        self.reverse_doc_id_map = {v: k for k, v in self.doc_id_map.items()}
        
        self.encrypted_index = {}
        print("Building index...")
        self._build_index()

    def _encrypt_int(self, val):
        """Encrypts an integer using the Paillier public key."""
        return self.public_key.encrypt(val)

    def _decrypt_int(self, enc_val):
        """Decrypts a Paillier ciphertext using the private key."""
        return self.private_key.decrypt(enc_val)

    def _build_index(self):
        """
        Builds the inverted index, mapping plaintext words to
        lists of Paillier-encrypted integer document IDs.
        """
        # Build plaintext index: word -> set of integer IDs
        inverted_index = defaultdict(set)
        for doc_name, content in self.documents.items():
            for word in content.lower().split():
                inverted_index[word].add(self.doc_id_map[doc_name])

        # Encrypt the values (doc IDs) of the index
        for word, doc_ids in inverted_index.items():
            # The 'word' (key) remains in plaintext
            encrypted_doc_ids = [self._encrypt_int(doc_id) for doc_id in doc_ids]
            self.encrypted_index[word] = encrypted_doc_ids
        print("Paillier Encrypted index built (plaintext keys, encrypted doc IDs).")

    def search(self, query):
        """
        Searches the index using the *plaintext* query.
        """
        query_lower = query.lower()
        
        print(f"\n--- Search results for '{query}' (Paillier) ---")
        # Search is a simple plaintext lookup
        if query_lower in self.encrypted_index:
            enc_doc_ids = self.encrypted_index[query_lower]
            
            # Decrypt the list of document IDs
            doc_ids = [self._decrypt_int(enc_id) for enc_id in enc_doc_ids]
            
            for doc_id in doc_ids:
                doc_name = self.reverse_doc_id_map[doc_id]
                print(f"{doc_name}: {self.documents[doc_name]}")
        else:
            print("No results found.")

# ----------------------------------------------------------------------
# 3. Demonstration and Main Menu
# ----------------------------------------------------------------------

def demo_aes_sse():
    """Runs a demo of the DeterministicAES_SSE class."""
    print("="*40)
    print("  Running Deterministic AES SSE Demo (Q1)")
    print("="*40)
    
    # 1. Initialize
    aes_searcher = DeterministicAES_SSE(b'my_secret_key_12345', DOCUMENTS)
    
    # 2. Run searches
    queries = ["fox", "music", "loyal", "quick", "animals", "sun"]
    for q in queries:
        aes_searcher.search(q)
    
    print("="*40)
    print("AES Demo Complete.\n")

def demo_paillier_index():
    """Runs a demo of the PaillierEncryptedIndex class."""
    print("="*40)
    print("  Running Paillier Encrypted Index Demo (Q2)")
    print("="*40)

    # 1. Initialize
    paillier_searcher = PaillierEncryptedIndex(DOCUMENTS)

    # 2. Run searches
    queries = ["fox", "music", "loyal", "quick", "animals", "sun"]
    for q in queries:
        paillier_searcher.search(q)

    print("="*40)
    print("Paillier Demo Complete.\n")

def main_menu():
    """
    Provides a command-line menu to run the different demos.
    """
    while True:
        print("\n" + "="*40)
        print("  Searchable Encryption Demos")
        print("="*40)
        print("1. Demo: Deterministic AES (ECB) SSE (from Q1.py)")
        print("2. Demo: Paillier Encrypted Index (from Q2.py)")
        print("3. Exit")
        print("="*40)
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == '1':
            demo_aes_sse()
        elif choice == '2':
            demo_paillier_index()
        elif choice == '3':
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")
        
        if choice in ('1', '2'):
            input("\nPress Enter to return to the menu...")

if __name__ == "__main__":
    main_menu()
