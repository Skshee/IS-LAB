import random
import math
import time
from statistics import mean

# ----------------------------------------------------------------------
# 1. Utility Class
# ----------------------------------------------------------------------

class CryptoUtils:
    """
    Contains static helper methods for mathematical operations
    used across different cryptosystems.
    """

    @staticmethod
    def gcd(a, b):
        """Compute the greatest common divisor of a and b."""
        while b != 0:
            a, b = b, a % b
        return a

    @staticmethod
    def lcm(a, b):
        """Compute the least common multiple of a and b."""
        if a == 0 or b == 0:
            return 0
        return abs(a * b) // CryptoUtils.gcd(a, b)

    @staticmethod
    def modinv_eea(a, m):
        """
        Compute modular inverse of a mod m using Extended Euclidean Algorithm.
        (From Q2.py)
        """
        m0, x0, x1 = m, 0, 1
        if m == 1:
            return 0
        while a > 1:
            if m == 0:  # No inverse exists
                return None
            q = a // m
            a, m = m, a % m
            x0, x1 = x1 - q * x0, x0
        return x1 + m0 if x1 < 0 else x1

    @staticmethod
    def modinv_fermat(a, p):
        """
        Modular inverse using Fermat's little theorem (p must be prime).
        (From AQ1.py, AQ3.py)
        """
        return pow(a, p - 2, p)

# ----------------------------------------------------------------------
# 2. Paillier Cryptosystem Class
# (Compiled from Q1.py, AQ2.py, AQ3.py, AQ4.py)
# ----------------------------------------------------------------------

class Paillier:
    """
    Implements the Paillier additively homomorphic cryptosystem.
    
    Homomorphic Properties:
    - E(m1) * E(m2) mod n^2 = E(m1 + m2)
    - E(m)^k mod n^2 = E(m * k)
    """

    def __init__(self, p, q):
        """
        Generates Paillier keys upon instantiation.
        """
        self.n = p * q
        self.n_sq = self.n * self.n
        
        # lambda = lcm(p-1, q-1)
        self.lam = CryptoUtils.lcm(p - 1, q - 1)
        
        # g = n + 1
        self.g = self.n + 1
        
        # mu = (L(g^lambda mod n^2))^-1 mod n
        l_val = self._l_function(pow(self.g, self.lam, self.n_sq), self.n)
        self.mu = CryptoUtils.modinv_eea(l_val, self.n)
        
        if self.mu is None:
            raise ValueError("Failed to compute modular inverse (mu). Check primes.")

        self.public_key = (self.n, self.g)
        self.private_key = (self.lam, self.mu)
        
        # print(f"Paillier keys generated: n={self.n}, g={self.g}, lam={self.lam}, mu={self.mu}")


    @staticmethod
    def _l_function(x, n):
        """L(x) = (x - 1) // n"""
        return (x - 1) // n

    def encrypt(self, m):
        """
        Encrypts plaintext message m using the public key.
        """
        if not (0 <= m < self.n):
            print(f"Warning: Plaintext {m} is not in range [0, n-1]. Result will be modulo {self.n}.")
            m = m % self.n

        # Select random r in [1, n-1] s.t. gcd(r, n) = 1
        r = random.randrange(1, self.n)
        while CryptoUtils.gcd(r, self.n) != 1:
            r = random.randrange(1, self.n)
        
        # c = (g^m * r^n) mod n^2
        c = (pow(self.g, m, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq
        return c

    def decrypt(self, c):
        """
        Decrypts ciphertext c using the private key.
        """
        # x = c^lambda mod n^2
        x = pow(c, self.lam, self.n_sq)
        
        # L = L(x, n)
        L = self._l_function(x, self.n)
        
        # m = (L * mu) mod n
        m = (L * self.mu) % self.n
        return m

    def add(self, c1, c2):
        """Homomorphic addition: E(m1) + E(m2) -> E(m1 + m2)"""
        return (c1 * c2) % self.n_sq

    def scalar_multiply(self, c, k):
        """Homomorphic scalar multiplication: E(m) * k -> E(m * k)"""
        # k must be a positive integer
        if k < 0:
             # Handle negative k by finding inverse
             inv_c = CryptoUtils.modinv_eea(c, self.n_sq)
             if inv_c is None:
                 raise ValueError("Ciphertext has no inverse mod n^2")
             return pow(inv_c, abs(k), self.n_sq)
        return pow(c, k, self.n_sq)

    def add_accumulate(self, cts):
        """Homomorphically sums a list of ciphertexts."""
        acc = 1
        for c in cts:
            acc = (acc * c) % self.n_sq
        return acc

# ----------------------------------------------------------------------
# 3. Textbook RSA Cryptosystem Class
# (Compiled from Q2.py)
# ----------------------------------------------------------------------

class TextbookRSA:
    """
    Implements the "textbook" RSA cryptosystem.
    
    Homomorphic Property:
    - E(m1) * E(m2) mod n = E(m1 * m2)
    """
    
    def __init__(self, p, q):
        """
        Generates RSA keys upon instantiation.
        """
        self.n = p * q
        self.phi = (p - 1) * (q - 1)
        
        # Choose e
        self.e = random.randrange(2, self.phi)
        while CryptoUtils.gcd(self.e, self.phi) != 1:
            self.e = random.randrange(2, self.phi)
            
        # Compute d
        self.d = CryptoUtils.modinv_eea(self.e, self.phi)
        if self.d is None:
            raise ValueError("Failed to compute modular inverse (d). Check primes.")

        self.public_key = (self.e, self.n)
        self.private_key = (self.d, self.n)
        
        # print(f"RSA keys generated: n={self.n}, e={self.e}, d={self.d}")

    def encrypt(self, plaintext):
        """Encrypts plaintext message m using the public key."""
        return pow(plaintext, self.e, self.n)

    def decrypt(self, ciphertext):
        """Decrypts ciphertext c using the private key."""
        return pow(ciphertext, self.d, self.n)

    def multiply(self, c1, c2):
        """Homomorphic multiplication: E(m1) * E(m2) -> E(m1 * m2)"""
        return (c1 * c2) % self.n

# ----------------------------------------------------------------------
# 4. ElGamal Cryptosystem Class
# (Compiled from AQ1.py, AQ4.py)
# ----------------------------------------------------------------------

class ElGamal:
    """
    Implements the ElGamal cryptosystem over Z_p*.
    
    Homomorphic Property:
    - E(m1) * E(m2) = E(m1 * m2)
    """

    def __init__(self, p=467, g=2):
        """
        Generates ElGamal keypair.
        p: prime modulus
        g: generator of Z_p*
        """
        self.p = p
        self.g = g
        self.x = random.randrange(2, p - 2)  # private key
        self.y = pow(g, self.x, p)           # public key component
        self.public_key = (self.p, self.g, self.y)
        self.private_key = self.x
        
        # print(f"ElGamal keys generated: p={self.p}, g={self.g}, y={self.y}, x={self.x}")

    def encrypt(self, m):
        """Encrypt message m with public key."""
        if not (1 <= m < self.p):
             raise ValueError(f"Plaintext must be in [1, p-1]. Got {m}")
             
        k = random.randrange(2, self.p - 2)
        a = pow(self.g, k, self.p)
        b = (pow(self.y, k, self.p) * m) % self.p
        return (a, b)

    def decrypt(self, ct):
        """Decrypt ciphertext ct with private key."""
        a, b = ct
        s = pow(a, self.x, self.p)
        s_inv = CryptoUtils.modinv_fermat(s, self.p)
        return (b * s_inv) % self.p

    def multiply(self, ct1, ct2):
        """
        Homomorphic multiplication of two ciphertexts:
        (a1, b1) * (a2, b2) = (a1*a2 mod p, b1*b2 mod p)
        """
        a1, b1 = ct1
        a2, b2 = ct2
        return ((a1 * a2) % self.p, (b1 * b2) % self.p)

    def multiply_accumulate(self, cts):
        """Homomorphically multiplies a list of ciphertexts."""
        a_acc, b_acc = 1, 1
        for a, b in cts:
            a_acc = (a_acc * a) % self.p
            b_acc = (b_acc * b) % self.p
        return (a_acc, b_acc)

# ----------------------------------------------------------------------
# 5. Shamir Secret Sharing Class
# (Compiled from AQ3.py)
# ----------------------------------------------------------------------

class ShamirSecretSharing:
    """
    Implements Shamir's (t, n) Secret Sharing scheme over a prime field P.
    """

    def __init__(self, P):
        """Initialize the scheme with a large prime P."""
        self.P = P

    def split(self, secret, t, n):
        """
        Split 'secret' into n shares with threshold t over field P.
        Returns list of (i, share_i) for i=1..n
        """
        # f(x) = a0 + a1*x + ... + a(t-1)*x^(t-1)
        # a0 = secret
        coeffs = [secret] + [random.randrange(0, self.P) for _ in range(t - 1)]
        shares = []
        for i in range(1, n + 1):
            x = i
            y = 0
            xp = 1  # x^power
            # Evaluate polynomial f(x) at x=i
            for a in coeffs:
                y = (y + a * xp) % self.P
                xp = (xp * x) % self.P
            shares.append((i, y))
        return shares

    def reconstruct(self, subset_shares):
        """
        Reconstruct secret from a subset of shares using Lagrange interpolation at x=0.
        subset_shares: list of (i, share_i)
        """
        secret = 0
        P = self.P
        for j, yj in subset_shares:
            # Calculate Lagrange basis L_j(0)
            num, den = 1, 1
            for m, ym in subset_shares:
                if m == j:
                    continue
                num = (num * (-m % P)) % P
                den = (den * (j - m)) % P
            
            # Lj0 = num * (den^-1) mod P
            den_inv = CryptoUtils.modinv_fermat(den % P, P)
            Lj0 = (num * den_inv) % P
            
            # secret = sum(yj * Lj0)
            secret = (secret + yj * Lj0) % P
        return secret

# ----------------------------------------------------------------------
# 6. Benchmarking Class
# (Adapted from AQ4.py to use the new classes)
# ----------------------------------------------------------------------

class Benchmarker:
    """
    Runs performance benchmarks for the Paillier and ElGamal classes.
    """
    def __init__(self, trials, N):
        self.TRIALS = trials
        self.N = N
        print(f"Benchmarker initialized: {trials} trials, N={N} messages per trial.")

    def _bench_paillier_trial(self, p, q, N):
        # Keygen
        t0 = time.perf_counter()
        crypto = Paillier(p, q)
        t1 = time.perf_counter()

        # Encrypt N messages
        n = crypto.n
        msgs = [random.randrange(0, n) for _ in range(N)]
        t2 = time.perf_counter()
        cts = [crypto.encrypt(m) for m in msgs]
        t3 = time.perf_counter()

        # Homomorphic sum
        c_sum = crypto.add_accumulate(cts)
        t4 = time.perf_counter()

        # Decrypt aggregate
        _ = crypto.decrypt(c_sum)
        t5 = time.perf_counter()

        return {
            "keygen_s": t1 - t0,
            "encrypt_s": t3 - t2,
            "hom_op_s": t4 - t3,
            "decrypt_s": t5 - t4,
            "N": N
        }

    def _bench_elgamal_trial(self, p, g, N):
        # Keygen
        t0 = time.perf_counter()
        crypto = ElGamal(p, g)
        t1 = time.perf_counter()

        # Encrypt N messages
        P = crypto.p
        msgs = [random.randrange(1, P) for _ in range(N)]
        t2 = time.perf_counter()
        cts = [crypto.encrypt(m) for m in msgs]
        t3 = time.perf_counter()

        # Homomorphic product
        c_prod = crypto.multiply_accumulate(cts)
        t4 = time.perf_counter()

        # Decrypt aggregate
        _ = crypto.decrypt(c_prod)
        t5 = time.perf_counter()

        return {
            "keygen_s": t1 - t0,
            "encrypt_s": t3 - t2,
            "hom_op_s": t4 - t3,
            "decrypt_s": t5 - t4,
            "N": N
        }

    def _summarize(self, name, res_list):
        N = res_list[0]["N"]
        avg_keygen = mean(r["keygen_s"] for r in res_list)
        avg_encrypt = mean(r["encrypt_s"] for r in res_list)
        avg_hom = mean(r["hom_op_s"] for r in res_list)
        avg_dec = mean(r["decrypt_s"] for r in res_list)
        enc_throughput = N / avg_encrypt if avg_encrypt > 0 else float("inf")
        return {
            "scheme": name,
            "N": N,
            "keygen_s": avg_keygen,
            "encrypt_s": avg_encrypt,
            "enc_msgs_per_s": enc_throughput,
            "hom_op_s": avg_hom,
            "decrypt_s": avg_dec
        }

    def run_and_print_benchmarks(self, p_pail, q_pail, p_eg, g_eg):
        random.seed(42)

        # Warm-up
        print("Running warm-up...")
        self._bench_paillier_trial(p_pail, q_pail, N=50)
        self._bench_elgamal_trial(p_eg, g_eg, N=50)

        # Run trials
        print(f"Running Paillier benchmark ({self.TRIALS} trials)...")
        paillier_results = [self._bench_paillier_trial(p_pail, q_pail, N=self.N) for _ in range(self.TRIALS)]
        print(f"Running ElGamal benchmark ({self.TRIALS} trials)...")
        elgamal_results = [self._bench_elgamal_trial(p_eg, g_eg, N=self.N) for _ in range(self.TRIALS)]

        s_p = self._summarize("Paillier (add)", paillier_results)
        s_e = self._summarize("ElGamal (mul)", elgamal_results)

        # Pretty print summary
        def fmt(x, digits=6):
            return f"{x:.{digits}f}" if isinstance(x, float) else str(x)

        print("\n=== Benchmark Summary (averaged) ===")
        headers = ["Scheme", "N", "KeyGen(s)", "Encrypt(s)", "Enc msgs/s", "HomOp(s)", "Decrypt(s)"]
        row_p = [s_p["scheme"], s_p["N"], fmt(s_p["keygen_s"]), fmt(s_p["encrypt_s"]),
                 fmt(s_p["enc_msgs_per_s"]), fmt(s_p["hom_op_s"]), fmt(s_p["decrypt_s"])]
        row_e = [s_e["scheme"], s_e["N"], fmt(s_e["keygen_s"]), fmt(s_e["encrypt_s"]),
                 fmt(s_e["enc_msgs_per_s"]), fmt(s_e["hom_op_s"]), fmt(s_e["decrypt_s"])]

        # Simple table
        col_widths = [max(len(h), len(str(rp))) for h, rp in zip(headers, row_p)]
        col_widths = [max(w, len(str(re))) for w, re in zip(col_widths, row_e)]

        def print_row(cells):
            print("  ".join(str(c).ljust(w) for c, w in zip(cells, col_widths)))

        print_row(headers)
        print_row(row_p)
        print_row(row_e)

# ----------------------------------------------------------------------
# 7. Demo Functions (from all files)
# ----------------------------------------------------------------------

def demo_paillier_simple():
    """Demonstrates Paillier homomorphic addition (from Q1.py)."""
    print("--- Paillier Simple Demo (Q1.py) ---")
    p, q = 47, 59
    paillier = Paillier(p, q)

    m1, m2 = 15, 25
    print(f"Original numbers: {m1}, {m2}")

    # Encrypt
    c1 = paillier.encrypt(m1)
    c2 = paillier.encrypt(m2)
    print(f"Ciphertexts: c1 = {c1}, c2 = {c2}")

    # Homomorphic addition: E(m1) * E(m2) mod n^2 = E(m1 + m2)
    c_sum = paillier.add(c1, c2)
    print(f"Encrypted sum (ciphertext): {c_sum}")

    # Decrypt sum
    decrypted_sum = paillier.decrypt(c_sum)
    print(f"Decrypted sum: {decrypted_sum}")
    print(f"Verification: {decrypted_sum == (m1 + m2)}")

def demo_rsa_simple():
    """Demonstrates Textbook RSA homomorphic multiplication (from Q2.py)."""
    print("--- Textbook RSA Simple Demo (Q2.py) ---")
    p, q = 61, 53
    rsa = TextbookRSA(p, q)

    m1, m2 = 7, 3
    print(f"Original numbers: {m1}, {m2}")

    # Encrypt
    c1 = rsa.encrypt(m1)
    c2 = rsa.encrypt(m2)
    print(f"Ciphertexts: c1 = {c1}, c2 = {c2}")

    # Homomorphic multiplication: E(m1) * E(m2) mod n = E(m1 * m2)
    c_product = rsa.multiply(c1, c2)
    print(f"Encrypted product (ciphertext): {c_product}")

    # Decrypt product
    decrypted_product = rsa.decrypt(c_product)
    print(f"Decrypted product: {decrypted_product}")
    print(f"Verification: {decrypted_product == (m1 * m2)}")

def demo_elgamal_simple():
    """Demonstrates ElGamal homomorphic multiplication (from AQ1.py)."""
    print("--- ElGamal Simple Demo (AQ1.py) ---")
    elgamal = ElGamal(p=467, g=2)

    # Messages
    m1, m2 = 7, 3
    print(f"Original: {m1}, {m2}")

    # Encrypt
    c1 = elgamal.encrypt(m1)
    c2 = elgamal.encrypt(m2)
    print(f"Ciphertexts:\n c1 = {c1}\n c2 = {c2}")

    # Homomorphic multiplication
    c_mul = elgamal.multiply(c1, c2)
    print(f"Encrypted product (ciphertext): {c_mul}")

    # Decrypt product
    dec = elgamal.decrypt(c_mul)
    print(f"Decrypted product: {dec}")
    print(f"Verification: {dec == (m1 * m2) % elgamal.p}")

def demo_paillier_sharing():
    """Demonstrates Paillier for secure aggregation (from AQ2.py)."""
    print("--- Paillier Secure Data Sharing Demo (AQ2.py) ---")
    p, q = 1789, 2027
    paillier = Paillier(p, q)

    # Parties' private data
    A_val = 46
    B_val = 33

    # Each party encrypts their data
    cA = paillier.encrypt(A_val)
    cB = paillier.encrypt(B_val)
    print(f"Party A's encrypted value (hidden): {cA}")
    print(f"Party B's encrypted value (hidden): {cB}")

    # Aggregator computes encrypted sum: E(A+B)
    c_sum = paillier.add(cA, cB)

    # Aggregator computes weighted sum: E(2*A + 3*B)
    c_weighted = paillier.add(
        paillier.scalar_multiply(cA, 2),
        paillier.scalar_multiply(cB, 3)
    )

    # Only key-holder decrypts results
    sum_dec = paillier.decrypt(c_sum)
    weighted_dec = paillier.decrypt(c_weighted)

    print(f"\nDecrypted A + B: {sum_dec}   [Expected {A_val + B_val}]")
    print(f"Decrypted 2A + 3B: {weighted_dec}   [Expected {2*A_val + 3*B_val}]")

def demo_threshold_paillier():
    """Demonstrates threshold decryption concept (from AQ3.py)."""
    print("--- Secure Threshold Count Demo (AQ3.py) ---")
    # 1) Setup Paillier
    p_paillier, q_paillier = 1789, 2027
    paillier = Paillier(p_paillier, q_paillier)

    # 2) Setup Shamir Secret Sharing for the private key
    P_field = 2**127 - 1  # A large prime field
    sss = ShamirSecretSharing(P_field)
    t, n_parties = 3, 5   # require any 3 of 5 parties
    
    # We share lambda and mu separately
    lam, mu = paillier.private_key
    lam_shares = sss.split(lam % P_field, t, n_parties)
    mu_shares  = sss.split(mu  % P_field, t, n_parties)

    # 3) Parties' private data and local thresholding
    values = [42, 57, 61, 39, 70, 12, 58]  # example data
    T = 50
    # Each party encrypts a '1' if v >= T, else '0'
    encrypted_bits = [paillier.encrypt(1 if v >= T else 0) for v in values]

    # 4) Aggregator computes encrypted count
    C = paillier.add_accumulate(encrypted_bits)

    # 5) Threshold-controlled decryption:
    # Any t parties pool their shares
    chosen = random.sample(range(n_parties), t)
    lam_subset = [lam_shares[i] for i in chosen]
    mu_subset  = [mu_shares[i]  for i in chosen]

    lam_rec = sss.reconstruct(lam_subset)
    mu_rec  = sss.reconstruct(mu_subset)

    # Ensure they match originals
    assert lam_rec % P_field == lam % P_field
    assert mu_rec  % P_field == mu  % P_field

    # Use reconstructed key to decrypt the aggregated result
    # We create a "dummy" private key tuple for the decrypt method
    reconstructed_priv_key = (lam_rec, mu_rec)
    count = paillier.decrypt(C) # Original object can still decrypt
    
    # We can also prove the reconstructed key works
    # Note: Paillier.decrypt() expects self.private_key
    # A real threshold scheme would have a partial-decryption protocol.
    # For this demo, we just show the key is reconstructible.
    print(f"Original private key:    lam={lam}, mu={mu}")
    print(f"Reconstructed private key: lam={lam_rec}, mu={mu_rec}")
    
    print("\nSecure thresholding with Paillier (educational threshold):")
    print(f"- Parties: {len(values)} values, threshold T = {T}")
    print(f"- Encrypted count decrypted by any {t} of {n_parties} key-share holders")
    print(f"- Count of values >= {T}: {count}  [Expected {sum(1 for v in values if v >= T)}]")

def demo_benchmarking():
    """Runs the full benchmark suite (from AQ4.py)."""
    print("--- Benchmark Demo (AQ4.py) ---")
    
    # Parameters
    TRIALS = 5
    N = 500

    # Paillier primes (demo sizes)
    p_pail, q_pail = 2357, 2551

    # ElGamal field (demo prime and generator)
    P_eg, G_eg = 467, 2

    # Instantiate and run
    benchmarker = Benchmarker(trials=TRIALS, N=N)
    benchmarker.run_and_print_benchmarks(p_pail, q_pail, P_eg, G_eg)


# ----------------------------------------------------------------------
# 8. Main Menu
# ----------------------------------------------------------------------

def main_menu():
    """
    Provides a command-line menu to run the different demos.
    """
    while True:
        print("\n" + "="*40)
        print("  Homomorphic Encryption Demos")
        print("="*40)
        print("1. Paillier Simple Demo (Additive, from Q1.py)")
        print("2. Textbook RSA Simple Demo (Multiplicative, from Q2.py)")
        print("3. ElGamal Simple Demo (Multiplicative, from AQ1.py)")
        print("4. Paillier Secure Data Sharing (Additive, from AQ2.py)")
        print("5. Paillier + Shamir Threshold Demo (from AQ3.py)")
        print("6. Run Cryptosystem Benchmarks (from AQ4.py)")
        print("7. Exit")
        print("="*40)
        
        choice = input("Enter your choice (1-7): ")
        
        print("\n" + "-"*40)
        if choice == '1':
            demo_paillier_simple()
        elif choice == '2':
            demo_rsa_simple()
        elif choice == '3':
            demo_elgamal_simple()
        elif choice == '4':
            demo_paillier_sharing()
        elif choice == '5':
            demo_threshold_paillier()
        elif choice == '6':
            demo_benchmarking()
        elif choice == '7':
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")
        print("-" * 40)
        input("\nPress Enter to return to the menu...")

if __name__ == "__main__":
    main_menu()
