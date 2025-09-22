"""
Diffie-Hellman key exchange demo with timing measurements.

 - Uses RFC 3526 2048-bit MODP Group (Group 14) prime and g = 2.
 - Measures time taken to generate keys (private -> public) and to compute shared secret.
 - Derives a symmetric key from the shared secret via SHA-256.
"""

import secrets
import time
import hashlib

# 2048-bit MODP Group prime from RFC 3526 (group 14) as a hex string (trimmed for readability)
RFC3526_2048_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF"
)
# convert to int
P = int(RFC3526_2048_HEX, 16)
G = 2  # generator

def generate_private_key(bits: int = 256) -> int:
    """
    Generate a cryptographically strong random private exponent.
    bits: size of the private exponent in bits. 256-384 bits is commonly used.
    """
    # ensure top bit set so we have full bit length and make it odd (not required, but fine)
    priv = secrets.randbits(bits) | (1 << (bits - 1)) | 1
    return priv

def public_from_private(private: int, p: int = P, g: int = G) -> int:
    """
    Compute public key g^private mod p
    """
    return pow(g, private, p)

def compute_shared_secret(their_public: int, my_private: int, p: int = P) -> int:
    """
    Compute the shared secret (their_public^my_private mod p)
    """
    return pow(their_public, my_private, p)

def derive_key(shared_secret_int: int, p: int = P) -> bytes:
    """
    Derive a fixed-length symmetric key from the shared secret integer.
    We'll convert the shared secret to bytes and hash it with SHA-256.
    """
    # Convert integer to big-endian bytes with minimal length to represent p
    size_bytes = (p.bit_length() + 7) // 8
    shared_bytes = shared_secret_int.to_bytes(size_bytes, byteorder='big')
    # Derive key
    return hashlib.sha256(shared_bytes).digest()

def timed_key_generation(bits: int = 256, p: int = P, g: int = G):
    """
    Generate private and public key, returning (private, public, time_taken_seconds)
    """
    t0 = time.perf_counter()
    priv = generate_private_key(bits)
    pub = public_from_private(priv, p, g)
    t1 = time.perf_counter()
    return priv, pub, (t1 - t0)

def timed_shared_computation(their_public: int, my_private: int, p: int = P):
    """
    Compute shared secret and return (shared_secret_int, time_taken_seconds)
    """
    t0 = time.perf_counter()
    shared = compute_shared_secret(their_public, my_private, p)
    t1 = time.perf_counter()
    return shared, (t1 - t0)

def demo_once(bits: int = 256):
    """
    Demo: two peers (Alice and Bob) perform DH exchange once, with timing.
    """
    # Alice key generation
    a_priv, a_pub, a_gen_time = timed_key_generation(bits)
    # Bob key generation
    b_priv, b_pub, b_gen_time = timed_key_generation(bits)

    # Exchange (compute shared)
    a_shared, a_shared_time = timed_shared_computation(b_pub, a_priv)
    b_shared, b_shared_time = timed_shared_computation(a_pub, b_priv)

    # Derive symmetric keys
    a_key = derive_key(a_shared)
    b_key = derive_key(b_shared)

    # Validate
    success = (a_shared == b_shared) and (a_key == b_key)

    result = {
        "a": {"private_bits": bits, "public": a_pub, "private": a_priv, "gen_time_s": a_gen_time, "shared_time_s": a_shared_time},
        "b": {"private_bits": bits, "public": b_pub, "private": b_priv, "gen_time_s": b_gen_time, "shared_time_s": b_shared_time},
        "shared_secret_int": a_shared,
        "symmetric_key_hex": a_key.hex(),
        "match": success
    }
    return result

def benchmark(iterations: int = 50, bits: int = 256):
    """
    Run multiple DH exchanges and report average times for:
      - key generation (per-peer)
      - shared computation (per-peer)
    Note: We do not regenerate P/G; only private keys are regenerated each run.
    """
    import statistics
    gen_times = []     # store per-peer generation times (we'll average across both peers)
    shared_times = []

    for _ in range(iterations):
        # Alice
        a_priv, a_pub, a_gen_time = timed_key_generation(bits)
        # Bob
        b_priv, b_pub, b_gen_time = timed_key_generation(bits)

        gen_times.extend([a_gen_time, b_gen_time])

        # shared
        _, a_shared_time = timed_shared_computation(b_pub, a_priv)
        _, b_shared_time = timed_shared_computation(a_pub, b_priv)
        shared_times.extend([a_shared_time, b_shared_time])

    return {
        "iterations": iterations,
        "avg_key_generation_s": statistics.mean(gen_times),
        "median_key_generation_s": statistics.median(gen_times),
        "avg_shared_compute_s": statistics.mean(shared_times),
        "median_shared_compute_s": statistics.median(shared_times),
    }

if __name__ == "__main__":
    # Single demo run
    demo = demo_once(bits=384)  # 384-bit private exponents give good security when p is 2048-bit
    print("=== Single DH Demo ===")
    print(f"Alice public (hex, first 80 chars): {hex(demo['a']['public'])[:80]}...")
    print(f"Bob   public (hex, first 80 chars): {hex(demo['b']['public'])[:80]}...")
    print(f"Alice key generation time: {demo['a']['gen_time_s']*1000:.3f} ms")
    print(f"Bob   key generation time: {demo['b']['gen_time_s']*1000:.3f} ms")
    print(f"Alice shared compute time: {demo['a']['shared_time_s']*1000:.3f} ms")
    print(f"Bob   shared compute time: {demo['b']['shared_time_s']*1000:.3f} ms")
    print(f"Derived symmetric key (SHA-256) hex: {demo['symmetric_key_hex']}")
    print(f"Shared secret match? {'YES' if demo['match'] else 'NO'}")

    # Benchmark many runs
    print("\n=== Benchmark (100 iterations) ===")
    bench = benchmark(iterations=100, bits=384)
    print(f"Iterations: {bench['iterations']}")
    print(f"Average key generation (per peer): {bench['avg_key_generation_s']*1000:.3f} ms")
    print(f"Median  key generation (per peer): {bench['median_key_generation_s']*1000:.3f} ms")
    print(f"Average shared computation (per peer): {bench['avg_shared_compute_s']*1000:.3f} ms")
    print(f"Median  shared computation (per peer): {bench['median_shared_compute_s']*1000:.3f} ms")
