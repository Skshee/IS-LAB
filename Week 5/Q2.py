from Crypto.Util.number import getPrime

KEYS = {}

def _blum_prime(bits):
    p = getPrime(bits)
    return p if p % 4 == 3 else _blum_prime(bits)

# Rabin keypair generator
def generate_keypair(bits=512):
    p = _blum_prime(bits // 2)
    q = _blum_prime(bits // 2)
    n = p * q
    return p, q, n

def generate(facility, bits=512):
    p, q, n = generate_keypair(bits)
    KEYS[facility] = {'p': p, 'q': q, 'n': n, 'revoked': False}
    print(f"[+] Generated for {facility}: n={n}")
    return n

def retrieve(facility):
    rec = KEYS.get(facility)
    if not rec:
        raise KeyError(f"No keys for {facility}")
    if rec['revoked']:
        raise KeyError(f"Keys for {facility} are revoked")
    print(f"[+] Retrieved for {facility}")
    return rec['n'], rec['p'], rec['q']

def revoke(facility):
    if facility in KEYS:
        KEYS[facility]['revoked'] = True
        print(f"[-] Revoked {facility}")

def renew_all(bits=512):
    for facility, rec in list(KEYS.items()):
        if not rec['revoked']:
            generate(facility, bits)
    print("[*] All non-revoked keys renewed")

# Demo sequence
if __name__ == "__main__":
    # Generate
    generate("Hospital_A")
    generate("Clinic_B")

    # Retrieve
    n, p, q = retrieve("Hospital_A")
    print(f"    → n={n}\n    → p={p}\n    → q={q}\n")

    # Revoke
    revoke("Clinic_B")
    try:
        retrieve("Clinic_B")
    except KeyError as e:
        print(f"    → Error: {e}\n")

    #Renew
    renew_all()

    # final state
    print("\nFinal KEYS store:")
    for f, rec in KEYS.items():
        print(f" {f}: revoked={rec['revoked']}  n={rec['n']}")