from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime
import numpy as np
import json
import base64


class KeyManager:
    def __init__(self):
        self.dh_p = getPrime(512)
        self.dh_g = 2
        self.keys = {}
        self.revoked = set()

    def generate_keys(self, subsystem_id):
        rsa_key = RSA.generate(2048)
        dh_private = np.random.randint(2, 1 << 16)
        dh_public = pow(self.dh_g, dh_private, self.dh_p)
        self.keys[subsystem_id] = {
            'rsa': rsa_key,
            'dh_private': dh_private,
            'dh_public': dh_public
        }

        # Print the generated keys
        print(f"\n=== Keys for {subsystem_id} ===")
        print("RSA Public Key:")
        print(rsa_key.publickey().export_key().decode())
        print("RSA Private Key:")
        print(rsa_key.export_key().decode())
        print(f"DH Private: {dh_private}")
        print(f"DH Public:  {dh_public}")
        print(f"Shared DH p: {self.dh_p}")
        print(f"Shared DH g: {self.dh_g}")
        print("=" * 50)

    def get_public_keys(self, subsystem_id):
        if subsystem_id in self.revoked:
            raise Exception("Key revoked")
        key = self.keys[subsystem_id]
        return {
            'rsa_public': key['rsa'].publickey().export_key(),
            'dh_public': key['dh_public'],
            'dh_p': self.dh_p,
            'dh_g': self.dh_g
        }

    def revoke_key(self, subsystem_id):
        self.revoked.add(subsystem_id)


class SecureChannel:
    def __init__(self, sender_id, receiver_id, key_manager):
        self.sender = sender_id
        self.receiver = receiver_id
        self.km = key_manager
        self.shared_key = self._derive_shared_key()

    def _derive_shared_key(self):
        sk = self.km.keys[self.sender]
        pk = self.km.get_public_keys(self.receiver)
        # Both sides now use the same dh_p/g
        shared = pow(pk['dh_public'], sk['dh_private'], pk['dh_p'])
        secret = shared.to_bytes((shared.bit_length() + 7) // 8, 'big')
        return HKDF(secret, 32, None, SHA256)

    def encrypt_message(self, message):
        cipher = AES.new(self.shared_key, AES.MODE_GCM)
        ct, tag = cipher.encrypt_and_digest(message.encode())
        packet = {
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'ciphertext': base64.b64encode(ct).decode(),
            'tag': base64.b64encode(tag).decode()
        }
        return json.dumps(packet).encode()

    def decrypt_message(self, packet_bytes):
        pkt = json.loads(packet_bytes.decode())
        nonce = base64.b64decode(pkt['nonce'])
        ct = base64.b64decode(pkt['ciphertext'])
        tag = base64.b64decode(pkt['tag'])

        cipher = AES.new(self.shared_key, AES.MODE_GCM, nonce=nonce)
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt.decode()


if __name__ == "__main__":
    km = KeyManager()
    for sys in ['SystemA', 'SystemB', 'SystemC']:
        km.generate_keys(sys)

    # A → B
    channel_ab = SecureChannel('SystemA', 'SystemB', km)
    encrypted = channel_ab.encrypt_message("Confidential Financial Report")
    print("\nEncrypted:", encrypted)

    # B → A (uses same dh_p/g, so shared_key matches)
    channel_ba = SecureChannel('SystemB', 'SystemA', km)
    decrypted = channel_ba.decrypt_message(encrypted)
    print("Decrypted:", decrypted)

    # Show public keys via getter
    print("\nPublic keys for SystemB:")
    print(km.get_public_keys('SystemB'))

    km.revoke_key('SystemC')
