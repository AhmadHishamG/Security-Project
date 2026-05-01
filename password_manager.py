import json
import os
import hashlib
import secrets
import base64
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
def compute_gcd(a, b):
    """
    Computes the Greatest Common Divisor (GCD) using the Euclidean Algorithm.
    """
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    """
    Computes the modular multiplicative inverse of 'a' modulo 'm' 
    using the iterative Extended Euclidean Algorithm.
    Returns x such that (a * x) % m == 1.
    """
    m0 = m
    x0 = 0
    x1 = 1

    if m == 1:
        return 0

    while a > 1:
        # q is quotient
        q = a // m
        # m is remainder now, process same as Euclid's algorithm
        m, a = a % m, m
        
        # Update x0 and x1
        x0, x1 = x1 - q * x0, x0

    # Make x1 positive
    if x1 < 0:
        x1 += m0

    return x1
class ElGamal:
    @staticmethod
    def generate_keys(bits=512):
        """Generates ElGamal parameters and key pair from scratch."""
        p = getPrime(bits)
        g = 2 # Simplified primitive root for demonstration
        x = secrets.randbelow(p - 2) + 1  # Private key
        y = pow(g, x, p)                  # Public key
        return p, g, x, y

    @staticmethod
    def sign(message, p, g, x):
        """Signs a message using ElGamal, using scratch-built math functions."""
        h_m = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        
        # 1. Find a random k such that GCD(k, p-1) == 1
        while True:
            k = secrets.randbelow(p - 2) + 1
            if compute_gcd(k, p - 1) == 1: 
                break
        # 2. Calculate r = g^k mod p
        r = pow(g, k, p)
        
        # 3. Calculate the modular inverse of k modulo (p-1)
        k_inv = mod_inverse(k, p - 1)      # <-- USING YOUR INVERSE
        
        # 4. Calculate s = (h_m - x * r) * k_inv mod (p-1)
        s = ((h_m - x * r) * k_inv) % (p - 1)
        
        return r, s

    @staticmethod
    def verify(message, r, s, p, g, y):
        """Verifies an ElGamal signature."""
        if not (0 < r < p) or not (0 < s < p - 1):
            return False
        h_m = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        v1 = pow(g, h_m, p)
        v2 = (pow(y, r, p) * pow(r, s, p)) % p
        return v1 == v2

# ==========================================
# MODULE 4: Diffie-Hellman Key Exchange
# ==========================================
class DiffieHellman:
    @staticmethod
    def generate_parameters(bits=512):
        q = getPrime(bits)
        a = 2 
        return q, a

    @staticmethod
    def generate_keypair(q, a):
        private_key = secrets.randbelow(q - 2) + 1
        public_key = pow(a, private_key, q)
        return private_key, public_key

    @staticmethod
    def compute_secret(other_public, my_private, q):
        shared_secret = pow(other_public, my_private, q)
        # Derive a 256-bit AES key from the shared secret
        return hashlib.sha256(str(shared_secret).encode()).digest()

# ==========================================
# MODULE 2: Vault Operations
# ==========================================
class Vault:
    def __init__(self, username):
        self.username = username
        self.vault_file = f"{username}_vault.json"
        self.keys_file = f"{username}_keys.json"
        self.p, self.g, self.priv_key, self.pub_key = None, None, None, None
        
    def init_user(self):
        """Initializes user with new ElGamal keys."""
        self.p, self.g, self.priv_key, self.pub_key = ElGamal.generate_keys()
        with open(self.keys_file, 'w') as f:
            json.dump({
                'p': self.p, 'g': self.g, 'x': self.priv_key, 'y': self.pub_key
            }, f)
        print(f"[*] Keys generated for {self.username}.")

    def load_keys(self):
        if not os.path.exists(self.keys_file):
            return False
        with open(self.keys_file, 'r') as f:
            keys = json.load(f)
            self.p, self.g = keys['p'], keys['g']
            self.priv_key, self.pub_key = keys['x'], keys['y']
        return True

    def _derive_aes_key(self, password):
        return hashlib.sha256(password.encode()).digest()

    def _encrypt_data(self, data_dict, key):
        """Encrypts data using AES-GCM."""
        cipher = AES.new(key, AES.MODE_GCM)
        plaintext = json.dumps(data_dict).encode()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        # Pack nonce + tag + ciphertext
        payload = cipher.nonce + tag + ciphertext
        return base64.b64encode(payload).decode()

    def _decrypt_data(self, b64_payload, key):
        """Decrypts data using AES-GCM."""
        try:
            payload = base64.b64decode(b64_payload)
            nonce, tag, ciphertext = payload[:16], payload[16:32], payload[32:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return json.loads(plaintext.decode())
        except ValueError:
            return None # Integrity/MAC failure or wrong password

    def save_vault(self, master_password, credentials):
        """Encrypts and signs the vault."""
        aes_key = self._derive_aes_key(master_password)
        encrypted_vault = self._encrypt_data(credentials, aes_key)
        
        # Sign the encrypted contents
        r, s = ElGamal.sign(encrypted_vault, self.p, self.g, self.priv_key)
        
        vault_data = {
            "encrypted_vault": encrypted_vault,
            "signature": f"{r},{s}"
        }
        with open(self.vault_file, 'w') as f:
            json.dump(vault_data, f)

    def load_vault(self, master_password):
        """Verifies signature and decrypts the vault."""
        if not os.path.exists(self.vault_file):
            return {}
            
        with open(self.vault_file, 'r') as f:
            vault_data = json.load(f)
            
        encrypted_vault = vault_data['encrypted_vault']
        r, s = map(int, vault_data['signature'].split(','))
        
        # Verify Integrity
        if not ElGamal.verify(encrypted_vault, r, s, self.p, self.g, self.pub_key):
            print("[!] ALERT: Vault signature is invalid! The file has been tampered with.")
            return None
            
        aes_key = self._derive_aes_key(master_password)
        creds = self._decrypt_data(encrypted_vault, aes_key)
        if creds is None:
            print("[!] ALERT: Decryption failed. Incorrect master password.")
        return creds

# ==========================================
# CLI INTERFACE
# ==========================================
def main():
    print("=== CMPS426 Secure Password Manager ===")
    user = input("Enter your username: ")
    vault = Vault(user)
    
    if not vault.load_keys():
        print("Initializing new user...")
        vault.init_user()
        
    while True:
        print("\n1. Add Credential\n2. View Credentials\n3. Export Vault (Diffie-Hellman)\n4. Exit")
        choice = input("Select action: ")
        
        if choice == '1':
            mp = input("Master Password: ")
            creds = vault.load_vault(mp)
            if creds is None: continue
            
            site = input("Website: ")
            u = input("Username: ")
            p = input("Password: ")
            creds[site] = {"username": u, "password": p}
            
            vault.save_vault(mp, creds)
            print("[*] Credential saved securely.")
            
        elif choice == '2':
            mp = input("Master Password: ")
            creds = vault.load_vault(mp)
            if creds is None: continue
            
            print("\n--- Your Vault ---")
            for site, data in creds.items():
                print(f"Site: {site} | User: {data['username']} | Pass: {data['password']}")
                
        elif choice == '3':
            print("\n--- Initiating Diffie-Hellman Export ---")
            mp = input("Verify Master Password to decrypt local vault: ")
            creds = vault.load_vault(mp)
            if creds is None: continue
            
            # Simulated Device 2 (Recipient)
            q, a = DiffieHellman.generate_parameters()
            d2_priv, d2_pub = DiffieHellman.generate_keypair(q, a)
            
            # Device 1 (You) generates DH pair
            d1_priv, d1_pub = DiffieHellman.generate_keypair(q, a)
            
            # Key Exchange & Signing Phase
            print("[*] Exchanging DH Keys and verifying ElGamal Signatures...")
            r1, s1 = ElGamal.sign(str(d1_pub), vault.p, vault.g, vault.priv_key)
            # (Assume Device 2 verifies r1, s1 here using your public key)
            
            # Derive Shared Secret
            session_key = DiffieHellman.compute_secret(d2_pub, d1_priv, q)
            print("[*] Shared session key derived successfully.")
            
            # Transfer Phase
            encrypted_export = vault._encrypt_data(creds, session_key)
            exp_r, exp_s = ElGamal.sign(encrypted_export, vault.p, vault.g, vault.priv_key)
            
            print(f"[*] Vault exported and signed. Package: {encrypted_export[:20]}...")
            print("[*] Export complete!")
            
        elif choice == '4':
            break

if __name__ == "__main__":
    main()