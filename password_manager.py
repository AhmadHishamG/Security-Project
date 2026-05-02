import base64
import hashlib
import json
import os

from Crypto.Cipher import AES

from module3and4 import DiffieHellman, ElGamal


def canonical_json(data):
    """Stable JSON string used whenever structured data must be signed."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def format_signature(signature):
    r, s = signature
    return f"{r},{s}"


def parse_signature(signature_text):
    r, s = signature_text.split(",", 1)
    return int(r), int(s)


# ==========================================
# MODULE 2: Vault Operations
# ==========================================
class Vault:
    def __init__(self, username):
        self.username = username
        self.vault_file = f"{username}_vault.json"
        self.keys_file = f"{username}_keys.json"
        self.public_key_file = f"{username}_public_key.json"
        self.p = None
        self.g = None
        self.priv_key = None
        self.pub_key = None

    def init_user(self, key_password):
        """Initializes a user with protected ElGamal keys."""
        self.p, self.g, self.priv_key, self.pub_key = ElGamal.generate_keys()
        self._save_key_files(key_password)
        print(f"[*] Keys generated for {self.username}.")
        print(f"[*] Public key exported to {self.public_key_file}.")

    def _save_key_files(self, key_password):
        encrypted_private = self._encrypt_data(
            {"x": self.priv_key}, self._derive_aes_key(key_password)
        )
        with open(self.keys_file, "w") as f:
            json.dump(
                {
                    "username": self.username,
                    "p": self.p,
                    "g": self.g,
                    "y": self.pub_key,
                    "encrypted_private_key": encrypted_private,
                },
                f,
                indent=2,
            )
        self.export_public_key()

    def export_public_key(self):
        with open(self.public_key_file, "w") as f:
            json.dump(self.public_key_data(), f, indent=2)

    def public_key_data(self):
        return {
            "username": self.username,
            "p": self.p,
            "g": self.g,
            "y": self.pub_key,
        }

    @staticmethod
    def load_public_key_file(public_key_file):
        with open(public_key_file, "r") as f:
            return json.load(f)

    def load_keys(self, key_password=None):
        if not os.path.exists(self.keys_file):
            return False

        with open(self.keys_file, "r") as f:
            keys = json.load(f)

        self.p = keys["p"]
        self.g = keys["g"]
        self.pub_key = keys["y"]

        if "encrypted_private_key" in keys:
            if key_password is None:
                print("[!] A key protection password is required.")
                return False

            private_data = self._decrypt_data(
                keys["encrypted_private_key"], self._derive_aes_key(key_password)
            )
            if private_data is None:
                print("[!] Incorrect key protection password.")
                return False
            self.priv_key = private_data["x"]
        else:
            # Backward compatibility for old plaintext key files.
            self.priv_key = keys["x"]
            print("[!] Loaded an old plaintext private key file.")

        self.export_public_key()
        return True

    def _derive_aes_key(self, password):
        return hashlib.sha256(password.encode()).digest()

    def _encrypt_data(self, data_dict, key):
        """Encrypts JSON-serializable data using AES-GCM."""
        cipher = AES.new(key, AES.MODE_GCM)
        plaintext = json.dumps(data_dict).encode()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        payload = cipher.nonce + tag + ciphertext
        return base64.b64encode(payload).decode()

    def _decrypt_data(self, b64_payload, key):
        """Decrypts AES-GCM data and verifies its authentication tag."""
        try:
            payload = base64.b64decode(b64_payload)
            nonce, tag, ciphertext = payload[:16], payload[16:32], payload[32:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return json.loads(plaintext.decode())
        except Exception:
            return None

    def save_vault(self, master_password, credentials):
        """Encrypts and signs the vault."""
        aes_key = self._derive_aes_key(master_password)
        encrypted_vault = self._encrypt_data(credentials, aes_key)
        signature = ElGamal.sign(encrypted_vault, self.p, self.g, self.priv_key)

        vault_data = {
            "owner": self.username,
            "encrypted_vault": encrypted_vault,
            "signature": format_signature(signature),
        }
        with open(self.vault_file, "w") as f:
            json.dump(vault_data, f, indent=2)

    def load_vault(self, master_password):
        """Verifies the signature, then decrypts the vault."""
        if not os.path.exists(self.vault_file):
            return {}

        with open(self.vault_file, "r") as f:
            vault_data = json.load(f)

        encrypted_vault = vault_data["encrypted_vault"]
        r, s = parse_signature(vault_data["signature"])

        if not ElGamal.verify(encrypted_vault, r, s, self.p, self.g, self.pub_key):
            print("[!] ALERT: Vault signature is invalid. Refusing to open.")
            return None

        creds = self._decrypt_data(encrypted_vault, self._derive_aes_key(master_password))
        if creds is None:
            print("[!] ALERT: Decryption failed. Incorrect master password.")
        return creds


def unlock_or_create_user(username):
    vault = Vault(username)
    if not os.path.exists(vault.keys_file):
        print("Initializing new user...")
        key_password = input("Create key protection password: ")
        vault.init_user(key_password)
        return vault

    for _ in range(3):
        key_password = input("Key protection password: ")
        if vault.load_keys(key_password):
            return vault

    print("[!] Could not unlock private key.")
    return None


def choose_existing_site(credentials):
    if not credentials:
        print("[!] Vault is empty.")
        return None

    print("\n--- Stored Sites ---")
    sites = list(credentials.keys())
    for index, site in enumerate(sites, start=1):
        print(f"{index}. {site}")

    choice = input("Choose site number: ")
    if not choice.isdigit():
        print("[!] Invalid selection.")
        return None

    index = int(choice) - 1
    if index < 0 or index >= len(sites):
        print("[!] Invalid selection.")
        return None

    return sites[index]


def add_credential(vault):
    master_password = input("Master Password: ")
    credentials = vault.load_vault(master_password)
    if credentials is None:
        return

    site = input("Website: ")
    username = input("Username: ")
    password = input("Password: ")
    credentials[site] = {"username": username, "password": password}
    vault.save_vault(master_password, credentials)
    print("[*] Credential saved securely.")


def retrieve_credential(vault):
    master_password = input("Master Password: ")
    credentials = vault.load_vault(master_password)
    if credentials is None:
        return

    site = choose_existing_site(credentials)
    if site is None:
        return

    data = credentials[site]
    print("\n--- Credential ---")
    print(f"Site: {site}")
    print(f"Username: {data['username']}")
    print(f"Password: {data['password']}")


def update_credential(vault):
    master_password = input("Master Password: ")
    credentials = vault.load_vault(master_password)
    if credentials is None:
        return

    site = choose_existing_site(credentials)
    if site is None:
        return

    old_data = credentials[site]
    new_username = input(f"New username [{old_data['username']}]: ")
    new_password = input("New password [leave blank to keep current]: ")
    credentials[site] = {
        "username": new_username or old_data["username"],
        "password": new_password or old_data["password"],
    }
    vault.save_vault(master_password, credentials)
    print("[*] Credential updated and vault re-signed.")


def delete_credential(vault):
    master_password = input("Master Password: ")
    credentials = vault.load_vault(master_password)
    if credentials is None:
        return

    site = choose_existing_site(credentials)
    if site is None:
        return

    confirm = input(f"Delete {site}? Type YES to confirm: ")
    if confirm != "YES":
        print("[*] Delete cancelled.")
        return

    del credentials[site]
    vault.save_vault(master_password, credentials)
    print("[*] Credential deleted and vault re-signed.")


def sign_dh_public_key(vault, q, alpha, public_key):
    message = canonical_json({"q": q, "alpha": alpha, "public_key": public_key})
    return message, ElGamal.sign(message, vault.p, vault.g, vault.priv_key)


def verify_with_public_key(message, signature, public_key_data):
    r, s = signature
    return ElGamal.verify(
        message,
        r,
        s,
        public_key_data["p"],
        public_key_data["g"],
        public_key_data["y"],
    )


def export_vault_with_diffie_hellman(sender_vault):
    print("\n--- Secure Vault Export via Diffie-Hellman ---")
    sender_master_password = input("Sender master password: ")
    credentials = sender_vault.load_vault(sender_master_password)
    if credentials is None:
        return

    recipient_name = input("Recipient username/device name: ")
    if recipient_name == sender_vault.username:
        print("[!] Recipient must be different from sender.")
        return

    recipient_vault = unlock_or_create_user(recipient_name)
    if recipient_vault is None:
        return

    recipient_master_password = input("Recipient master password for imported vault: ")

    print("[*] Generating ephemeral Diffie-Hellman keys...")
    q, alpha = DiffieHellman.generate_parameters()
    sender_dh_private, sender_dh_public = DiffieHellman.generate_keypair(q, alpha)
    recipient_dh_private, recipient_dh_public = DiffieHellman.generate_keypair(q, alpha)

    print("[*] Signing and verifying DH public keys...")
    sender_message, sender_dh_signature = sign_dh_public_key(
        sender_vault, q, alpha, sender_dh_public
    )
    if not verify_with_public_key(
        sender_message, sender_dh_signature, sender_vault.public_key_data()
    ):
        print("[!] Recipient rejected sender DH key signature. Export aborted.")
        return

    recipient_message, recipient_dh_signature = sign_dh_public_key(
        recipient_vault, q, alpha, recipient_dh_public
    )
    if not verify_with_public_key(
        recipient_message, recipient_dh_signature, recipient_vault.public_key_data()
    ):
        print("[!] Sender rejected recipient DH key signature. Export aborted.")
        return

    sender_session_key = DiffieHellman.compute_secret(
        recipient_dh_public, sender_dh_private, q
    )
    recipient_session_key = DiffieHellman.compute_secret(
        sender_dh_public, recipient_dh_private, q
    )

    if sender_session_key != recipient_session_key:
        print("[!] Shared secret mismatch. Export aborted.")
        return

    encrypted_export = sender_vault._encrypt_data(credentials, sender_session_key)
    export_signature = ElGamal.sign(
        encrypted_export, sender_vault.p, sender_vault.g, sender_vault.priv_key
    )

    package = {
        "sender": sender_vault.username,
        "recipient": recipient_vault.username,
        "dh_parameters": {"q": q, "alpha": alpha},
        "sender_dh_public": sender_dh_public,
        "sender_dh_signature": format_signature(sender_dh_signature),
        "recipient_dh_public": recipient_dh_public,
        "recipient_dh_signature": format_signature(recipient_dh_signature),
        "encrypted_vault": encrypted_export,
        "export_signature": format_signature(export_signature),
    }
    package_file = f"{sender_vault.username}_to_{recipient_vault.username}_export_package.json"
    with open(package_file, "w") as f:
        json.dump(package, f, indent=2)

    print("[*] Transfer package written and signed.")
    if not verify_with_public_key(
        encrypted_export, export_signature, sender_vault.public_key_data()
    ):
        print("[!] Recipient rejected transfer package signature. Import aborted.")
        return

    imported_credentials = recipient_vault._decrypt_data(
        encrypted_export, recipient_session_key
    )
    if imported_credentials is None:
        print("[!] Recipient could not decrypt transfer package.")
        return

    recipient_vault.save_vault(recipient_master_password, imported_credentials)
    print(f"[*] Import complete. Recipient vault saved as {recipient_vault.vault_file}.")
    print(f"[*] Export package saved as {package_file}.")


# ==========================================
# CLI INTERFACE
# ==========================================
def main():
    print("=== CMPS426 Secure Password Manager ===")
    user = input("Enter your username: ")
    vault = unlock_or_create_user(user)
    if vault is None:
        return

    while True:
        print(
            "\n1. Add Credential"
            "\n2. Retrieve Credential"
            "\n3. Update Credential"
            "\n4. Delete Credential"
            "\n5. Export Vault (Diffie-Hellman)"
            "\n6. Export Public Key"
            "\n7. Exit"
        )
        choice = input("Select action: ")

        if choice == "1":
            add_credential(vault)
        elif choice == "2":
            retrieve_credential(vault)
        elif choice == "3":
            update_credential(vault)
        elif choice == "4":
            delete_credential(vault)
        elif choice == "5":
            export_vault_with_diffie_hellman(vault)
        elif choice == "6":
            vault.export_public_key()
            print(f"[*] Public key exported to {vault.public_key_file}.")
        elif choice == "7":
            break
        else:
            print("[!] Invalid choice.")


if __name__ == "__main__":
    main()
