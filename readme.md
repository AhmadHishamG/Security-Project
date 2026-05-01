# CMPS426 Secure Password Manager

## Overview

This is a command-line Secure Password Manager for the CMPS426 Security Course Project. It stores credentials in an AES-GCM encrypted vault, signs vault data with ElGamal digital signatures, and supports secure vault export/import through an authenticated Diffie-Hellman session.

The program implements the 4 required modules:

1. **ElGamal Key Management**
   - Generates ElGamal parameters and a long-term public/private signing key pair.
   - Protects the private key locally using AES-GCM with a key protection password.
   - Exports the public key to `{username}_public_key.json`.

2. **Vault Encryption & Credential Management**
   - Derives an AES-256 key from the master password using SHA-256.
   - Encrypts the full vault with AES-GCM.
   - Supports add, retrieve, update, and delete operations.

3. **Digital Signatures for Vault Integrity**
   - Signs the encrypted vault content after every modification.
   - Verifies the signature before opening the vault.
   - Refuses to open the vault if tampering is detected.

4. **Secure Vault Export via Diffie-Hellman**
   - Generates ephemeral DH keys per export session.
   - Signs and verifies both DH public keys using ElGamal.
   - Derives a shared AES session key from the DH secret.
   - Encrypts and signs the export package.
   - Simulates recipient-side import by decrypting the package, re-encrypting it with the recipient's master password, and signing the recipient vault with the recipient's private key.

## Prerequisites

Install Python 3.8 or newer and pycryptodome:

```bash
pip install pycryptodome
```

## How to Run

From this directory:

```bash
python password_manager.py
```

If you are one directory above `Security-Project`, run:

```bash
python Security-Project/password_manager.py
```

## CLI Menu

After entering your username and unlocking or creating your protected key file, the app shows:

1. Add Credential
2. Retrieve Credential
3. Update Credential
4. Delete Credential
5. Export Vault (Diffie-Hellman)
6. Export Public Key
7. Exit

## Generated Files

- `{username}_keys.json`: local protected private key plus public parameters.
- `{username}_public_key.json`: exportable public key file.
- `{username}_vault.json`: AES-GCM encrypted vault plus ElGamal signature.
- `{sender}_to_{recipient}_export_package.json`: encrypted and signed transfer package generated during DH export.

## Notes

- The key protection password protects the ElGamal private signing key.
- The master password protects the password vault contents.
- Prime generation is handled through pycryptodome, while ElGamal signing/verification, modular inverse, GCD, and Diffie-Hellman shared-secret logic are implemented directly in the project code.
