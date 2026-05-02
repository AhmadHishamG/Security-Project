## CMPS426 Secure Password Manager - Team 5

## Prerequisites

Install Python 3.8 or newer and pycryptodome:

```bash
pip install pycryptodome
```

## How to Run
Execute the script from your terminal:

```Bash
python password_manager.py
```
## System Workflow & Usage
1. Initialization and Login
Upon running the application, enter your username.

First-time users: You will be prompted to create a Key Protection Password. This password protects your locally generated ElGamal private key.

Returning users: Enter your Key Protection Password to unlock your keys and access the main menu.

2. Main Menu Actions
To perform any vault operations, you will be prompted for your Master Password. This acts as the root for your AES encryption data key.

1. Add Credential: Prompts for a website name, username, and password. The vault is securely decrypted, updated, re-encrypted, and then re-signed.

2. Retrieve Credential: View a specific stored credential or print out the contents of the entire vault.

3. Update Credential: Modify an existing username or password for a specific site.

4. Delete Credential: Remove a single site credential or securely wipe the entire vault.

5. Export Vault (Diffie-Hellman): Securely transfer your vault to another user/device (see details below).

6. Export Public Key: Generates a JSON file of your ElGamal public key, which can be shared with others for signature verification.

7. Exit: Safely close the application.

3. Secure Vault Export (Diffie-Hellman Transfer)
This feature allows Device 1 to securely send an encrypted vault to Device 2, mimicking an end-to-end encrypted transfer.

The sender selects Export Vault.

Enter the sender's master password to unlock the vault for the transfer.

Input the recipient's username (the recipient must have an initialized profile on the machine).

Enter the recipient's master password (this represents what the recipient will use to encrypt the newly imported vault).

The application will perform an ephemeral Diffie-Hellman key exchange, sign the public keys with ElGamal to prevent Man-in-the-Middle (MITM) attacks, and encrypt the vault using the derived AES session key.

The transfer package is created and automatically ingested, verified, decrypted, and re-encrypted into the recipient's local vault.

Generated Files Structure
The application automatically generates the following files in its working directory:

[username]_vault.json: The AES-encrypted vault containing credentials and its ElGamal digital signature.

[username]_keys.json: Your ElGamal parameters and AES-encrypted private key.

[username]_public_key.json: Your exportable ElGamal public key for sharing.

dh_config.json: The shared configuration containing the Diffie-Hellman prime and generator parameters.

[sender]_to_[recipient]_export_package.json: The transit package generated during a secure vault export.