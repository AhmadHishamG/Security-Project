# CMPS426 Secure Password Manager

## Overview
This project is Part 1 of the CMPS426 Security Course Project[cite: 1]. It is a command-line based Secure Password Manager designed to securely store, retrieve, and manage credentials[cite: 1]. 

The application implements several core cryptographic concepts:
*   **AES (GCM Mode):** For secure vault encryption and decryption[cite: 1].
*   **SHA-256:** For hashing operations and deriving data keys from the master password[cite: 1].
*   **ElGamal Digital Signatures:** Implemented from scratch to ensure vault integrity and protect against tampering[cite: 1].
*   **Diffie-Hellman Key Exchange:** Implemented from scratch to facilitate secure vault exports between devices/users[cite: 1].

## Prerequisites
To run this application, you must have Python 3.8 or higher installed on your system. 

You will also need to install the `pycryptodome` library, which is used strictly for AES encryption and SHA hashing as permitted by the project guidelines[cite: 1]. 

Install the required dependency using pip:
```bash
pip install pycryptodome

How to Run the Application
1.Open your terminal or command prompt.

2.Navigate to the directory containing the project files.

3.Execute the main Python script:
    python password_manager.py

## Workflow & Usage Guide

Upon launching the application, you will be prompted to enter your **username**. 

*   **First-Time Users:** If this is your first time logging in, the system will automatically initialize your profile by generating an ElGamal public/private key pair[cite: 1]. These keys are saved locally in a `{username}_keys.json` file.
*   **Returning Users:** The system will load your existing key pair to verify and sign your vault.

Once logged in, you will be presented with a CLI menu offering the following options:

### 1. Add Credential
*   You will be prompted to enter your **Master Password**. 
*   The system uses this password to derive an AES key and decrypt your vault in memory[cite: 1].
*   Enter the Website, Username, and Password for the new credential.
*   The system will re-encrypt the vault and generate a fresh ElGamal digital signature over the encrypted contents before saving it to disk[cite: 1].

### 2. View Credentials
*   Enter your **Master Password**.
*   The system will first verify the ElGamal signature to ensure the vault file hasn't been tampered with[cite: 1]. If the signature is invalid, the vault will refuse to open[cite: 1].
*   If valid, the vault decrypts and displays your stored credentials[cite: 1].

### 3. Export Vault (Diffie-Hellman)
*   This module simulates a secure export to another device.
*   Enter your **Master Password** to unlock your local vault.
*   The system will automatically generate ephemeral Diffie-Hellman parameters and perform a simulated key exchange with a receiving device[cite: 1]. 
*   Both the sent and received DH public keys are signed using ElGamal to prevent Man-in-the-Middle attacks[cite: 1].
*   A 256-bit session key is derived from the DH shared secret, which is then used to securely encrypt the vault data for transit[cite: 1].

### 4. Exit
*   Safely closes the application.

## File Structure
*   `password_manager.py`: The main application script containing all 4 required modules[cite: 1].
*   `{username}_keys.json`: Stores your generated ElGamal public and private keys (generated on first run).
*   `{username}_vault.json`: The AES-encrypted vault containing your credentials and the ElGamal digital signature[cite: 1].