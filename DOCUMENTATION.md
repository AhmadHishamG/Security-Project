# Secure Password Manager Documentation

## 1. Project Goal

The goal of this project is to build a command-line Secure Password Manager that protects stored credentials using encryption, hashing, digital signatures, and secure key exchange.

The system supports two main workflows:

1. **Local workflow:** A user creates a vault, stores credentials, retrieves them, and modifies them securely.
2. **Export workflow:** A user securely exports a vault to another user/device using Diffie-Hellman key exchange and ElGamal digital signatures.

The application is divided into four modules:

1. ElGamal Key Management.
2. Vault Encryption and Credential Management.
3. Digital Signatures for Vault Integrity.
4. Secure Vault Export using Diffie-Hellman.

---

## 2. Overall Design

The application is implemented as a CLI-based password manager. Each user has a local vault file and a key file. The vault file stores encrypted credentials and a digital signature. The key file stores the user's ElGamal public key and encrypted private key.

The main design idea is separation between confidentiality and integrity:

- **Confidentiality** is handled by AES-GCM encryption.
- **Integrity and authenticity** are handled by ElGamal digital signatures.
- **Secure transfer** is handled by Diffie-Hellman session key agreement.

The vault is never stored in plaintext. Credentials are only decrypted temporarily in memory after the user enters the correct master password and after the vault signature passes verification.

---

## 3. Module 1: ElGamal Key Management

### Purpose

Module 1 is responsible for generating and storing the user's ElGamal key pair. The key pair is used later by Module 3 and Module 4 for digital signatures.

### Design Decisions

- The ElGamal key pair is generated once when a new user is initialized.
- The public key is exported to a separate JSON file so other users can verify signatures.
- The private key is not stored in plaintext. It is encrypted locally using AES-GCM with a key derived from a key protection password.
- The same long-term ElGamal key pair is reused across vault signing and export signing.

### Files Created

```text
<username>_keys.json
<username>_public_key.json
```

The private key file contains encrypted private key data, while the public key file contains the public parameters needed for verification.

---

## 4. Module 2: Vault Encryption and Credential Management

### Purpose

Module 2 manages the encrypted credential vault. It supports adding, retrieving, updating, and deleting credentials.

### Algorithm Choices

- The master password is hashed using SHA-256.
- The resulting SHA-256 digest is used as the AES key.
- AES-GCM is used because it provides authenticated encryption.
- The vault is stored as JSON.

### Vault Save Flow

When a credential is added, updated, or deleted:

1. The user enters the master password.
2. The AES key is derived from the master password using SHA-256.
3. The vault is decrypted in memory.
4. The credential operation is applied.
5. The updated vault is encrypted again using AES-GCM.
6. The encrypted vault is signed using ElGamal.
7. The encrypted vault and signature are saved to the vault JSON file.

### Vault Load Flow

When the user retrieves credentials:

1. The vault file is loaded.
2. The signature is verified before decryption.
3. If the signature is invalid, the vault refuses to open.
4. If the signature is valid, the vault is decrypted using the master password.
5. The requested credential is displayed.

---

## 5. Module 3: Digital Signatures for Vault Integrity

### Purpose

Module 3 protects the vault against tampering. Every time the vault is modified, it is signed. Every time the vault is opened, the signature is verified before credentials are shown.

### Signing Algorithm

The code implements ElGamal digital signatures manually.

The signing process is:

1. Compute SHA-256 hash of the encrypted vault data.
2. Convert the hash into an integer modulo `p - 1`.
3. Generate a random `k` such that `gcd(k, p - 1) = 1`.
4. Compute:

```text
r = g^k mod p
```

5. Compute:

```text
s = (H(m) - x*r) * k^-1 mod (p - 1)
```

6. Store the signature as the pair `(r, s)`.

### Verification Algorithm

To verify a signature:

1. Recompute SHA-256 hash of the encrypted vault data.
2. Convert the hash into an integer modulo `p - 1`.
3. Check:

```text
y^r * r^s mod p == g^H(m) mod p
```

If the equation is true, the signature is valid. Otherwise, the vault has been modified or the wrong public key is being used.

### Design Decisions

- The signature is computed over the encrypted vault, not plaintext credentials.
- Verification occurs before decryption.
- The signature is stored in the vault file as a string in the form `r,s`.
- The module does not generate keys. It depends on Module 1 for the ElGamal key pair.

### Tampering Detection

If someone manually edits the encrypted vault data, the recomputed hash changes. Since the old signature no longer matches the modified encrypted data, verification fails and the vault refuses to open.

---

## 6. Module 4: Secure Vault Export using Diffie-Hellman

### Purpose

Module 4 allows one user/device to securely export a vault to another user/device.

Diffie-Hellman is used to create a shared AES session key. ElGamal signatures are used to authenticate DH public keys and the encrypted export package.

### Key Exchange Phase

1. Both devices load shared Diffie-Hellman parameters `q` and `alpha` from `dh_config.json`.
2. Each device generates an ephemeral DH private key.
3. Each device computes its DH public key:

```text
public_key = alpha^private_key mod q
```

4. Device 1 signs its DH public key using its ElGamal private key.
5. Device 2 verifies Device 1's DH public key signature using Device 1's public key.
6. Device 2 signs its DH public key using its ElGamal private key.
7. Device 1 verifies Device 2's DH public key signature using Device 2's public key.
8. If either signature verification fails, the export is aborted.

### Shared Secret Computation

Each side computes the shared secret:

```text
shared_secret = other_public_key^my_private_key mod q
```

Both sides should obtain the same shared secret.

The session key is then derived as:

```text
session_key = SHA-256(shared_secret)
```

This creates a 256-bit AES key.

### Transfer Phase

1. The sender enters the vault master password.
2. The sender's vault is decrypted locally in memory.
3. The decrypted credential data is encrypted using the DH-derived session key.
4. The encrypted export data is signed using the sender's ElGamal private key.
5. The export package is saved as JSON.

### Import Phase

1. The recipient verifies the sender's signature over the encrypted export data.
2. If verification fails, import is aborted.
3. If verification succeeds, the recipient decrypts the export data using the DH-derived session key.
4. The recipient enters a master password for the imported vault.
5. The imported vault is encrypted using the recipient's master password.
6. The new encrypted vault is signed using the recipient's ElGamal private key.
7. The recipient's local vault file is saved.

### Design Decisions

- DH private keys are ephemeral and generated per export session.
- ElGamal signing keys are long-lived and generated once per user.
- DH public keys are signed to prevent man-in-the-middle attacks.
- The export package is signed so the recipient can verify that the encrypted transfer data was not modified.
- The imported vault is re-signed by the recipient so future vault operations depend on the recipient's own key pair.

---

## 7. JSON File Formats

### User Key File

```json
{
  "username": "alice",
  "p": 12345,
  "g": 5,
  "y": 67890,
  "encrypted_private_key": "base64-data"
}
```

### Public Key File

```json
{
  "username": "alice",
  "p": 12345,
  "g": 5,
  "y": 67890
}
```

### Vault File

```json
{
  "owner": "alice",
  "encrypted_vault": "base64-data",
  "signature": "r,s"
}
```

### Diffie-Hellman Config File

```json
{
  "q": 12345,
  "alpha": 5
}
```

### Export Package File

```json
{
  "sender": "alice",
  "recipient": "bob",
  "dh_parameters": {
    "q": 12345,
    "alpha": 5
  },
  "sender_public_key": {},
  "recipient_public_key": {},
  "sender_dh_public": 11111,
  "sender_dh_signature": "r,s",
  "recipient_dh_public": 22222,
  "recipient_dh_signature": "r,s",
  "encrypted_vault": "base64-data",
  "export_signature": "r,s"
}
```

---

## 8. Primitive Root Decision

The program generates safe primes of the form:

```text
p = 2q + 1
```

where both `p` and `q` are prime. For such primes, checking whether a candidate generator is a primitive root can be optimized by checking the factors of `p - 1`.

The direct definition-based method checks whether all powers of `alpha` generate every value from `1` to `p - 1`. This is correct but inefficient for large primes.

For large cryptographic parameters, the optimized safe-prime check is preferred because it avoids looping through an extremely large range.

---

## 9. Challenges Faced

### 1. Signing the Correct Data

A key challenge was deciding what should be signed. The correct choice was to sign the encrypted vault data, not the plaintext credentials. This means tampering can be detected before decryption.

### 2. Signature Verification Order

Another challenge was ensuring that verification happens before decryption. If the vault is decrypted before verification, tampered data could be processed. The final design verifies first, then decrypts only if verification succeeds.

### 3. Diffie-Hellman Authentication

Diffie-Hellman alone does not authenticate users. A man-in-the-middle attacker could replace DH public keys. To solve this, each DH public key is signed using ElGamal and verified by the other side before computing the shared secret.

### 4. Stable Data Representation for Signing

When signing structured JSON data, different key orders or spacing can produce different strings. The `canonical_json()` helper function was used to create a stable JSON string before signing.

### 5. Balancing Security and Performance

Large primes are better for security but slower for testing. Smaller values are easier for debugging, but final demonstrations should use larger values to better match the project requirement of using large primes.

---

## 10. Limitations and Possible Improvements

- The current export/import flow is simulated in one program execution. A more realistic implementation could separate export and import into two independent commands.
- The public key trust model assumes users already have the correct public key file. In a real system, public keys would need certificates or a trusted distribution method.
- The program could add stronger validation for received Diffie-Hellman public keys.
- A graphical interface could be added as a bonus feature.

---

## 11. Conclusion

The project implements a functional secure password manager with encrypted credential storage, ElGamal-based vault integrity verification, and Diffie-Hellman-based secure vault export. The design satisfies the required workflow: setup, store credentials, sign, verify, export to another user, and import into the recipient vault.
