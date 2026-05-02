import hashlib
import math
import secrets

from Crypto.Util.number import getPrime, isPrime


def generate_k(p):
    while True:
        k = secrets.randbelow(p - 2) + 1
        if math.gcd(k, p - 1) == 1:
            return k


def doingSha256ToVault(vaultData):
    if isinstance(vaultData, str):
        vaultData = vaultData.encode()
    digest = hashlib.sha256(vaultData).digest()
    return digest


def sign(data, x, q, g, p):
    message = int.from_bytes(doingSha256ToVault(data), byteorder="big") % (p - 1)
    k = generate_k(p)
    r = pow(g, k, p)
    s = ((message - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return r, s


def verify(data, signature, q, publicKey, p, g, message=None):
    r, s = signature

    if not (0 < r < p):
        return False
    if not (0 < s < p - 1):
        return False

    if message is None:
        message = int.from_bytes(doingSha256ToVault(data), byteorder="big") % (p - 1)

    v1 = (pow(publicKey, r, p) * pow(r, s, p)) % p
    v2 = pow(g, message, p)

    if v1 == v2:
        return True

    print("Warning: Verification failed.")
    return False


def primitiveRootChecker(alpha, p):
    q = (p - 1) // 2

    if alpha <= 1 or alpha >= p:
        return False
    if pow(alpha, 2, p) == 1:
        return False
    if pow(alpha, q, p) == 1:
        return False

    return True


def generateSafePrimeAndGenerator(bits=512):
    while True:
        q = getPrime(bits - 1)
        p = 2 * q + 1
        if isPrime(p):
            break

    while True:
        alpha = secrets.randbelow(p - 3) + 2
        if primitiveRootChecker(alpha, p):
            return p, alpha


def generatePrivateKey(q):
    return secrets.randbelow(q - 2) + 1


def generatePublicKey(x, alpha, q):
    return pow(alpha, x, q)


def computeSharedSecret(otherPublicKey, myPrivateKey, q):
    return pow(otherPublicKey, myPrivateKey, q)


def deriveSessionKey(sharedSecret):
    sharedSecretBytes = str(sharedSecret).encode()
    return hashlib.sha256(sharedSecretBytes).digest()


def keyExchange(q1, alpha1):
    device1PrivateKey = generatePrivateKey(q1)
    device2PrivateKey = generatePrivateKey(q1)

    public_key1 = generatePublicKey(device1PrivateKey, alpha1, q1)
    public_key2 = generatePublicKey(device2PrivateKey, alpha1, q1)

    device1SharedSecret = computeSharedSecret(public_key2, device1PrivateKey, q1)
    device2SharedSecret = computeSharedSecret(public_key1, device2PrivateKey, q1)

    if device1SharedSecret != device2SharedSecret:
        raise ValueError("Diffie-Hellman key exchange failed.")

    sessionKey = deriveSessionKey(device1SharedSecret)
    return public_key1, public_key2, sessionKey


class ElGamal:
    @staticmethod
    def generate_keys(bits=512):
        p, g = generateSafePrimeAndGenerator(bits)
        x = generatePrivateKey(p)
        y = pow(g, x, p)
        return p, g, x, y

    @staticmethod
    def sign(message, p, g, x):
        return sign(message, x, None, g, p)

    @staticmethod
    def verify(message, r, s, p, g, y):
        return verify(message, (r, s), None, y, p, g)


class DiffieHellman:
    @staticmethod
    def generate_parameters(bits=512):
        return generateSafePrimeAndGenerator(bits)

    @staticmethod
    def generate_keypair(q, alpha):
        private_key = generatePrivateKey(q)
        public_key = generatePublicKey(private_key, alpha, q)
        return private_key, public_key

    @staticmethod
    def compute_secret(other_public, my_private, q):
        shared_secret = computeSharedSecret(other_public, my_private, q)
        return deriveSessionKey(shared_secret)
