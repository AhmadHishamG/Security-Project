import hashlib

import secrets
import math

def generate_k(p):
    while True:
        k = secrets.randbelow(p - 2) + 1  

        if math.gcd(k, p - 1) == 1:
            return k

def doingSha256ToVault(vaultData):
    if isinstance(vaultData,str):
        vaultData = vaultData.encode()
    digest = hashlib.sha256(vaultData).digest()
    return digest

def sign(data, x, q, g, p):
    hash_value = int.from_bytes(doingSha256ToVault(data), byteorder='big')
    k =  generate_k(p)
    r = pow(g, k, p)
    s = ((hash_value-x*r)*pow(k, -1, p-1)) % (p-1)
    return r,s

def verify(data, signature,q,publicKey,p,g,message):
    r,s = signature
    hash_value = int.from_bytes(doingSha256ToVault(data), byteorder='big')
    # V1​=y^r*r^smodp do this pls


   
    V1 = (pow(publicKey, r, p) * pow(r, s, p)) % p
    V2 = pow(g, hash_value, p)
    if(V1 == V2):
        return True
    else:
        print("Warning: Verification failed.")
        return False
    
def primitiveRootChecker(alpha, p):
    required_set = set(num for num in range(1, p) if math.gcd(num, p) == 1)
    actual_set = set(pow(alpha, power, p) for power in range(1, p))
    return required_set == actual_set
def generatePrivateKey(q):
    return secrets.randbelow(q - 1) + 1
def generatePublicKey(x, alpha, q):
    return pow(alpha, x, q)

def keyExchange(q1,alpha1):

    if not primitiveRootChecker(alpha1, q1):
        raise ValueError("Alpha is not a primitive root modulo q")
    public_key1 = generatePublicKey(x1, alpha1, q1)
    public_key2 = generatePublicKey(x2, alpha2, q2)
    sign()ic_key2 = generatePublicKey(x2, alpha2, q2)
    sign()