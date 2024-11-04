import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

def generateRSAKeyPair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def RSAEncrypt(public_key, plain_text):
    cipher_text = public_key.encrypt(
        plain_text,
        padding.PKCS1v15()
    )
    return cipher_text

def RSADecrypt(private_key, cipher_text):
    plain_text = private_key.decrypt(
        cipher_text,
        padding.PKCS1v15()
    )
    return plain_text

def generateDSAKeyPair():
    private_key = dsa.generate_private_key(
        key_size=1024
    )
    public_key = private_key.public_key()
    return private_key, public_key

def DSASign(private_key, message):
    signature = private_key.sign(
        message,
        hashes.SHA256()
    )
    return signature

def DSAVerify(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except:
        return False

def generateECDSAKeyPair():
    private_key = ec.generate_private_key(
        ec.SECP256K1()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def ECDSASign(private_key, message):
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def ECDSAVerify(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except:
        return False

def main():
    # RSA
    RSAprivateKey, RSApublicKey = generateRSAKeyPair()
    plainText = b"Message for RSA algorithm"
    cipherText = RSAEncrypt(RSApublicKey, plainText)
    decryptedText = RSADecrypt(RSAprivateKey, cipherText)
    print("RSA details:")
    print("RSA Public Key:", RSApublicKey)
    print("RSA Private Key:", RSAprivateKey)
    print("Plaintext:", plainText.decode())
    print("Ciphertext:", cipherText)
    print("Decrypted Text:", decryptedText.decode())

    # DSA
    DSAPrivateKey, DSAPublicKey = generateDSAKeyPair()
    message = b"Message for DSA algorithm"
    signature = DSASign(DSAPrivateKey, message)
    verified = DSAVerify(DSAPublicKey, message, signature)
    print("\nDSA details:")
    print("DSA Public Key:", DSAPublicKey)
    print("DSA Private Key:", DSAPrivateKey)
    print("Message:", message.decode())
    print("Signature:", signature)
    print("Verification:", verified)

    # ECDSA
    ECDSAPrivateKey, ECDSAPublicKey = generateECDSAKeyPair()
    message_ecdsa = b"Message for ECDSA algorithm"
    signature_ecdsa = ECDSASign(ECDSAPrivateKey, message_ecdsa)
    verified_ecdsa = ECDSAVerify(ECDSAPublicKey, message_ecdsa, signature_ecdsa)
    print("\nECDSA:")
    print("ECDSA Public Key:", ECDSAPublicKey)
    print("ECDSA Private Key:", ECDSAPrivateKey)
    print("Message:", message_ecdsa.decode())
    print("Signature:", signature_ecdsa)
    print("Verification:", verified_ecdsa)

if __name__ == "__main__":
    main()
