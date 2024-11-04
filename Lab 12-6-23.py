import random
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes

def generateTxid():
    random_integer = random.randint(1, 1000000)
    txid_hash = hashlib.sha256(str(random_integer).encode()).hexdigest()
    return txid_hash

def generateInput():
    prevTxid = generateTxid()
    prevOutputIndex = random.randint(0, 5)
    return prevTxid, prevOutputIndex

def generateOutput():
    recipientAddress = 'recipient_address_' + str(random.randint(1, 100))
    amount = round(random.uniform(0.001, 1.0), 8)
    return recipientAddress, amount

def generateTransactionFee():
    return round(random.uniform(0.0001, 0.001), 8)

def generateRandomTransaction():
    txid = generateTxid()
    inputPrevTxid, inputPrevOutputIndex = generateInput()
    outputRecipientAddress, outputAmount = generateOutput()
    transactionFee = generateTransactionFee()
    return txid, inputPrevTxid, inputPrevOutputIndex, outputRecipientAddress, outputAmount, transactionFee

def concatenateString(txid, inputPrevTxid, inputPrevOutputIndex, outputRecipientAddress, outputAmount, transactionFee):
    transactionData = str(txid) + str(inputPrevTxid) + str(inputPrevOutputIndex) + str(outputRecipientAddress) + str(outputAmount) + str(transactionFee)
    return transactionData

def generateECDSAKeyPair():
    ECDSAPrivateKey = ec.generate_private_key(ec.SECP256K1())
    ECDSAPublicKey = ECDSAPrivateKey.public_key()
    return ECDSAPrivateKey, ECDSAPublicKey

def ECDSASign(privateKey, message):
    signature = privateKey.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

def ECDSAVerify(publicKey, message, signature):
    try:
        publicKey.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False

def main():
    txid, inputPrevTxid, inputPrevOutputIndex, outputRecipientAddress, outputAmount, transactionFee = generateRandomTransaction()
    transactionDataAsMessage = concatenateString(txid, inputPrevTxid, inputPrevOutputIndex, outputRecipientAddress, outputAmount, transactionFee).encode()
    transactionDataAsMessageSHA256Hashed = hashlib.sha256(transactionDataAsMessage).hexdigest()

    ECDSAPrivateKey, ECDSAPublicKey = generateECDSAKeyPair()
    signature = ECDSASign(ECDSAPrivateKey, transactionDataAsMessageSHA256Hashed)
    verified = ECDSAVerify(ECDSAPublicKey, transactionDataAsMessageSHA256Hashed, signature)

    print("ECDSA:")
    print("ECDSA Public Key:", ECDSAPublicKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print("ECDSA Private Key:", ECDSAPrivateKey.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    print("transactionDataAsMessageSHA256Hashed:", transactionDataAsMessageSHA256Hashed)
    print("Signature:", signature.hex())
    print("Verification:", verified)

if __name__ == "__main__":
    main()
