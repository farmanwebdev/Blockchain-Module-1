import hashlib
import bcrypt

# Take name as input
name = input("Enter your name: ")
number =input("Enter Your ID Number:")

# Convert name string to bytes
name_bytes = name.encode()

# Generate MD5 hash
md5_hash = hashlib.md5(name_bytes).hexdigest()

# Generate SHA-1 hash
sha1_hash = hashlib.sha1(name_bytes).hexdigest()

# Generate SHA-256 hash
sha256_hash = hashlib.sha256(name_bytes).hexdigest()

# Generate SHA-512 hash
sha512_hash = hashlib.sha512(name_bytes).hexdigest()

# Generate SHA-3 (SHA-3-256) hash
sha3_hash = hashlib.sha3_256(name_bytes).hexdigest()

# Generate BLAKE2 hash
blake2_hash = hashlib.blake2s(name_bytes).hexdigest()

# Generate bcrypt hash
bcrypt_salt = bcrypt.gensalt()
bcrypt_hash = bcrypt.hashpw(name_bytes, bcrypt_salt).decode()

# Generate RIPEMD-160 hash
ripemd_hash = hashlib.new('ripemd160', name_bytes).hexdigest()

# Print the hashes
print("MD5:", md5_hash)
print("SHA-1:", sha1_hash)
print("SHA-256:", sha256_hash)
print("SHA-512:", sha512_hash)
print("SHA-3:", sha3_hash)
print("BLAKE2:", blake2_hash)
print("bcrypt:", bcrypt_hash)
print("RIPEMD-160:", ripemd_hash)
# salt = bcrypt.gensalt()
# bcrypt_hash = bcrypt.hashpw(text.encode(),salt);
# print("bcrypt.Hash:"),bcrypt_hash
# ripemd160_hash = hashlib.new('ripemd160',.text.encode()).hexdigest()
# print("RIPEMD-160.Hash:",ripemd160_hash)
import bcrypt

def hash_password(password):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def verify_password(password, hashed_password):
    # Verify if the password matches the hashed password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

# Example usage
password = "my_password"

# Hash the password
hashed_password = hash_password(password)
# Verify the password
is_valid = verify_password(password, hashed_password)

print("Password is valid:", is_valid) 