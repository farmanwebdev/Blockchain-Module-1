import hashlib
import urllib.request

# Task 1
# a. Calculate SHA-256 hash of the file "Lab5-6-2023.pdf"
def calculate_online_hash():
    file_url = "https://example.com/Lab5-6-2023.pdf"  # Replace with the actual file URL
    response = urllib.request.urlopen(file_url)
    hash_object = hashlib.sha256()
    hash_object.update(response.read())
    online_hash = hash_object.hexdigest()
    return online_hash

# b. Accept and store the online hash
online_hash = calculate_online_hash()

# c. Import the file and calculate the hash
def calculate_file_hash(filename):
    hash_object = hashlib.sha256()
    with open(filename, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            hash_object.update(chunk)
    file_hash = hash_object.hexdigest()
    return file_hash

file_hash = calculate_file_hash('Lab5-6-2023.pdf')  # Replace with the actual file name

# d. Compare both hashes and print the result
if online_hash == file_hash:
    print("Hashes match.")
else:
    print("Hashes do not match.")

# Task 2
# Create a text file containing random content
with open('random_file.txt', 'w') as file:
    file.write("This is some random content.")

# Calculate the initial hash
initial_hash = calculate_file_hash('random_file.txt')

# Modify the content and calculate the new hash
with open('random_file.txt', 'a') as file:
    file.write(" Adding some more content.")

# Calculate the new hash
new_hash = calculate_file_hash('random_file.txt')

print("Initial hash:", initial_hash)
print("New hash:", new_hash)

# Task 3
# a. Import the files
url1 = "https://drive.google.com/uc?export=download&id=14KwmJ-cD-bOrGz65Nh7jpJTEyoac3tpq"
url2 = "https://drive.google.com/uc?export=download&id=1U2K4cOks8Nb78kcJe6u4n8JP0HD2AhWk"
urllib.request.urlretrieve(url1, "message1.bin")
urllib.request.urlretrieve(url2, "message2.bin")

# b. Calculate MD5 and SHA-1 hashes
def calculate_hashes(filename):
    with open(filename, 'rb') as file:
        content = file.read()
        md5_hash = hashlib.md5(content).hexdigest()
        sha1_hash = hashlib.sha1(content).hexdigest()
    return md5_hash, sha1_hash

md5_hash1, sha1_hash1 = calculate_hashes('message1.bin')
md5_hash2, sha1_hash2 = calculate_hashes('message2.bin')

print("Message1.bin:")
print("MD5 hash:", md5_hash1)
print("SHA-1 hash:", sha1_hash1)

print("Message2.bin:")
print("MD5 hash:", md5_hash2)
print("SHA-1 hash:", sha1_hash2)
