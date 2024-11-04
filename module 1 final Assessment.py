import hashlib

def calculate_hash(input_string):
    return hashlib.sha256(input_string.encode()).hexdigest()

def find_nonce(target_prefix):
    attempts = 0
    nonce = 0

    while True:
        input_string = f"{sender_email}{recipient_email}{email_subject}{message_body}{nonce}"
        hash_result = calculate_hash(input_string)
        attempts += 1

        if hash_result.startswith(target_prefix):
            return nonce, attempts

        nonce += 1

# Task 1
sender_email = input("Enter sender's email address: ")
recipient_email = input("Enter recipient's email address: ")
email_subject = input("Enter email subject: ")
message_body = input("Enter message body: ")

nonce_ff, attempts_ff = find_nonce("ff")

print(f"\nTask 1 Results:")
print(f"Nonce (first two hexadecimal digits are 'ff'): {nonce_ff}")
print(f"Number of attempts: {attempts_ff}")

# Task 2
nonce_ffff, attempts_ffff = find_nonce("ffff")

print(f"\nTask 2 Results:")
print(f"Nonce (first four hexadecimal digits are 'ffff'): {nonce_ffff}")
print(f"Number of attempts: {attempts_ffff}")
