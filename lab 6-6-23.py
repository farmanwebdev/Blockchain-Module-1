import hashlib

def calculate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def construct_merkle_tree(data_list):
    if len(data_list) == 1:
        return data_list[0]

    new_data_list = []

    for i in range(0, len(data_list), 2):
        if i + 1 < len(data_list):
            combined_data = data_list[i] + data_list[i + 1]
            new_data_list.append(calculate_hash(combined_data))
        else:
            new_data_list.append(data_list[i])

    return construct_merkle_tree(new_data_list)

def main():
    random_strings = [
        "string1", "string2", "string3", "string4",
        "string5", "string6", "string7", "string8"
    ]

    block_hashes = [calculate_hash(data) for data in random_strings]
    merkle_root = construct_merkle_tree(block_hashes)

    print("Block Hashes:")
    for i, hash_value in enumerate(block_hashes):
        print(f"Block {i + 1}: {hash_value}")

    print("\nMerkle Root:", merkle_root)

if __name__ == "__main__":
    main()


