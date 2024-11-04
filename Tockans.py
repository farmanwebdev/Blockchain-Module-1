import hashlib
import time

class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash

def calculate_hash(index, previous_hash, timestamp, data):
    value = str(index) + str(previous_hash) + str(timestamp) + str(data)
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def create_genesis_block():
    return Block(0, "0", time.time(), "Genesis Block", calculate_hash(0, "0", time.time(), "Genesis Block"))

def create_new_block(previous_block, data):
    index = previous_block.index + 1
    timestamp = time.time()
    hash = calculate_hash(index, previous_block.hash, timestamp, data)
    return Block(index, previous_block.hash, timestamp, data, hash)

# Example usage
blockchain = [create_genesis_block()]
previous_block = blockchain[0]

# Add blocks to the blockchain
for i in range(1, 10):
    data = f"Block {i}"
    new_block = create_new_block(previous_block, data)
    blockchain.append(new_block)
    previous_block = new_block
    print(f"Block #{i} has been added to the blockchain!")
    print(f"Hash: {new_block.hash}\n")
