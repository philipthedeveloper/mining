import hashlib
import json

f = open("json_data.json")

json_full_data = json.load(f)

json_data = json_full_data["result"]

f.close()
# replace with actual previous block hash
version = json_data["version"]
prev_block_hash = bytes.fromhex(json_data["previousblockhash"])
merkle_root_hash = bytes.fromhex(json_data["merkleroot"])
timestamp = int(json_data["time"])
bits = bytes.fromhex(json_data["bits"])
nonce = int(json_data["nonce"])

# Decode the bits value
exponent = bits[0]
coefficient = int.from_bytes(bits[1:], byteorder="big")
target = coefficient * 2**(8 * (exponent - 3))

# Encode the fields in the correct binary format
version_bytes = version.to_bytes(4, byteorder="little")
# reverse byte order for little-endian format
prev_block_hash_bytes = prev_block_hash[::-1]
# reverse byte order for little-endian format
merkle_root_hash_bytes = merkle_root_hash[::-1]
timestamp_bytes = timestamp.to_bytes(4, byteorder="little")
# truncate to 4 bytes for "bits" format
bits_bytes = target.to_bytes(32, byteorder="big")[:4]
nonce_bytes = nonce.to_bytes(4, byteorder="little")

# print(version_bytes)
# print(prev_block_hash_bytes)
# print(merkle_root_hash_bytes)
# print(timestamp_bytes)
# print(bits_bytes)
# print(nonce_bytes)

# Concatenate the fields together in the correct order
header = version_bytes + prev_block_hash_bytes + \
    merkle_root_hash_bytes + timestamp_bytes + bits_bytes + nonce_bytes
# print(header)

# Hash the header using the Scrypt algorithm

low = True

hash = hashlib.scrypt(header, salt=b"", n=1024, r=1, p=1)


def hasher():
    global hash
    hash = hashlib.scrypt(header, salt=b"", n=1024, r=1, p=1)
    # Convert the hash value and target threshold to integers
    hash_int = int.from_bytes(hash, byteorder="big")
    target_int = int.from_bytes(bits_bytes, byteorder="big")
    return hash_int, target_int


def increment_nonce():
    global nonce
    global header
    # Increment the nonce value
    nonce += 1

    # Convert the nonce to a 4-byte little-endian binary string
    nonce_bytes = nonce.to_bytes(4, byteorder="little")

    # Concatenate the header fields to form the block header
    header = version_bytes + prev_block_hash_bytes + \
        merkle_root_hash_bytes + timestamp_bytes + bits_bytes + nonce_bytes


while low:
    increment_nonce()
    hash_int, target_int = hasher()
    # Check if the hash value meets the target threshold
    if hash_int <= target_int:
        print("Block hash found!")
        print("Hash:", hash.hex())
        print("nonce", nonce)
        print("Target threshold:", target_int)
        low = False
    else:
        print("Nonce value too high, try again with a new nonce.")
