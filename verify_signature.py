#!/usr/bin/env python3

import sys
import hashlib
from Crypto.PublicKey import RSA

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} original_file signature.txt server_key.pub")
        sys.exit(1)

    original_file = sys.argv[1]
    signature_file = sys.argv[2]
    pub_key_file = sys.argv[3]

    # Load the server's public key
    with open(pub_key_file, "rb") as f:
        pub_key = RSA.import_key(f.read())
    n = pub_key.n
    e = pub_key.e

    # Read the original file and calculate its hash
    with open(original_file, "rb") as f:
        content = f.read()
    original_hash = hashlib.sha256(content).digest()
    original_hash_int = int.from_bytes(original_hash, 'big')

    # Read the signature from the file and convert it from hexadecimal to bytes, then to an integer
    with open(signature_file, "r") as f:
        signature_hex = f.read().strip()
    
    try:
        signature_bytes = bytes.fromhex(signature_hex.replace(':', ''))
        signature_int = int.from_bytes(signature_bytes, 'big')
    except ValueError:
        print("Error: The signature format in the file is not valid.")
        sys.exit(1)

    # Verify the signature by "decrypting" it with the public key
    # verified_hash = (signature)^e mod n
    verified_hash_int = pow(signature_int, e, n)
    
    # Compare the verified hash with the original hash
    if verified_hash_int == original_hash_int:
        print("VALID SIGNATURE")
    else:
        print("INVALID SIGNATURE")

if __name__ == "__main__":
    main()