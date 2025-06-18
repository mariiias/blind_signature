#!/usr/bin/env python3
# client_sign.py

import sys
import socket
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Util.number import getRandomInteger, inverse

HOST = '127.0.0.1'
PORT = 65432
KEY_SIZE = 2048

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} original_file server_key.pub > signature.txt", file=sys.stderr)
        sys.exit(1)

    original_file = sys.argv[1]
    pub_key_file = sys.argv[2]

    # Load the server's public key
    with open(pub_key_file, "rb") as f:
        pub_key = RSA.import_key(f.read())
    n = pub_key.n
    e = pub_key.e

    # Read the original file and calculate its hash (SHA-256)
    with open(original_file, "rb") as f:
        content = f.read()
    original_hash = hashlib.sha256(content).digest()
    original_hash_int = int.from_bytes(original_hash, 'big')

    # Generate the "blinding factor" (r)
    r = 0
    while True:
        r = getRandomInteger(KEY_SIZE)
        if r > 1 and r < n:
            from math import gcd
            if gcd(r, n) == 1:
                break
    
    # Blind the hash: blinded_hash = (original_hash * r^e) mod n
    blinded_hash_int = (original_hash_int * pow(r, e, n)) % n
    blinded_hash_bytes = blinded_hash_int.to_bytes(KEY_SIZE // 8, 'big')

    # Connect to the server and send the blinded hash
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        except ConnectionRefusedError:
            print(f"Error: Could not connect to the server at {HOST}:{PORT}. Is the server running?", file=sys.stderr)
            sys.exit(1)
            
        s.sendall(blinded_hash_bytes)
        
        # Receive the blinded signature from the server (CORRECT, ROBUST WAY)
        expected_bytes = KEY_SIZE // 8
        received_sections = []
        bytes_received = 0
        while bytes_received < expected_bytes:
            section = s.recv(expected_bytes - bytes_received)
            if not section:
                # The server closed the connection unexpectedly
                print("Error: The server closed the connection before sending the full signature.", file=sys.stderr)
                sys.exit(1)
            received_sections.append(section)
            bytes_received += len(section)
        
        blinded_signature_bytes = b''.join(received_sections)

    blinded_signature_int = int.from_bytes(blinded_signature_bytes, 'big')

    # "Unblind" the signature: final_signature = (blinded_signature * r^-1) mod n
    r_inverse = inverse(r, n)
    final_signature_int = (blinded_signature_int * r_inverse) % n
    final_signature_bytes = final_signature_int.to_bytes(KEY_SIZE // 8, 'big')

    # Display the final signature in the required format (hexadecimal with ':')
    signature_hex = final_signature_bytes.hex(':').upper()
    print(signature_hex)

if __name__ == "__main__":
    main()