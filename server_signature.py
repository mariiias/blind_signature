#!/usr/bin/env python3

import socket
import os
from Crypto.PublicKey import RSA

HOST = '127.0.0.1' 
PORT = 65432    
KEY_SIZE = 2048
PRIVATE_KEY_FILE = "server_key"
PUBLIC_KEY_FILE = "server_key.pub"

def generate_and_save_keys():
    """Generates an RSA key pair and saves them to files if they don't already exist."""
    if not os.path.exists(PRIVATE_KEY_FILE):
        print("[+] Generating a new RSA key pair...")
        key = RSA.generate(KEY_SIZE)
        
        # Save the private (full) key
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(key.export_key('PEM'))
            
        # Save the public key
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(key.publickey().export_key('PEM'))
            
        print(f"[+] Keys saved to '{PRIVATE_KEY_FILE}' and '{PUBLIC_KEY_FILE}'.")
    else:
        print("[+] Using existing keys.")

def start_server():
    """Starts the server to listen for signing requests."""
    
    # Load the server's private key
    try:
        with open(PRIVATE_KEY_FILE, "rb") as f:
            private_key = RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"[!] Error: Private key file '{PRIVATE_KEY_FILE}' not found.")
        print("[!] Please run the server once to generate the keys.")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[+] Server listening on {HOST}:{PORT}...")
        
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"\n[*] Connection established from {addr}")
                
                # Receive the blinded hash from the client
                blinded_hash_bytes = conn.recv(KEY_SIZE // 8)
                if not blinded_hash_bytes:
                    continue

                # Convert the received bytes to an integer for mathematical operations
                blinded_hash_int = int.from_bytes(blinded_hash_bytes, 'big')

                # Sign the blinded hash using the raw RSA operation (modular exponentiation)
                # blinded_signature = (blinded_hash)^d mod n
                blinded_signature_int = pow(blinded_hash_int, private_key.d, private_key.n)
                
                # Convert the signature back to bytes and send it to the client
                blinded_signature_bytes = blinded_signature_int.to_bytes(KEY_SIZE // 8, 'big')
                conn.sendall(blinded_signature_bytes)
                print("[+] Blinded signature sent to the client.")

if __name__ == "__main__":
    generate_and_save_keys()
    start_server()