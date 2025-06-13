# Blind Signature Implementation in Python using a client/server model

This project implements the **Blind Signature** protocol using a client-server model in Python with sockets. The goal is to allow a client to obtain a digital signature from an authority (the server) for a document, without the authority ever learning the content of the document, thus ensuring the client's privacy.

---

## Protocol Description

A blind signature is a cryptographic protocol in which a message is "blinded" by the client before being sent to the signer (server). The server signs the blinded message and returns it. The client can then "unblind" the message to obtain a valid signature on the original message.

The main workflow is as follows:
1.  **Client:** Calculates the hash of the original document.
2.  **Client:** Generates a "blinding factor" (a random number) and uses it to blind the hash.
3.  **Client:** Sends the blinded hash to the server.
4.  **Server:** Signs the blinded hash with its RSA private key and returns it. It has no knowledge of what it is signing.
5.  **Client:** Receives the blinded signature and uses the blinding factor to "unblind" it, thereby obtaining a valid signature for the original hash.

---

## Project Structure

The project consists of three main scripts:

### `server_signature.py`
The server acts as the signing authority.
*   On its first run, it generates a 2048-bit RSA key pair.
*   It saves the full key (public and private) to `server_key` and the public key to `server_key.pub`.
*   It listens on a port (default `65432`) for incoming connections.
*   When it receives a blinded hash, it signs it and returns the signature.

### `client_signature.py`
The client is responsible for orchestrating the blind signature process.
*   It reads an input file.
*   It calculates its hash (SHA-256).
*   It blinds the hash using the server's public key and a blinding factor.
*   It sends the blinded hash to the server.
*   It receives the blinded signature, unblinds it, and prints the result to standard output in a hex format, separated by colons.

### `verify_signature.py`
This program checks the validity of a signature without needing to interact with the server.
*   It takes the original file, the signature file, and the server's public key as input.
*   It calculates the hash of the original file and verifies if the signature corresponds to that hash using the public key.
*   It prints whether the signature is `VALID SIGNATURE` or `INVALID SIGNATURE`.

---

## Technology Stack

*   **Python 3**: The primary language for the project.
*   **Sockets**: For client-server network communication.
*   **PyCryptodome**: A library for cryptographic operations (RSA, hashing, padding).

---

## Prerequisites and Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/your-repository.git
    cd your-repository
    ```

2.  **Install dependencies:**
    The project requires the `pycryptodome` library. You can install it using pip:
    ```bash
    pip install pycryptodome
    ```

---

## How to Run the Project

Follow these steps in order to test the complete workflow.

### Step 1: Start the Server

In a terminal, run the server script. It will start listening for requests.
```bash
python3 server_signature.py
```
**Output (on first run):**
```
[+] Generating RSA key pair (2048 bits)...
[+] Keys saved to server_key and server_key.pub
[+] Server listening on port 65432...
```

### Step 2: Request a Signature from the Client

1.  First, create a sample file to be signed:
    ```bash
    echo "This is my secret document." > my_document.txt
    ```

2.  In a **new terminal**, run the client script to get the signature. The output will be redirected to `signature.txt`.
    ```bash
    python3 client_signature.py my_document.txt server_key.pub > signature.txt
    ```

### Step 3: Verify the Signature

Use the verifier script to check if the generated signature is valid for the original document.

**To check a valid signature:**
```bash
python3 verify_signature.py my_document.txt signature.txt server_key.pub
```
**Expected Output:**
```
VALID SIGNATURE
```

**To check an invalid signature (e.g., with a modified document):**
```bash
echo "This is a modified document." > modified_document.txt
python3 verify_signature.py modified_document.txt signature.txt server_key.pub
```
**Expected Output:**
```
INVALID SIGNATURE
```