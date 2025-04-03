# RSA-OAEP Authenticated Encryption Tool

## Overview

This Python program provides secure message encryption and decryption using RSA-OAEP (Optimal Asymmetric Encryption Padding) with authenticity through digital signatures. It implements the "encrypt-then-sign" paradigm for authenticated encryption, using separate key pairs for encryption and signing operations.

## Features

- Generates separate RSA key pairs for encryption and signing (2048-bit)
- Implements RSA-OAEP encryption with SHA-256
- Uses PSS signatures with SHA-256 for message authentication
- Saves keys in PEM format for persistence
- Handles messages up to 140 ASCII characters
- Provides hexadecimal output of ciphertext and signatures
- Implements verify-then-decrypt workflow

## Requirements

- Python 3.6+
- cryptography library (`pip install cryptography`)

## Installation

1. Clone or download the repository
2. Install the required dependencies:
   ```bash
   pip install cryptography
   ```

## Usage

Run the program with:
```bash
python rsa_oaep.py
```

### Menu Options

1. **Encrypt-then-sign a message**
   - Enter a message (up to 140 characters)
   - Program will:
     - Encrypt the message using RSA-OAEP
     - Sign the ciphertext
     - Save ciphertext to `ciphertext.bin`
     - Save signature to `signature.bin`
     - Display hexadecimal representations of both

2. **Verify-then-decrypt a message**
   - Program will:
     - Verify the signature of the ciphertext
     - If verification succeeds, decrypt the message
     - Display the original plaintext

3. **Exit**
   - Terminates the program

## Key Management

- On first run, the program generates four key files:
  - `enc_private.pem` - Encryption private key
  - `enc_public.pem` - Encryption public key
  - `sig_private.pem` - Signing private key
  - `sig_public.pem` - Signing public key

- Subsequent runs will use these existing keys
- To regenerate keys, simply delete the PEM files and restart the program

## Security Notes

- Uses industry-standard cryptographic practices:
  - RSA-OAEP for encryption
  - RSA-PSS for signatures
  - SHA-256 for hashing
  - 2048-bit key length
- Never share your private keys (`enc_private.pem`, `sig_private.pem`)
- Public keys can be safely shared for verification/encryption

## File Formats

- **Keys**: PEM format (standard for cryptographic keys)
- **Ciphertext**: Binary format (saved to `ciphertext.bin`)
- **Signatures**: Binary format (saved to `signature.bin`)

## Example Workflow

1. Alice runs the program and selects option 1 to encrypt and sign a message
2. She shares:
   - `ciphertext.bin`
   - `signature.bin`
   - Her signing public key (`sig_public.pem`)
   - The recipient's encryption public key (`enc_public.pem`)
3. Bob receives these files and uses option 2 to verify and decrypt the message

## Limitations

- Message size limited to 140 ASCII characters
- Not designed for streaming or very large data
- Requires proper key management for production use

## License

This tool is provided for educational purposes. Users are responsible for understanding and complying with all applicable laws and regulations regarding cryptography in their jurisdiction.