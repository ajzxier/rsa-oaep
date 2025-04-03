import os
import binascii 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Key generation functions
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


# Save keys to PEM files
def save_keys(enc_private_key, enc_public_key, sig_private_key, sig_public_key):
    # Save encryption keys
    with open("enc_private.pem", "wb") as f:
        f.write(enc_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open("enc_public.pem", "wb") as f:
        f.write(enc_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    # Save signing keys
    with open("sig_private.pem", "wb") as f:
        f.write(sig_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open("sig_public.pem", "wb") as f:
        f.write(sig_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Load keys from PEM files
def load_keys():
    with open("enc_private.pem", "rb") as f:
        enc_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    with open("enc_public.pem", "rb") as f:
        enc_public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    
    with open("sig_private.pem", "rb") as f:
        sig_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    with open("sig_public.pem", "rb") as f:
        sig_public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    
    return enc_private_key, enc_public_key, sig_private_key, sig_public_key

# Encrypt a message
def encrypt_message(message, enc_public_key):
    ciphertext = enc_public_key.encrypt(
        message.encode('ascii'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Sign the encrypted message
def sign_message(ciphertext, sig_private_key):
    signature = sig_private_key.sign(
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify the signature 
def verify_signature(ciphertext, signature, sig_public_key):
    try:
        sig_public_key.verify(
            signature,
            ciphertext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

# Decrypt the message
def decrypt_message(ciphertext, enc_private_key):
    plaintext = enc_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('ascii')

# Main program
def main():
    # Generate keys if does not exist
    if not all(os.path.exists(f) for f in ["enc_private.pem", "enc_public.pem", "sig_private.pem", "sig_public.pem"]):
        print("Generating new key pairs...")
        enc_private, enc_public = generate_keys()
        sig_private, sig_public = generate_keys()
        save_keys(enc_private, enc_public, sig_private, sig_public)
        print("Key pairs generated and saved to PEM files.")
    else:
        print("Loading existing key pairs...")
        enc_private, enc_public, sig_private, sig_public = load_keys()
    
    while True:
        print("\nOptions:")
        print("1. Encrypt-then-sign a message")
        print("2. Verify-then-decrypt a message")
        print("3. Exit")
        choice = input("Enter your choice: ")
        
        if choice == "1":
            # Encrypt-then-sign
            message = input("Enter message to encrypt (max 140 chars): ")[:140]
            ciphertext = encrypt_message(message, enc_public)
            signature = sign_message(ciphertext, sig_private)
            
            # Save ciphertext and signature to files
            with open("ciphertext.bin", "wb") as f:
                f.write(ciphertext)
            with open("signature.bin", "wb") as f:
                f.write(signature)
            
            print("\nMessage encrypted and signed. Ciphertext and signature saved to files.")
            print("Ciphertext (hex):", binascii.hexlify(ciphertext).decode('ascii'))
            print("Signature (hex):", binascii.hexlify(signature).decode('ascii'))
            print(f"\nCiphertext length: {len(ciphertext)} bytes")
            print(f"Signature length: {len(signature)} bytes")
        
        elif choice == "2":
            # Verify-then-decrypt
            try:
                with open("ciphertext.bin", "rb") as f:
                    ciphertext = f.read()
                with open("signature.bin", "rb") as f:
                    signature = f.read()
                
                # Verify signature
                if verify_signature(ciphertext, signature, sig_public):
                    print("Signature verified successfully.")
                    # Decrypt message
                    plaintext = decrypt_message(ciphertext, enc_private)
                    print(f"Decrypted message: {plaintext}")
                else:
                    print("Message verification failed. Decryption aborted.")
            
            except FileNotFoundError:
                print("Ciphertext or signature file not found.")
        
        elif choice == "3":
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()