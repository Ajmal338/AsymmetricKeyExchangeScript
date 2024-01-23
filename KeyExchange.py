from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def generate_keypair():
    """
    Generate a new RSA keypair
    """
    return rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=65537,
        key_size=2048
    )

def serialize_public_key(public_key):
    """
    Serialize the public key to send it over the network
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Encrypt and Decrypt functions for the RSA key pair:

def encrypt_with_public_key(public_key, plaintext):
    """
    Encrypt the plaintext with the public key
    """
    encrypted = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_with_private_key(private_key, ciphertext):
    """
    Decrypt the ciphertext with the private key
    """
    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    except ValueError:
        print("Invalid key or ciphertext")
        return None
    
#-----------------------------------------------------------
    
def generate_symmetric_key():
    """
    Generate a symmetric key
    """
    return Fernet.generate_key()

# Encrypt and Decrypt functions for the symmetric key:

def encrypt_with_symmetric_key(symmetric_key, plaintext):
    """
    Encrypt the plaintext with the symmetric key
    """
    f = Fernet(symmetric_key)
    return f.encrypt(plaintext)

def decrypt_with_symmetric_key(symmetric_key, ciphertext):
    """
    Decrypt the ciphertext with the symmetric key
    """
    f = Fernet(symmetric_key)
    return f.decrypt(ciphertext)

if __name__ == "__main__":
    alice_private_key = generate_keypair()
    alice_public_key = alice_private_key.public_key()
    alice_public_key_pem = serialize_public_key(alice_public_key)

    bob_private_key = generate_keypair()
    bob_public_key = bob_private_key.public_key()
    bob_public_key_pem = serialize_public_key(bob_public_key)

    # Alice generates a symmetric key and encrypts it with Bob's public key
    symmetric_key = generate_symmetric_key()
    encrypted_symmetric_key = encrypt_with_public_key(bob_public_key, symmetric_key)

    # Bob decrypts the symmetric key with his private key
    decrypted_symmetric_key = decrypt_with_private_key(bob_private_key, encrypted_symmetric_key)

    # Now Alice and Bob can use the symmetric key to encrypt and decrypt messages
    message = "If you can read this message, we share the symmetric key!"
    encrypted_message = encrypt_with_symmetric_key(symmetric_key, message)
    decrypted_message = decrypt_with_symmetric_key(decrypted_symmetric_key, encrypted_message)

    print("Decrypted message:", decrypted_message)