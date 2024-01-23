from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

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