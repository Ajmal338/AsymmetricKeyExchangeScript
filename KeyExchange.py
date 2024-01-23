from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_keypair():
    """
    Generate a new RSA keypair
    """
    return rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=65537,
        key_size=2048
    )