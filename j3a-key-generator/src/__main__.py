import io
import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

if __name__ == "__main__":

    # Generate RSA private key    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Convert RSA private key to PEM PKCS8 format
    pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        #format = serialization.PrivateFormat.TraditionalOpenSSL,
        format = serialization.PrivateFormat.PKCS8,        
        encryption_algorithm = serialization.NoEncryption()
    )
    
    # Save private key to file 
    f = open('private.pem', 'wb+')
    f.write(pem)
    f.close()

    # Get public key from private key
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # save public key to file
    f = open('public.pem', 'wb+')
    f.write(pem)
    f.close()
