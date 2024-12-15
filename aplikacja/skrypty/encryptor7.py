from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os

def generate_keys(private_key_file="private_key.pem", public_key_file="public_key.pem"):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    with open(private_key_file, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(public_key_file, "wb") as key_file:
        key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def sign_file(file_path, private_key_file="private_key.pem"):
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    with open(file_path, "rb") as f:
        data = f.read()

    # Tworzenie podpisu
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    signature_file = f"{file_path}.sig"
    with open(signature_file, "wb") as sig_file:
        sig_file.write(signature)

    return signature_file


def verify_signature(file_path, signature_path, public_key_file="public_key.pem"):
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    with open(file_path, "rb") as f:
        data = f.read()

    with open(signature_path, "rb") as sig_file:
        signature = sig_file.read()

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        return False
    
