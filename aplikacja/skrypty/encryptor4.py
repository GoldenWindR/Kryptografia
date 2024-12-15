from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt(data, key):
    if isinstance(key, str):
        key = key.encode('utf-8')

    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes long")

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)

    if isinstance(data, str):
        data = data.encode('utf-8')

    encrypted_data = iv + cipher.encrypt(data)
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt(encrypted_data, key):
    if isinstance(key, str):
        key = key.encode('utf-8')

    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes long")

    encrypted_data_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_data_bytes[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    decrypted_data = cipher.decrypt(encrypted_data_bytes[AES.block_size:])
    return decrypted_data 