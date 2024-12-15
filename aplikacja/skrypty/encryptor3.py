import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad

def encrypt(text, key):
    salt = get_random_bytes(16)
    iv = get_random_bytes(16)
    derived_key = scrypt(key.encode('utf-8'), salt, 32, N=2**14, r=8, p=1)
    
    if isinstance(text, str):
        text = text.encode('utf-8')
    
    padded_data = pad(text, AES.block_size)
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_b64 = base64.b64encode(salt + iv + encrypted_data).decode('utf-8')
    return encrypted_b64

def decrypt(text, key):
    encrypted_data = base64.b64decode(text)
    salt, iv, encrypted_content = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    derived_key = scrypt(key.encode('utf-8'), salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_content), AES.block_size)
    return decrypted_data.decode('utf-8')

def encrypt_file(file_path, output_path, key=None):
    with open(file_path, 'rb') as file:
        data = file.read()

    if key:
        salt = get_random_bytes(16)
        iv = get_random_bytes(16)
        derived_key = scrypt(key.encode('utf-8'), salt, 32, N=2**14, r=8, p=1)
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        encrypted_data = salt + iv + cipher.encrypt(pad(data, AES.block_size))
    else:
        iv = get_random_bytes(16)
        cipher = AES.new(get_random_bytes(32), AES.MODE_CBC, iv)
        encrypted_data = iv + cipher.encrypt(pad(data, AES.block_size))

    with open(output_path, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(file_path, output_path, key=None):
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    if key:
        salt, iv, encrypted_content = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        derived_key = scrypt(key.encode('utf-8'), salt, 32, N=2**14, r=8, p=1)
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_content), AES.block_size)
    else:
        raise ValueError("Key is required for decryption")

    with open(output_path, 'wb') as file:
        file.write(decrypted_data)
