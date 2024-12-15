import random, base64
from math import gcd


#p: 
# 53058221213493778594726184931460202103315917243288071207792611324133601065112492804582868759943663936178570333485715421100038508726256465838113544193776948111157502137529261781895798105364978489149993221003658209278476995457379183180242121376868444160314303419822795721533147683882478572777570750675248836819
#q:
# 144345197537721346597046304015706506128918365173106913154170733054668875762266582312467460258103981874271418146368389276565511142663245020927496808019264193890682028765589155274006002558456186059052245267650631820684010942683414768603842076907891426971898503718054608401759155868842926624056386535984366126529

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_prime(b):
    if b <= 1:
        raise ValueError("Długość bitowa musi być większa niż 1")

    min_value = 1 << (b - 1)
    max_value = (1 << b) - 1

    while True:
        candidate = random.randint(min_value, max_value)
        if is_prime(candidate):
            return candidate

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

def mod_inverse(e, phi):
    g, x, _ = egcd(e, phi)
    if g != 1:
        raise Exception("Odwrotność modularna nie istnieje")
    return x % phi

def generate_rsa_keys(p, q):
    if p == q:
        raise ValueError("Liczby pierwsze p i q muszą być różne.")
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        raise ValueError("e i phi nie są względnie pierwsze.")
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def encrypt_rsa(plain_text, public_key):
    e, n = public_key
    return [pow(ord(char), e, n) for char in plain_text]

def decrypt_rsa(encrypted_text, private_key):
    d, n = private_key
    return ''.join([chr(pow(char, d, n)) for char in encrypted_text])


def generate_dh_keys(p, g):
    private_key = random.randint(2, p - 2)  
    public_key = pow(g, private_key, p)     
    return private_key, public_key

def compute_shared_key(public_key_other, private_key, p):
    return pow(public_key_other, private_key, p) 


def encrypt_file(file_path, output_path, public_key):
    e, n = public_key

    with open(file_path, 'rb') as file:
        data = file.read()
    base64_data = base64.b64encode(data).decode('utf-8')

    max_block_size = (n.bit_length() // 8) - 1 
    encrypted_blocks = []

    for i in range(0, len(base64_data), max_block_size):
        block = base64_data[i:i + max_block_size]
        encrypted_block = encrypt_rsa(block, public_key)
        encrypted_blocks.extend(encrypted_block)

    with open(output_path, 'w') as file:
        file.write(' '.join(map(str, encrypted_blocks)))

def decrypt_file(file_path, output_path, private_key):
    d, n = private_key

    with open(file_path, 'r') as file:
        encrypted_data = list(map(int, file.read().split()))

    try:
        decrypted_blocks = [chr(pow(char, d, n)) for char in encrypted_data]
    except ValueError as e:
        raise ValueError(f"Błąd deszyfrowania: {e}")

    decrypted_blocks = decrypt_rsa(encrypted_data, private_key)
    decrypted_data = ''.join(decrypted_blocks).rstrip('\0')

    original_data = base64.b64decode(decrypted_data.encode('utf-8'))

    with open(output_path, 'wb') as file:
        file.write(original_data)
