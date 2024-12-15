import math

def create_triangle_structure(message):
    n = int(math.ceil((-1 + math.sqrt(1 + 8 * len(message))) / 2))
    triangle = []
    index = 0

    for row in range(1, n + 1):
        if index + row <= len(message):
            triangle.append(list(message[index:index + row]))
        else:
            triangle.append(list(message[index:] + ' ' * (row - (len(message) - index))))
        index += row

    return triangle


def encrypt(message):
    message = message.replace(' ', '')
    triangle = create_triangle_structure(message)
    print("szyfrowania:")
    for row in triangle:
        print(' '.join(row))
    
    encrypted_message = []
    num_columns = len(triangle[-1]) 

   
    for col in range(num_columns):
        for row in triangle:
            if col < len(row) and row[col] != ' ':
                encrypted_message.append(row[col])
    
    return ''.join(encrypted_message)

def decrypt(encrypted_message):
    n = int(math.ceil((-1 + math.sqrt(1 + 8 * len(encrypted_message))) / 2))
    triangle = create_triangle_structure(' ' * len(encrypted_message))
    
    index = 0
    num_columns = len(triangle[-1]) 

    
    for col in range(num_columns):
        for row in triangle:
            if col < len(row) and index < len(encrypted_message):
                row[col] = encrypted_message[index]
                index += 1

    print("odszyfrowywania:")
    for row in triangle:
        print(' '.join(row))

    
    decrypted_message = []
    for row in triangle:
        decrypted_message.extend([char for char in row if char != ' '])

    return ''.join(decrypted_message)
