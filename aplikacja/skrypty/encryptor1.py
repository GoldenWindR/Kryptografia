import os
klucz = [2,-2,3,-7]
def encrypt(text):
    szyfrogram = ""
    indeks = -1
    for i in text:
        
        if indeks >= 3:
            indeks = 0
        else:
            indeks += 1
        if i.islower():
            litera =  ord(i) + klucz[indeks]
            if litera > ord('z'):
                litera -= 26 
            elif litera < ord('a'):
                litera += 26
        elif i.isupper():
            litera = ord(i) + klucz[indeks]
            if litera > ord('Z'):
                litera -= 26
            elif litera < ord('A'):
                litera += 26
        else:
            litera = ord(i) + klucz[indeks]
        szyfrogram += chr(litera)

    return szyfrogram


def decrypt(text):
    szyfrogram = ""
    indeks = -1
    for i in text:
        if indeks >= 3:
            indeks = 0
        else:
            indeks += 1
        if i.islower():
            litera = ord(i) - klucz[indeks]
            if litera > ord('z'):
                litera -= 26
            elif litera < ord('a'):
                litera += 26
        elif i.isupper():
            litera = ord(i) - klucz[indeks]
            if litera > ord('Z'):
                litera -= 26
            elif litera < ord('A'):
                litera += 26
        else:
            litera =  ord(i) - klucz[indeks]
        szyfrogram += chr(litera)

    return szyfrogram
