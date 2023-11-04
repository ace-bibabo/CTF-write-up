from numpy.polynomial import Polynomial

#alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}_1234567890"

def encrypt(plaintext):
    f = Polynomial([1, 2, 1])
    return "".join(chr(int(f(c))) for c in plaintext)

with open("flag.txt", "rb") as f, open("spicy_flag.txt", "w") as g:
    FLAG = f.read().strip()
    enc = encrypt(FLAG)
    g.write(enc)