# [Easy Peasy](https://play.picoctf.org/practice/challenge/125?category=2&page=1&search=)

> This is an OTP (One Time Password) CTF (Capture The Flag), where the encryption process is defined in such a way that encrypted_msg = encrypt (msg, key), where 'key' is a random or time-based value, somewhat akin to adding salt in hashing.

> A one-time password (OTP), also known as a one-time PIN, one-time authorization code (OTAC) or dynamic password, is a password that is valid for only one login session or transaction, on a computer system or other digital device. OTPs avoid several shortcomings that are associated with traditional (static) password-based authentication; a number of implementations also incorporate two-factor authentication by ensuring that the one-time password requires access to something a person has (such as a small keyring fob device with the OTP calculator built into it, or a smartcard or specific cellphone) as well as something a person knows (such as a PIN).

* from the encrypted flag's length = 64, while the original length should be 32 characters. This is due to the following line in the code:
 
```
result = list(map(lambda p, k: "{:02x}".format(ord(p) ^ k), flag, key)
```
* We can deduce that the encryption algorithm used is: encrypted_msg = key ^ msg Since the XOR (^) operation is reversible, we can calculate the key as key = msg ^ encrypted_msg
With this information, the solution becomes clearer:
Obtain the key using: key = msg ^ enrcypted_msg
Use the obtained key to decrypt the flag with flag = key ^ encrypted_flag
 

```

from pwn import *

KEY_LEN = 50000

def decrypt(text, flag, key_location, encrypt_text):
    print(text, flag, key_location, encrypt_text)
    real_flag = ""

    for k in range(key_location):
        # hexadecimal to decimal
        word = int(text[k * 2:k * 2 + 2], 16)
        encrypt_word = int(encrypt_text[k * 2:k * 2 + 2], 16)
        # print(word, encrypt_word)
        key = word ^ ord(flag[k])
        # print('encrypt_word {} key {} {}'.format(encrypt_word, key, chr(key)))
        real_flag += chr(encrypt_word ^ key)
    print(real_flag)


if __name__ == '__main__':
    key_location = 32

    io = connect("mercury.picoctf.net", 36981)
    io.recvuntil("This is the encrypted flag!\n")
    encrypt_text = str(io.recvline(), "ascii").strip()
    io.sendlineafter("What data would you like to encrypt? ", "a" * (key_len - key_location))

    pretend_flag = "a" * 32
    io.sendlineafter("What data would you like to encrypt? ", pretend_flag)
    io.recvuntil("Here ya go!\n")
    pretend_text = str(io.recvline(), "ascii").strip()
    # print(encrypt_text, text)

    decrypt(pretend_text, pretend_flag, key_location, encrypt_text)
 


```
~~~
 picoCTF{7f9da29f40499a98db220380a57746a4}
~~~