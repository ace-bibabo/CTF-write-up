# [substitude teacher]()


* The encryption used is p = Polynomial([1, 2, 1]), which means f(x) = 1x^2 + 2x + x. If we have f(x) which is the spicy flag, we can calculate x as the original character. Consequently, we obtain COMP6841{g?M??_?0?T}.
* You might wonder why there are "?" characters in the result. This occurs because we need to encrypt and determine if it matches the original encrypted flag. These five "?" characters can't be directly converted back to the char in the spicy flag.
How to obtain these "?" characters? The answer is brute forcing each "?" by truncating the encrypted flag. Since the alphabet is the hint, finally we can obtain the flag.
 





* crack code here

```
import numpy as np
from numpy.polynomial import Polynomial

alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}_1234567890"


def encrypt(flag, encrypt_file="", from_file=True):
    p = Polynomial([1, 2, 1])

    if from_file:
        with open(flag, "rb") as f, open(encrypt_file, "w") as g:
            plaintext = f.read().strip()
            encrypt_text = "".join(chr(int(p(c))) for c in plaintext)
            g.write(encrypt_text)
            return encrypt_text
    else:
        if len(flag) == 1:
            encrypt_char = chr(int(p(ord(flag))))
            return encrypt_char
        else:
            encrypt_text = "".join(chr(int(p(ord(c)))) for c in flag)
            return encrypt_text


def toFlag(flag_file, w_file):
    real_flag = ''
    coefficients = [1, 2, 1]
    with open(flag_file, "rb") as f, open(w_file, "w") as g:
        FLAG_test = f.read().strip()
        FLAG = FLAG_test.decode()
        for char_, char_test in zip(list(FLAG), list(FLAG_test)):

            target_value = ord(char_)
            # print("char_ is {}  char_test {} target_val is {}".format(char_, char_test, target_value))

            equation = np.poly1d(coefficients) - target_value
            # print("equation is {} ".format(equation))

            solutions = np.roots(equation)
            for s in solutions:
                if int(s) <= 0:
                    continue
                if int(s) >= 0:
                    i = int(s)
                    decrypt_i = chr(i)
                    encrypt_verify = encrypt(decrypt_i, "", False)
                    if char_ != encrypt_verify:
                        real_flag += "?"
                    else:
                        real_flag += decrypt_i

        g.write(real_flag)
        return real_flag, FLAG


if __name__ == '__main__':
    flag, orgin_flag = toFlag("spicy_flag.txt", "flag.txt")
    encrypted_flag = encrypt("flag.txt", "spicy_flag_2.txt")
    print(flag, orgin_flag, encrypted_flag)

    while orgin_flag != encrypted_flag:
        print("current flag is {}".format(flag))
        for alpha in alphabet:
            idx = flag.index("?")
            truncated_origin_flag = orgin_flag[:idx + 1]
            truncated_flag = flag[:idx] + alpha
            encrypted_t_flag = encrypt(truncated_flag, "", False)

            if truncated_origin_flag == encrypted_t_flag:
                flag = flag[:idx] + alpha + flag[idx + 1:]
                encrypted_flag = encrypted_t_flag + encrypted_flag[idx + 1:]
                break
            else:
                continue

    print(flag, orgin_flag, encrypted_flag, orgin_flag == encrypted_flag)
```


* the log 

```
COMP6841{g?M??_?0?T} ሐᤀោᦡ௑ಱૹৄ㰐⩀⯤ោ⽄⢤␀㎩ॡ㄀᰹㸄 ሐᤀោᦡ௑ಱૹৄ㰐⩀ကោကက␀ကॡက᰹㸄
current flag is COMP6841{g?M??_?0?T}
current flag is COMP6841{giM??_?0?T}
current flag is COMP6841{giMm?_?0?T}
current flag is COMP6841{giMme_?0?T}
current flag is COMP6841{giMme_r0?T}
COMP6841{giMme_r0oT} ሐᤀោᦡ௑ಱૹৄ㰐⩀⯤ោ⽄⢤␀㎩ॡ㄀᰹㸄 ሐᤀោᦡ௑ಱૹৄ㰐⩀⯤ោ⽄⢤␀㎩ॡ㄀᰹㸄 True
```


> flag: COMP6841{giMme_r0oT}
