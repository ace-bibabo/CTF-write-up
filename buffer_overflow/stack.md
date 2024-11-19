## stack 

* main{sum(a,b)}
* sum{c = a+b; return c}

```
# Stack (Before function call):
+--------------------+  
|      b (param)     |  <- esp (points to b, higher address)
+--------------------+  
|      a (param)     |  
+--------------------+  
|  Return address    |  <- pushed by the caller
+--------------------+  

# prologue
push %ebp
mov % esp, %ebp

+--------------------+  
|      b (param)     |  
+--------------------+  
|      a (param)     |  
+--------------------+  
|  Return address    |  
+--------------------+  
|   Old ebp (caller) |  <- esp, ebp (at this point, esp and ebp are equal)
+--------------------+  

# saving live registers
push %esi
push %edi
push %ebx
Stack:
+--------------------+  
|      b (param)     |  
+--------------------+  
|      a (param)     |  
+--------------------+  
|  Return address    |  
+--------------------+  
|   Old ebp (caller) |  
+--------------------+  
|       esi          |  <- esp after `push %esi`
+--------------------+  
|       edi          |  <- esp after `push %edi`
+--------------------+  
|       ebx          |  <- esp after `push %ebx`
+--------------------+  

# making room for c
sub $4, %esp
Stack:
+--------------------+  
|      b (param)     |  
+--------------------+  
|      a (param)     |  
+--------------------+  
|  Return address    |  
+--------------------+  
|   Old ebp (caller) |  
+--------------------+  
|       esi          |  
+--------------------+  
|       edi          |  
+--------------------+  
|       ebx          |  
+--------------------+  
|     (empty) c      |  <- esp (space for local variable `c`)
+--------------------+  

# move b to ebx
movl 12(%ebp), %ebx
Stack (unchanged):
+--------------------+  
|      b (param)     |  <- 12(%ebp)
+--------------------+  
|      a (param)     |  <- 8(%ebp)
+--------------------+  
|  Return address    |  
+--------------------+  
|   Old ebp (caller) |  
+--------------------+  
|       esi          |  
+--------------------+  
|       edi          |  
+--------------------+  
|       ebx (b)      |  <- esp
+--------------------+  

# a + b
add 8(%ebp), %ebx

Stack (unchanged):
+--------------------+  
|      b (param)     |  <- 12(%ebp)
+--------------------+  
|      a (param)     |  <- 8(%ebp)
+--------------------+  
|  Return address    |  
+--------------------+  
|   Old ebp (caller) |  
+--------------------+  
|       esi          |  
+--------------------+  
|       edi          |  
+--------------------+  
|       ebx (a+b)    |  <- esp
+--------------------+  

# moving a+b into c
movl %ebx, -16(%ebp)

Stack:
+--------------------+  
|      b (param)     |  
+--------------------+  
|      a (param)     |  
+--------------------+  
|  Return address    |  
+--------------------+  
|   Old ebp (caller) |  
+--------------------+  
|       esi          |  
+--------------------+  
|       edi          |  
+--------------------+  
|       ebx (a+b)    |  
+--------------------+  
|   c = a + b        |  <- esp (local variable `c`)
+--------------------+  

#move c into eax
molv -16 (%ebp), %eax

# clean up stack& restore
add $4, %esp
pop %ebx
pop %edi
pop %esi
Stack:
+--------------------+  
|      b (param)     |  
+--------------------+  
|      a (param)     |  
+--------------------+  
|  Return address    |  
+--------------------+  
|   Old ebp (caller) |  <- esp after pops
+--------------------+  

# epilogue
mov %ebp, % esp
pop %ebp
ret
Stack (after return):
+--------------------+  
|      b (param)     |  
+--------------------+  
|      a (param)     |  
+--------------------+  
|  Return address    |  <- esp after function return
+------
```