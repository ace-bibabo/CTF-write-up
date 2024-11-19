## ROP

```
+----------------------+  <---- High address (stack bottom)         
|    system address    |  # Jump to system function
+----------------------+
|    /bin/sh address   |  # Argument for system function
+----------------------+
|(pop rdi; ret)addr    |  <---- Low address (stack top)     
+----------------------+
```

# Step-by-Step ROP Chain Construction and Execution

## 1. Stack Layout
   - **Top of the Stack (`RSP` points here)**: Place the address of the `"/bin/sh"` string here.
   - **Above it**: Place the address of the `system` function.

## 2. Execution Process
   - **Control Flow**: The control flow is redirected to the `pop rdi; ret` gadget, so the instruction pointer (`RIP`) now points to this gadget.
   
   - **Step 1 - `pop rdi`**: 
     - This gadget executes `pop rdi`, which takes the value at the current `RSP` address (i.e., the `"/bin/sh"` address) and stores it in the `rdi` register.
     - After `pop rdi` executes, `RSP` moves up by 8 bytes (one stack entry), now pointing to the `system` function’s address.

   - **Step 2 - `ret`**: 
     - Next, `ret` pops the new top of the stack, which is now the `system` address, and jumps to it, transferring control to `system`.

## 3. Executing `system("/bin/sh")`
   - When the `system` function is called, `rdi` already contains the address of `"/bin/sh"` as its first argument. Thus, `system("/bin/sh")` is executed, opening a shell.

---

In summary, this ROP chain redirects control to `system` with `"/bin/sh"` as its argument by carefully manipulating the stack and using `pop rdi; ret`. This is the core process of ROP: using gadgets to load specific registers and redirect control flow to achieve a desired function call.
