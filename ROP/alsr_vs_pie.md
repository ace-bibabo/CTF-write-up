**ALSR**: system level by checking

	
	cat /proc/sys/kernel/randomize_va_space
	

**PIE**: application level 




| Feature         | Stack Address | Heap Address | Shared Libraries | .text Section (Code) |
|-----------------|---------------|--------------|------------------|-----------------------|
| No ASLR, No PIE | Fixed         | Fixed        | Fixed           | Fixed                |
| ASLR, No PIE    | Randomized    | Randomized   | Randomized      | Fixed                |
| ASLR + PIE      | Randomized    | Randomized   | Randomized      | Randomized           |
