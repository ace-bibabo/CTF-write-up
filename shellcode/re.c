#include <stdio.h>

int main(int argc, char *argv[]) {
    int var_b = 0;
    
    if (var_b <= 9) {
        if ((var_b & 1) == 0) {
            printf("%d\n", var_b);
        }
    }

    var_b += 1;
    
    return 1;
}

