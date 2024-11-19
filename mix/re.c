#include <stdio.h>

int compute_value(int var_c, int var_10) {
    int sum = var_c + var_10;
    int div_by_5 = sum / 5;
    int sign_bit = sum >> 31;
    int result = div_by_5 - sign_bit;
    result = result * 4;
    int final_result = sum - result;
    return final_result;
}

