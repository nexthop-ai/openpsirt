#include "include/shared.h"
#include <string.h>

int leak(int n) {
    char *buf = malloc(n);
    if (n > 10) {
        return 1;
    }
    free(buf);
    return header_div(n);
}

int div_zero(int x) {
    int d = 0;
    return x / d;
}
