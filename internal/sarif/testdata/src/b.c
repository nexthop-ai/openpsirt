#include "include/shared.h"

int use_after_free(void) {
    int *p = malloc(sizeof *p);
    free(p);
    return *p + header_div(1);
}

int also_divides(void) {
    return header_div(2);
}
