#include <stdio.h>

int main() {
    for (int i = 0; i < 10; i++) {
        //printf("altroprintf");
        if (i % 3 == 0) continue;
        printf("For con continue: i = %d\n", i);
    }
    return 0;
}