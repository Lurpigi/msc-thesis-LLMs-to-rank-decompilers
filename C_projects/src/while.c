#include <stdio.h>

int main(void) {
    printf("=== TestWhiles ===\n");
    {
        int a;
        scanf("%d", &a);
        int i = 0;
        while (a < 10) {
            printf("While semplice: i = %d, a = %d\n", i, a);
            a++;
            i++;
        }
    }
    return 0;
}
