// collapse_failures.c
// Esempi di CFG che possono causare fallimenti di regole in CollapseStructure::collapseInternal()

#include <stdio.h>

void TestWhiles() {
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
    {
        int x = 20;
        while (x > 0) {
            printf("While decremento: x = %d\n", x);
            x -= 2;
        }
    }
    {
        int i = 0;
        while (1) {
            if (i >= 5) break;
            printf("While con break: i = %d\n", i);
            i++;
        }
    }
    {
        int i = 0;
        while (i < 10) {
            i++;
            if (i % 2 == 0) continue;
            printf("While con continue: i dispari = %d\n", i);
        }
    }
    {
        int i = 0;
        while (i < 3) {
            int j = 0;
            while (j < 2) {
                printf("While annidato: i = %d, j = %d\n", i, j);
                j++;
            }
            i++;
        }
    }
    {
        int a = 2, b = 3;
        while ((a + b) < 20 && (b < 10)) {
            printf("While condizionale: a = %d, b = %d\n", a, b);
            a += 2;
            b += 1;
        }
    }
}

void TestFors() {
    for (int i = 0; i < 5; i++) {
        printf("For classico: i = %d\n", i);
    }
    for (int i = 0; i < 20; i += 3) {
        printf("For multiplo: i = %d\n", i);
    }
    for (int i = 0, j = 10; i < j; i++, j--) {
        printf("For variabili multiple: i = %d, j = %d\n", i, j);
    }
    for (int i = 0; i < 10; i++) {
        if (i % 3 == 0) continue;
        printf("For con continue: i = %d\n", i);
    }
    {
        int i = 0;
        for ( ; i < 5; ) {
            if(i == 3) {
                i++;
                continue;
            }
            printf("For vuoto: i = %d\n", i);
            i++;
        }
    }
}


int main(void) {
    printf("=== TestWhiles ===\n");
    TestWhiles();
    printf("=== TestFors ===\n");
    TestFors();
    return 0;
}
