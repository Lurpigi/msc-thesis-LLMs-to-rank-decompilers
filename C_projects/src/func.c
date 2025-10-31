// collapse_failures.c
// Esempi di CFG che possono causare fallimenti di regole in CollapseStructure::collapseInternal()

#include <stdio.h>

// Tutti gli esempi con while in una sola funzione
void TestWhiles() {
    // 1. While semplice con incremento
    {
        int a = 10;
        int i = 0;
        while (a < 10) {
            printf("While semplice: i = %d, a = %d\n", i, a);
            a++;
            i++;
        }
    }
    // 2. While con decremento
    {
        int x = 20;
        while (x > 0) {
            printf("While decremento: x = %d\n", x);
            x -= 2;
        }
    }
    // 3. While con break
    {
        int i = 0;
        while (1) {
            if (i >= 5) break;
            printf("While con break: i = %d\n", i);
            i++;
        }
    }
    // 4. While con continue
    {
        int i = 0;
        while (i < 10) {
            i++;
            if (i % 2 == 0) continue;
            printf("While con continue: i dispari = %d\n", i);
        }
    }
    // 5. While annidato
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
    // 6. While con condizione complessa
    {
        int a = 2, b = 3;
        while ((a + b) < 20 && (b < 10)) {
            printf("While condizionale: a = %d, b = %d\n", a, b);
            a += 2;
            b += 1;
        }
    }
}

// Tutti gli esempi con for in una sola funzione
void TestFors() {
    // 1. For classico con incremento
    for (int i = 0; i < 5; i++) {
        printf("For classico: i = %d\n", i);
    }
    // 2. For con incremento multiplo
    for (int i = 0; i < 20; i += 3) {
        printf("For multiplo: i = %d\n", i);
    }
    // 3. For con variabili multiple
    for (int i = 0, j = 10; i < j; i++, j--) {
        printf("For variabili multiple: i = %d, j = %d\n", i, j);
    }
    // 4. For con continue
    for (int i = 0; i < 10; i++) {
        if (i % 3 == 0) continue;
        printf("For con continue: i = %d\n", i);
    }
    // 5. For con loop “vuoto” nell’inizializzazione o aggiornamento
    {
        int i = 0;
        for ( ; i < 5; ) {
            printf("For vuoto: i = %d\n", i);
            i++;
        }
    }
}

// Le tue funzioni originali (modificate leggermente per compatibilità con le nuove)
void WhileSemplice() {
    int a = 10;
    int i = 0;
    while (a < 10) {
        printf("whileSemplice Iterazione: %d con a = %d\n", i, a);
        a++;
        i++;
    }
}

void CheckDelFor() {
    int a = 10;
    for (int i = 0; i < 10; ) {
        i++;
        printf("CheckDelFor Iterazione: %d con a = %d\n", i, a);
        a++;
    }

    int b = 5;
    for (int i = 0; i < 10; i++) {
        printf("CheckDelFor Iterazione: %d con b = %d\n", i, b);
        b++;
    }

    for (; b < a; b++) {
        printf("CheckDelFor Iterazione con b = %d\n", b);
    }
}

int main(void) {
    printf("=== TestWhiles ===\n");
    TestWhiles();
    printf("=== TestFors ===\n");
    TestFors();
    printf("=== WhileSemplice (originale) ===\n");
    WhileSemplice();
    printf("=== CheckDelFor (originale) ===\n");
    CheckDelFor();
    return 0;
}
