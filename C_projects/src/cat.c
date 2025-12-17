#include <stdio.h>

void test1(a1){
    printf("1");
    switch(a1){
        case 2: 
            printf("2");
            break;
        case 6:
            printf("6");
            break;
        case 125:
            printf("7");
            break;  
        default:
            printf("8");
    }
    printf("9");
    return;
}


void test2( int a1, int a2){
    printf("1");
    if(a1==1 && a2==1){
        printf("3");
    }else{
        printf("2");
        if( a1 != 1 ){
            printf("4");
            goto L1;
        }
    }
    printf("5");
L1:
    printf("6");
    return;

}

void test3( int a1, int a2){
    int a = a1;
    int b = a2;
    int c = a1+a2;
    printf("1");
    while(a < 100){
        printf("2");
        while(b < 20){
            printf("3");
            if(c < 50){
                goto L1; 
            }
            printf("4");
        }
    }
    L1:
    printf("5");
    return;
}

void test4(int a1, int a2){
    printf("1");
L1:
    while(a1 != 1){
        printf("2");
        if(a2 > 19){
            printf("7");
            return;
        }
    }
    printf("3");
    if(a2 > 4){
        goto L2;
    }
    printf("4");
    goto L3;
L2:
    printf("5");    
    if(a2 > 9){
L3:
        printf("6");
        goto L1;
    }
    
}

int main(){
    int a1,a2;
    scanf("%d", &a1);
    scanf("%d", &a2);

    test1(a1);
    test2(a1,a2);
    test3(a1,a2);
    test4(a1, a2);
    return 0;
    
}