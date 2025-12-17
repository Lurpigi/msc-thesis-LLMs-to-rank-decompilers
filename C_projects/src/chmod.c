#include <stdio.h>

void foo(int a1){
    if(a1 > 0){
        printf("positive");
    }else{
        printf("non positive");
    }
}


int main(){
    int a1;
    scanf("%d", &a1);
    foo(a1);
    return 0;
}