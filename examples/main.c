#include <stdio.h>
#include <stdlib.h>

void (*un_init_func_table[16])(int) = {0};

void second_gate(int x, int y){
    if( x + y == 0)
        un_init_func_table[x](y);
    else
        return;
}

void second_gate_dup(int x, int y){
    if( x + y != 0)
        un_init_func_table[x](y);
    else
        return;
}

void (*init_func_table[16])(int, int) = {second_gate, second_gate_dup, 0};

void target(int x){
    printf("Target!\n");
}

int origin_flow(void (*arg_func)(int, int), int num){
    printf("we point the %p! and arg is %d! WOW!\n", arg_func, num);
    return 0;
}

int first_gate(void (*arg_func)(int, int), int num){
    if(num == -1)
        return -1;
    if(num == 0)
        arg_func(num, 0);
    else
        init_func_table[0](num, -1);
    return 0;
}

void third_gate(int x){
    if(x == 0)
        target(x);
    else
        return;
}

int vuln(){
    // vuln_ptr is attacker controlled value, but because of CFI, it can only call the origin_flow and first_gate
    int (*vuln_ptr)(void (*)(int, int), int) = origin_flow;
    printf("first gate is %p, second gate is %p\n", first_gate, second_gate);
    scanf("%p", &vuln_ptr);

    // Attacker can also control the args!
    void (*arg_func)(int,int) = 0;
    scanf("%p", &arg_func);
    int arg_num = 0;
    scanf("%d", &arg_num);

    vuln_ptr(arg_func, arg_num);
    return 0;
}

int init_table_on_runtime(){
    un_init_func_table[0] = third_gate;
    return 0;
}

int main(){
    init_table_on_runtime();
    second_gate_dup(0,0);
    return vuln();
}