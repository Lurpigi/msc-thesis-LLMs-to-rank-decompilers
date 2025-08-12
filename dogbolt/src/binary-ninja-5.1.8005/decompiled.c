int64_t (* const)() _init()
{
    if (!__gmon_start__)
        return __gmon_start__;
    
    return __gmon_start__();
}

int64_t sub_401020()
{
    int64_t var_8 = 0;
    /* jump -> nullptr */
}

int64_t sub_401030()
{
    int64_t var_8 = 0;
    /* tailcall */
    return sub_401020();
}

int64_t sub_401040()
{
    int64_t var_8 = 1;
    /* tailcall */
    return sub_401020();
}

int64_t sub_401050()
{
    int64_t var_8 = 2;
    /* tailcall */
    return sub_401020();
}

int64_t sub_401060()
{
    int64_t var_8 = 3;
    /* tailcall */
    return sub_401020();
}

int64_t sub_401070()
{
    int64_t var_8 = 4;
    /* tailcall */
    return sub_401020();
}

int64_t sub_401080()
{
    int64_t var_8 = 5;
    /* tailcall */
    return sub_401020();
}

int64_t sub_401090()
{
    int64_t var_8 = 6;
    /* tailcall */
    return sub_401020();
}

int64_t sub_4010a0()
{
    int64_t var_8 = 7;
    /* tailcall */
    return sub_401020();
}

int64_t sub_4010b0()
{
    int64_t var_8 = 8;
    /* tailcall */
    return sub_401020();
}

void __cxa_finalize(void* d)
{
    /* tailcall */
    return __cxa_finalize(d);
}

int32_t puts(char const* str)
{
    /* tailcall */
    return puts(str);
}

double pow(double x, double y)
{
    /* tailcall */
    return pow(x, y);
}

void __stack_chk_fail() __noreturn
{
    /* tailcall */
    return __stack_chk_fail();
}

int32_t system(char const* line)
{
    /* tailcall */
    return system(line);
}

double cos(double arg1)
{
    /* tailcall */
    return cos(arg1);
}

double tan(double arg1)
{
    /* tailcall */
    return tan(arg1);
}

int32_t __printf_chk(int32_t flag, char const* format, ...)
{
    /* tailcall */
    return __printf_chk(flag, format);
}

double sin(double arg1)
{
    /* tailcall */
    return sin(arg1);
}

int32_t __isoc99_scanf(char const* format, ...)
{
    /* tailcall */
    return __isoc99_scanf(format);
}

int32_t main(int32_t argc, char** argv, char** envp)
{
    int16_t x87control;
    askdo(x87control);
    return 0;
}

void _start(int64_t arg1, int64_t arg2, void (* arg3)()) __noreturn
{
    int64_t stack_end_1;
    int64_t stack_end = stack_end_1;
    void ubp_av;
    __libc_start_main(main, __return_addr, &ubp_av, nullptr, nullptr, arg3, &stack_end);
    /* no return */
}

char* deregister_tm_clones()
{
    return &__TMC_END__;
}

int64_t (* const)() register_tm_clones()
{
    return nullptr;
}

void __do_global_dtors_aux()
{
    if (__TMC_END__)
        return;
    
    if (__cxa_finalize)
        __cxa_finalize(__dso_handle);
    
    deregister_tm_clones();
    __TMC_END__ = 1;
}

int64_t (* const)() frame_dummy()
{
    /* tailcall */
    return register_tm_clones();
}

int64_t askdo(int16_t arg1 @ x87control)
{
    void* fsbase;
    int64_t rax = *(fsbase + 0x28);
    system("clear");
    puts("\x1b[1;32m---------------------------------------\x1b[0m");
    char var_60 = *(memory + 8);
    char memory_1 = *memory;
    __printf_chk(2, "\x1b[1;32m%Lf\x1b[0m\n");
    __printf_chk(2, "\x1b[1;32m---------------------------------------\x1b[0m");
    puts("\n0. Clear all\n1. Addition\n2. Subtraction\n3. Multiplication\n4. Division\n5. sin (deg)"
    "6. cos (deg)\n7.tan (deg)\n8. n Power\n9. n Root");
    __printf_chk(2, "Enter function option number/memory input num>9: ");
    __isoc99_scanf("%Lf", &askdo_input);
    long double askdo_input_1 = askdo_input;
    long double askdo_input_5 = 0;
    askdo_input_1 - askdo_input_5;
    long double askdo_input_2;
    
    if (FCMP_UO(askdo_input_1, askdo_input_5))
        askdo_input_2 = askdo_input_5;
    else if (askdo_input_1 == askdo_input_5)
    {
        result = askdo_input_5;
        memory = result;
        system("clear");
        arg1 = askdo(arg1);
        askdo_input_2 = askdo_input;
    }
    else
        askdo_input_2 = askdo_input_5;
    
    long double x87_r6 = 10f;
    
    if (askdo_input_2 >= x87_r6)
    {
        result = x87_r6;
        memory = x87_r6;
        system("clear");
        arg1 = askdo(arg1);
    }
    
    long double x87_r7_2 = 0;
    long double memory_2 = memory;
    memory_2 - x87_r7_2;
    
    if (!FCMP_UO(memory_2, x87_r7_2) && !(memory_2 != x87_r7_2))
    {
        long double askdo_input_3 = askdo_input;
        long double x87_r6_2 = 2f;
        x87_r6_2 - askdo_input_3;
        char rax_6 = FCMP_O(x87_r6_2, askdo_input_3);
        long double x87_r6_3 = 1;
        
        if (x87_r6_2 != askdo_input_3)
            rax_6 = 0;
        
        x87_r6_3 - askdo_input_3;
        long double x87_r6_4 = 3f;
        char rdx_1 = FCMP_O(x87_r6_3, askdo_input_3);
        
        if (x87_r6_3 != askdo_input_3)
            rdx_1 = 0;
        
        char rax_7 = rax_6 | rdx_1;
        x87_r6_4 - askdo_input_3;
        rdx_1 = FCMP_O(x87_r6_4, askdo_input_3);
        
        if (x87_r6_4 != askdo_input_3)
            rdx_1 = 0;
        
        rax_7 |= rdx_1;
        
        if (rax_7)
        {
            __printf_chk(2, "Enter memory number/primary number:", rdx_1);
            __isoc99_scanf("%Lf", &memory);
        }
        else
        {
            long double x87_r6_5 = 4f;
            x87_r6_5 - askdo_input_3;
            rdx_1 = FCMP_O(x87_r6_5, askdo_input_3);
            
            if (x87_r6_5 == askdo_input_3)
                rax_7 = rdx_1;
            
            if (rax_7)
            {
                __printf_chk(2, "Enter memory number/primary number:", rdx_1);
                __isoc99_scanf("%Lf", &memory);
            }
        }
    }
    
    __printf_chk(2, "Enter performing number:");
    __isoc99_scanf("%Lf", &func_name);
    long double askdo_input_4 = askdo_input;
    int16_t x87status;
    int16_t temp0_2;
    temp0_2 = __fnstcw_memmem16(arg1);
    int16_t rax_12;
    *rax_12[1] = *temp0_2[1] | 0xc;
    int16_t x87control;
    int16_t x87status_1;
    x87control = __fldcw_memmem16(rax_12);
    int16_t x87control_1;
    int16_t x87status_2;
    x87control_1 = __fldcw_memmem16(temp0_2);
    uint64_t rax_13 = askdo_input_4;
    long double result_1;
    int32_t var_50;
    long double var_38;
    long double x87_r7_5;
    
    if (rax_13 > 9)
        result_1 = result;
    else
        switch (rax_13)
        {
            case 0:
            {
                result_1 = result;
                break;
            }
            case 1:
            {
                result_1 = memory + func_name;
                result = result_1;
                break;
            }
            case 2:
            {
                result_1 = memory - func_name;
                result = result_1;
                break;
            }
            case 3:
            {
                result_1 = memory * func_name;
                result = result_1;
                break;
            }
            case 4:
            {
                result_1 = memory / func_name;
                result = result_1;
                break;
            }
            case 5:
            {
                var_50 = func_name / 57.295779500000002;
                var_50 = sin(var_50);
                result_1 = var_50;
                result = result_1;
                break;
            }
            case 6:
            {
                var_50 = func_name / 57.295779500000002;
                var_50 = cos(var_50);
                result_1 = var_50;
                result = result_1;
                break;
            }
            case 7:
            {
                var_50 = func_name / 57.295779500000002;
                var_50 = tan(var_50);
                result_1 = var_50;
                result = result_1;
                break;
            }
            case 8:
            {
                __printf_chk(2, "Enter exponent value: ", &jump_table_402194);
                __isoc99_scanf("%Lf", &var_38);
                x87_r7_5 = var_38;
                goto label_4014ba;
            }
            case 9:
            {
                __printf_chk(2, "Enter root cap value: ", &jump_table_402194);
                __isoc99_scanf("%Lf", &var_38);
                x87_r7_5 = 1 / var_38;
            label_4014ba:
                var_50 = x87_r7_5;
                var_50 = pow(func_name, var_50);
                result_1 = var_50;
                result = result_1;
                break;
            }
        }
    memory = result_1;
    system("clear");
    askdo(x87control_1);
    *(fsbase + 0x28);
    
    if (rax == *(fsbase + 0x28))
        return 0;
    
    __stack_chk_fail();
    /* no return */
}

int64_t repeat()
{
    memory = result;
    system("clear");
    int16_t x87control;
    /* tailcall */
    return askdo(x87control);
}

int64_t _fini() __pure
{
    return;
}

