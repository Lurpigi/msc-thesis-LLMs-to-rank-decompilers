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

void __cxa_finalize(void* d)
{
    /* tailcall */
    return __cxa_finalize(d);
}

int32_t __printf_chk(int32_t flag, char const* format, ...)
{
    /* tailcall */
    return __printf_chk(flag, format);
}

int32_t main()
{
    __printf_chk(1, "sleep");
    return 0x2a;
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

int foo() __pure
{
    return 0x2a;
}

int64_t _fini() __pure
{
    return;
}

