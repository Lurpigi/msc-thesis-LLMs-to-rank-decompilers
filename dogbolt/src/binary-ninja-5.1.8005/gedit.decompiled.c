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

int64_t sub_4010c0()
{
    int64_t var_8 = 9;
    /* tailcall */
    return sub_401020();
}

int64_t sub_4010d0()
{
    int64_t var_8 = 0xa;
    /* tailcall */
    return sub_401020();
}

int64_t sub_4010e0()
{
    int64_t var_8 = 0xb;
    /* tailcall */
    return sub_401020();
}

int64_t sub_4010f0()
{
    int64_t var_8 = 0xc;
    /* tailcall */
    return sub_401020();
}

int64_t sub_401100()
{
    int64_t var_8 = 0xd;
    /* tailcall */
    return sub_401020();
}

int64_t sub_401110()
{
    int64_t var_8 = 0xe;
    /* tailcall */
    return sub_401020();
}

int64_t sub_401120()
{
    int64_t var_8 = 0xf;
    /* tailcall */
    return sub_401020();
}

int64_t sub_401130()
{
    int64_t var_8 = 0x10;
    /* tailcall */
    return sub_401020();
}

int64_t sub_401140()
{
    int64_t var_8 = 0x11;
    /* tailcall */
    return sub_401020();
}

void __cxa_finalize(void* d)
{
    /* tailcall */
    return __cxa_finalize(d);
}

int64_t g_application_run()
{
    /* tailcall */
    return g_application_run();
}

int64_t g_type_check_instance_cast()
{
    /* tailcall */
    return g_type_check_instance_cast();
}

void __stack_chk_fail() __noreturn
{
    /* tailcall */
    return __stack_chk_fail();
}

int64_t gedit_dirs_get_gedit_locale_dir()
{
    /* tailcall */
    return gedit_dirs_get_gedit_locale_dir();
}

char* bindtextdomain(char const* domainname, char const* dirname)
{
    /* tailcall */
    return bindtextdomain(domainname, dirname);
}

char* bind_textdomain_codeset(char const* domainname, char const* codeset)
{
    /* tailcall */
    return bind_textdomain_codeset(domainname, codeset);
}

int64_t g_object_add_weak_pointer()
{
    /* tailcall */
    return g_object_add_weak_pointer();
}

int64_t g_application_get_type()
{
    /* tailcall */
    return g_application_get_type();
}

int64_t g_object_run_dispose()
{
    /* tailcall */
    return g_object_run_dispose();
}

int64_t gedit_debug_message()
{
    /* tailcall */
    return gedit_debug_message();
}

int64_t gedit_dirs_init()
{
    /* tailcall */
    return gedit_dirs_init();
}

char* setlocale(int32_t category, char const* locale, int64_t arg3, int64_t arg4, uint64_t arg5, ssize_t arg6, int32_t category, int32_t category)
{
    /* tailcall */
    return setlocale(category, locale, arg3, arg4, arg5, arg6, category, category);
}

int64_t gedit_app_get_type()
{
    /* tailcall */
    return gedit_app_get_type();
}

int64_t g_object_new()
{
    /* tailcall */
    return g_object_new();
}

char* textdomain(char const* domainname)
{
    /* tailcall */
    return textdomain(domainname);
}

int64_t g_object_unref()
{
    /* tailcall */
    return g_object_unref();
}

int64_t gedit_dirs_shutdown()
{
    /* tailcall */
    return gedit_dirs_shutdown();
}

int64_t gedit_settings_unref_singleton()
{
    /* tailcall */
    return gedit_settings_unref_singleton();
}

int32_t main(int32_t argc, char** argv, char** envp)
{
    void* fsbase;
    int64_t rax = *(fsbase + 0x28);
    int64_t rax_2 = gedit_app_get_type();
    int64_t rcx;
    int64_t rdx;
    uint64_t r8;
    ssize_t r9;
    rcx = gedit_dirs_init();
    int64_t var_38;
    setlocale(6, &data_402004[5], rdx, rcx, r8, r9, var_38, rax);
    bindtextdomain("gedit", gedit_dirs_get_gedit_locale_dir());
    bind_textdomain_codeset("gedit", "UTF-8");
    textdomain("gedit");
    int64_t rax_5 = g_object_new(rax_2, "application-id", "org.gnome.gedit", "flags", 0xc, 0);
    var_38 = rax_5;
    int32_t result =
        g_application_run(g_type_check_instance_cast(rax_5, g_application_get_type()), argc, argv);
    gedit_settings_unref_singleton();
    g_object_run_dispose(g_type_check_instance_cast(var_38, 0x50));
    g_object_add_weak_pointer(g_type_check_instance_cast(var_38, 0x50), &var_38);
    g_object_unref(var_38);
    int64_t rdi_8 = var_38;
    
    if (rdi_8)
        gedit_debug_message(0x100, "../gedit/gedit.c", 0xa1, "main", "Leaking with %i refs", 
            *(g_type_check_instance_cast(rdi_8, 0x50) + 8));
    
    gedit_dirs_shutdown();
    *(fsbase + 0x28);
    
    if (rax == *(fsbase + 0x28))
        return result;
    
    __stack_chk_fail();
    /* no return */
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
    return &__bss_start;
}

int64_t (* const)() sub_401450()
{
    return nullptr;
}

void _FINI_0()
{
    if (__bss_start)
        return;
    
    if (__cxa_finalize)
        __cxa_finalize(data_404008);
    
    deregister_tm_clones();
    __bss_start = 1;
}

int64_t (* const)() _INIT_0()
{
    /* tailcall */
    return sub_401450();
}

int64_t _fini() __pure
{
    return;
}

