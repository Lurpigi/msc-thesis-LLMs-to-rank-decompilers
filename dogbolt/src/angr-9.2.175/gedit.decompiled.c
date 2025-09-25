typedef struct struct_0 {
    struct struct_0 *field_0;
} struct_0;

extern struct_0 *g_403fe8;

long long sub_401000()
{
    struct_0 **v1;  // rax

    v1 = g_403fe8;
    if (g_403fe8)
        v1 = g_403fe8();
    return v1;
}

extern unsigned long long g_403f38;
extern unsigned long long g_403f40;

void sub_401020()
{
    unsigned long v0;  // [bp-0x8]

    v0 = g_403f38;
    goto g_403f40;
}

void sub_401030()
{
    void* v0;  // [bp-0x8]

    v0 = 0;
    sub_401020();
    return;
}

void sub_401040()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 1;
    sub_401020();
    return;
}

void sub_401050()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 2;
    sub_401020();
    return;
}

void sub_401060()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 3;
    sub_401020();
    return;
}

void sub_401070()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 4;
    sub_401020();
    return;
}

void sub_401080()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 5;
    sub_401020();
    return;
}

void sub_401090()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 6;
    sub_401020();
    return;
}

void sub_4010a0()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 7;
    sub_401020();
    return;
}

void sub_4010b0()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 8;
    sub_401020();
    return;
}

void sub_4010c0()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 9;
    sub_401020();
    return;
}

void sub_4010d0()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 10;
    sub_401020();
    return;
}

void sub_4010e0()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 11;
    sub_401020();
    return;
}

void sub_4010f0()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 12;
    sub_401020();
    return;
}

void sub_401100()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 13;
    sub_401020();
    return;
}

void sub_401110()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 14;
    sub_401020();
    return;
}

void sub_401120()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 15;
    sub_401020();
    return;
}

void sub_401130()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 16;
    sub_401020();
    return;
}

void sub_401140()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 17;
    sub_401020();
    return;
}

typedef struct struct_0 {
    char padding_0[8];
    unsigned int field_8;
} struct_0;

extern char g_402009;

int main(unsigned int a0, unsigned long long a1)
{
    unsigned long long v0;  // [bp-0x38]
    unsigned long long v2;  // rax
    unsigned long long v3;  // rdx
    unsigned long long v4;  // rcx
    unsigned long long v5;  // r8
    unsigned long long v6;  // r9
    unsigned long long v8;  // rax
    unsigned long long v9;  // rax
    unsigned int v10;  // eax
    unsigned long long v13;  // rdi
    struct_0 *v14;  // rax

    v2 = gedit_app_get_type();
    gedit_dirs_init(a0, a1, v3, v4, v5, v6);
    setlocale(6, &g_402009);
    bindtextdomain("gedit", gedit_dirs_get_gedit_locale_dir(a0, a1, v3, v4, v5, v6));
    bind_textdomain_codeset("gedit", "UTF-8");
    textdomain("gedit");
    v8 = g_object_new(v2, "application-id", "org.gnome.gedit", "flags", 12, 0);
    v0 = v8;
    v9 = g_application_get_type(a0, a1, v3, v4, v5, v6, v8);
    v10 = g_application_run(g_type_check_instance_cast(v8, v9), a0, a1);
    gedit_settings_unref_singleton(a0, a1, v3, v4, v5, v6);
    g_object_run_dispose(g_type_check_instance_cast(v0, 80));
    g_object_add_weak_pointer(g_type_check_instance_cast(v0, 80), &v0);
    g_object_unref(v0);
    v13 = v0;
    if (v13)
    {
        v14 = g_type_check_instance_cast(v13, 80);
        gedit_debug_message(0x100, "../gedit/gedit.c", 161, "main", "Leaking with %i refs", v14->field_8);
    }
    gedit_dirs_shutdown(v13);
    return v10;
}

void _start(unsigned long a0, unsigned long a1, unsigned long long a2)
{
    unsigned long long v1;  // [bp+0x0]
    unsigned long v2;  // [bp+0x8]
    unsigned long long v3;  // rax

    v1 = v3;
    __libc_start_main(main, v1, &(char)v2, 0, 0, a2, &v1, v1); /* do not return */
}

void sub_401415()
{
    [D] Unsupported jumpkind Ijk_SigTRAP at address 4199445()
}

void sub_401416()
{
    sub_401420();
    return;
}


void sub_401420()
{
    return;
}


long long sub_401449()
{
    return 0;
}

extern char __bss_start;
extern unsigned long long g_403fe0;
extern unsigned long long g_404008;

void sub_401490()
{
    if (__bss_start)
        return;
    if (g_403fe0)
        __cxa_finalize(g_404008);
    sub_401420();
    __bss_start = 1;
    return;
}

void sub_4014d0()
{
}

void sub_4014dc()
{
    return;
}

