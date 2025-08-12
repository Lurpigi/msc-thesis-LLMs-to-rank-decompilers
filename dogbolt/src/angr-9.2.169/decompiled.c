typedef struct struct_0 {
    struct struct_0 *field_0;
} struct_0;

extern struct_0 *g_403fe8;

long long _init()
{
    struct_0 **v1;  // rax

    v1 = g_403fe8;
    if (g_403fe8)
        v1 = g_403fe8();
    return v1;
}

extern unsigned long long g_403f80;
extern unsigned long long g_403f88;

void sub_401020()
{
    unsigned long v0;  // [bp-0x8]

    v0 = g_403f80;
    goto g_403f88;
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

int main()
{
    askdo();
    return 0;
}

void _start(unsigned long a0, unsigned long a1, unsigned long long a2)
{
    unsigned long long v1;  // [bp+0x0]
    unsigned long v2;  // [bp+0x8]
    unsigned long long v3;  // rax

    v1 = v3;
    __libc_start_main(main, v1, &(char)v2, 0, 0, a2, &v1, v1); /* do not return */
}

void sub_4011a5()
{
    [D] Unsupported jumpkind Ijk_SigTRAP at address 4198821()
}


void deregister_tm_clones()
{
    return;
}


void register_tm_clones()
{
    return;
}

extern char __TMC_END__;
extern unsigned long long __dso_handle;
extern unsigned long long g_403ff8;

void __do_global_dtors_aux()
{
    if (__TMC_END__)
        return;
    if (g_403ff8)
        __cxa_finalize(__dso_handle);
    deregister_tm_clones();
    __TMC_END__ = 1;
    return;
}

void frame_dummy()
{
    register_tm_clones();
    return;
}

extern char g_40201a;
extern char g_402078;
extern unsigned int g_402194[4];
extern unsigned long long g_404058;
extern unsigned long long memory;

void askdo()
{
    unsigned long v0;  // [bp-0x68]
    unsigned long v1;  // [bp-0x60]
    unsigned int v2;  // [bp-0x50]
    unsigned short v3;  // [bp-0x3c]
    unsigned short v4;  // [bp-0x3a]
    unsigned int v6;  // eax
    unsigned long v7;  // cc_dep1
    unsigned long long v8;  // cc_ndep
    unsigned long v9;  // cc_dep1
    unsigned int v11;  // eax
    unsigned int v13;  // edx
    unsigned long v14;  // rax
    unsigned long v16;  // rdx
    char v18;  // al
    unsigned long v19;  // fpround

    system("clear");
    puts(&g_402078);
    v1 = g_404058;
    v0 = memory;
    __printf_chk(2, &g_40201a);
    __printf_chk(2, &g_402078);
    puts("\n0. Clear all\n1. Addition\n2. Subtraction\n3. Multiplication\n4. Division\n5. sin (deg)\n6. cos (deg)\n7.tan (deg)\n8. n Power\n9. n Root");
    __printf_chk(2, "Enter function option number/memory input num>9: ");
    __isoc99_scanf("%Lf");
    if ([D] unsupported_<class 'pyvex.expr.GetI'>())
    {
        [D] PutI(904:F64x8)[t2,0] = t5()
        [D] PutI(968:I8x8)[t2,0] = 0x01()
    }
    else
    {
        [D] PutI(904:F64x8)[t2,0] = t5()
        [D] PutI(968:I8x8)[t2,0] = 0x01()
    }
    v6 = v0;
    [D] PutI(904:F64x8)[t9,0] = t12()
    [D] PutI(968:I8x8)[t9,0] = 0x01()
    [D] PutI(904:F64x8)[t26,0] = t29()
    [D] PutI(968:I8x8)[t26,0] = 0x01()
    [D] PutI(904:F64x8)[t38,0] = t42()
    [D] PutI(968:I8x8)[t38,0] = 0x01()
    [D] PutI(904:F64x8)[t38,2] = t35()
    [D] PutI(968:I8x8)[t38,2] = 0x01()
    v7 = CmpF(([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan), ([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan)) & 69;
    [D] PutI(904:F64x8)[t70,2] = t71()
    [D] PutI(968:I8x8)[t70,2] = 0x01()
    [D] PutI(968:I8x8)[t70,0] = 0x00()
    if (((char)((CmpF(([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan), ([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan)) & 69) >> 2) & 1))
    {
        [D] PutI(904:F64x8)[t1,0] = t2()
        [D] PutI(968:I8x8)[t1,0] = 0x01()
        [D] PutI(968:I8x8)[t1,0] = 0x00()
    }
    else if (((char)v7 & 64))
    {
        [D] PutI(904:F64x8)[t0,0] = t1()
        [D] PutI(968:I8x8)[t0,0] = 0x01()
        [D] PutI(968:I8x8)[t0,0] = 0x00()
    }
    else
    {
        [D] PutI(904:F64x8)[t9,1] = t10()
        [D] PutI(968:I8x8)[t9,1] = 0x01()
        [D] PutI(968:I8x8)[t9,0] = 0x00()
        [D] amd64g_dirtyhelper_storeF80le(0x404030<64>, Reinterpret(F64->I64, ((([D] unsupported_<class 'pyvex.expr.GetI'>() != 0x0<8>)) ? ([D] unsupported_<class 'pyvex.expr.GetI'>()) : (nan<64>))))
        [D] PutI(968:I8x8)[t25,0] = 0x00()
        [D] PutI(904:F64x8)[t32,0] = t35()
        [D] PutI(968:I8x8)[t32,0] = 0x01()
        [D] amd64g_dirtyhelper_storeF80le(0x404050<64>, Reinterpret(F64->I64, ((([D] unsupported_<class 'pyvex.expr.GetI'>() != 0x0<8>)) ? ([D] unsupported_<class 'pyvex.expr.GetI'>()) : (nan<64>))))
        [D] PutI(968:I8x8)[t54,0] = 0x00()
        system("clear");
        v6 = (unsigned long long)askdo();
        if ([D] unsupported_<class 'pyvex.expr.GetI'>())
        {
            [D] PutI(904:F64x8)[t2,0] = t5()
            [D] PutI(968:I8x8)[t2,0] = 0x01()
        }
        else
        {
            [D] PutI(904:F64x8)[t2,0] = t5()
            [D] PutI(968:I8x8)[t2,0] = 0x01()
        }
    }
    if ([D] unsupported_<class 'pyvex.expr.GetI'>())
    {
        [D] PutI(904:F64x8)[t1,0] = t4()
        [D] PutI(968:I8x8)[t1,0] = 0x01()
    }
    else
    {
        [D] PutI(904:F64x8)[t1,0] = t4()
        [D] PutI(968:I8x8)[t1,0] = 0x01()
    }
    [D] PutI(904:F64x8)[t5,0] = t9()
    [D] PutI(968:I8x8)[t5,0] = 0x01()
    [D] PutI(904:F64x8)[t5,1] = t2()
    [D] PutI(968:I8x8)[t5,1] = 0x01()
    [D] PutI(904:F64x8)[t37,1] = t38()
    [D] PutI(968:I8x8)[t37,1] = 0x01()
    [D] PutI(968:I8x8)[t37,0] = 0x00()
    if ((CmpF(([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan), ([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan)) & 1))
    {
        [D] PutI(904:F64x8)[t0,0] = t1()
        [D] PutI(968:I8x8)[t0,0] = 0x01()
        [D] PutI(968:I8x8)[t0,0] = 0x00()
    }
    else
    {
        [D] PutI(904:F64x8)[t15,0] = t18()
        [D] PutI(968:I8x8)[t15,0] = 0x01()
        [D] amd64g_dirtyhelper_storeF80le(0x404030<64>, Reinterpret(F64->I64, ((([D] unsupported_<class 'pyvex.expr.GetI'>() != 0x0<8>)) ? ([D] unsupported_<class 'pyvex.expr.GetI'>()) : (nan<64>))))
        [D] PutI(968:I8x8)[t28,0] = 0x00()
        [D] amd64g_dirtyhelper_storeF80le(0x404050<64>, Reinterpret(F64->I64, ((([D] unsupported_<class 'pyvex.expr.GetI'>() != 0x0<8>)) ? ([D] unsupported_<class 'pyvex.expr.GetI'>()) : (nan<64>))))
        [D] PutI(968:I8x8)[t47,0] = 0x00()
        system("clear");
        v6 = (unsigned long long)askdo();
    }
    [D] PutI(904:F64x8)[t2,0] = t5()
    [D] PutI(968:I8x8)[t2,0] = 0x01()
    [D] PutI(904:F64x8)[t12,0] = t15()
    [D] PutI(968:I8x8)[t12,0] = 0x01()
    v9 = CmpF(([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan), ([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan)) & 69;
    [D] PutI(968:I8x8)[t28,0] = 0x00()
    [D] PutI(904:F64x8)[t42,0] = t43()
    [D] PutI(968:I8x8)[t42,0] = 0x01()
    [D] PutI(968:I8x8)[t42,0] = 0x00()
    if (!((char)((CmpF(([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan), ([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan)) & 69) >> 2) & 1) && !((char)v9 & 64))
    {
        if ([D] unsupported_<class 'pyvex.expr.GetI'>())
        {
            [D] PutI(904:F64x8)[t2,0] = t5()
            [D] PutI(968:I8x8)[t2,0] = 0x01()
        }
        else
        {
            [D] PutI(904:F64x8)[t2,0] = t5()
            [D] PutI(968:I8x8)[t2,0] = 0x01()
        }
        if ([D] unsupported_<class 'pyvex.expr.GetI'>())
        {
            [D] PutI(904:F64x8)[t1,0] = t4()
            [D] PutI(968:I8x8)[t1,0] = 0x01()
        }
        else
        {
            [D] PutI(904:F64x8)[t1,0] = t4()
            [D] PutI(968:I8x8)[t1,0] = 0x01()
        }
        [D] PutI(968:I8x8)[t23,0] = 0x00()
        [D] PutI(904:F64x8)[t44,0] = t47()
        [D] PutI(968:I8x8)[t44,0] = 0x01()
        v11 = (!((CmpF(([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan), ([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan)) & 69) >> 6 & 1) ? 0 : v6 & 0xffffff00 | (char)amd64g_calculate_condition(11, 0, (unsigned long long)(CmpF(([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan), ([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan)) & 69), 0, v8));
        [D] PutI(968:I8x8)[t72,0] = 0x00()
        [D] PutI(904:F64x8)[t86,0] = t89()
        [D] PutI(968:I8x8)[t86,0] = 0x01()
        v13 = (!((CmpF(([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan), ([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan)) & 69) >> 6 & 1) ? 0 : (unsigned int)v1 & 0xffffff00 | (char)amd64g_calculate_condition(11, 0, (unsigned long long)(CmpF(([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan), ([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan)) & 69), 0, v8));
        v14 = v11 | v13;
        [D] PutI(968:I8x8)[t128,0] = 0x00()
        v16 = (!((CmpF(([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan), ([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan)) & 69) >> 6 & 1) ? 0 : v13 & 0xffffff00 | (char)amd64g_calculate_condition(11, 0, (unsigned long long)(CmpF(([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan), ([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan)) & 69), 0, v8));
        if (!(char)v14 && !(char)v16)
        {
            if ([D] unsupported_<class 'pyvex.expr.GetI'>())
            {
                [D] PutI(904:F64x8)[t1,0] = t4()
                [D] PutI(968:I8x8)[t1,0] = 0x01()
            }
            else
            {
                [D] PutI(904:F64x8)[t1,0] = t4()
                [D] PutI(968:I8x8)[t1,0] = 0x01()
            }
            [D] PutI(968:I8x8)[t12,0] = 0x00()
            [D] PutI(904:F64x8)[t26,0] = t27()
            [D] PutI(968:I8x8)[t26,0] = 0x01()
            [D] PutI(968:I8x8)[t26,0] = 0x00()
            v18 = (((CmpF(([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan), ([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan)) & 69) >> 6 & 1) == 1 ? (unsigned int)v16 & 0xffffff00 | (char)amd64g_calculate_condition(11, 0, (unsigned long long)(CmpF(([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan), ([D] unsupported_<class 'pyvex.expr.GetI'>() ? [D] unsupported_<class 'pyvex.expr.GetI'>() : nan)) & 69), 0, v8) : (unsigned int)v14 & 0xffffff00 | (char)v14 | (char)v16);
            if (!v18)
                goto LABEL_4013ce;
        }
        else
        {
            [D] PutI(904:F64x8)[t0,0] = t1()
            [D] PutI(968:I8x8)[t0,0] = 0x01()
            [D] PutI(968:I8x8)[t0,0] = 0x00()
        }
        __printf_chk(2, "Enter memory number/primary number:");
        __isoc99_scanf("%Lf");
    }
LABEL_4013ce:
    __printf_chk(2, "Enter performing number:");
    __isoc99_scanf("%Lf");
    if ([D] unsupported_<class 'pyvex.expr.GetI'>())
    {
        [D] PutI(904:F64x8)[t2,0] = t5()
        [D] PutI(968:I8x8)[t2,0] = 0x01()
    }
    else
    {
        [D] PutI(904:F64x8)[t2,0] = t5()
        [D] PutI(968:I8x8)[t2,0] = 0x01()
    }
    v4 = amd64g_create_fpucw(v19 & 4294967295);
    v3 = v4 & 255 | ((char)(v4 >> 8) | 12) * 0x100;
    if ([D] unsupported_<class 'pyvex.expr.GetI'>())
    {
        v2 = [D] unsupported_<class 'pyvex.expr.GetI'>();
        [D] PutI(968:I8x8)[t7,0] = 0x00()
    }
    else
    {
        v2 = nan;
        [D] PutI(968:I8x8)[t7,0] = 0x00()
    }
    if (v2 <= 9)
    {
        goto (long long)(g_402194[v2] + (char *)&g_402194[0]);
    }
    else
    {
        if ([D] unsupported_<class 'pyvex.expr.GetI'>())
        {
            [D] PutI(904:F64x8)[t2,0] = t5()
            [D] PutI(968:I8x8)[t2,0] = 0x01()
        }
        else
        {
            [D] PutI(904:F64x8)[t2,0] = t5()
            [D] PutI(968:I8x8)[t2,0] = 0x01()
        }
        if ([D] unsupported_<class 'pyvex.expr.GetI'>())
        {
            [D] amd64g_dirtyhelper_storeF80le(0x404050<64>, Reinterpret(F64->I64, [D] unsupported_<class 'pyvex.expr.GetI'>()))
            [D] PutI(968:I8x8)[t5,0] = 0x00()
        }
        else
        {
            [D] amd64g_dirtyhelper_storeF80le(0x404050<64>, Reinterpret(F64->I64, nan<64>))
            [D] PutI(968:I8x8)[t5,0] = 0x00()
        }
        system("clear");
        askdo();
        return;
    }
}

void repeat()
{
    if ([D] unsupported_<class 'pyvex.expr.GetI'>())
    {
        [D] PutI(904:F64x8)[t2,0] = t5()
        [D] PutI(968:I8x8)[t2,0] = 0x01()
    }
    else
    {
        [D] PutI(904:F64x8)[t2,0] = t5()
        [D] PutI(968:I8x8)[t2,0] = 0x01()
    }
    if ([D] unsupported_<class 'pyvex.expr.GetI'>())
    {
        [D] amd64g_dirtyhelper_storeF80le(0x404050<64>, Reinterpret(F64->I64, [D] unsupported_<class 'pyvex.expr.GetI'>()))
        [D] PutI(968:I8x8)[t5,0] = 0x00()
    }
    else
    {
        [D] amd64g_dirtyhelper_storeF80le(0x404050<64>, Reinterpret(F64->I64, nan<64>))
        [D] PutI(968:I8x8)[t5,0] = 0x00()
    }
    system("clear");
    askdo();
    return;
}

void _fini()
{
    return;
}

