// VA=0x1000
void __cdecl _init( void )
{
    if( __gmon_start__ != 0 ) {
        __gmon_start__();
    }
}

// VA=0x102c
void __cdecl func_0x102C( void )
{
    goto data_0x3F88;
}

// VA=0x103e
void __cdecl func_0x103E( void )
{
    goto data_0x3F88;
}

// VA=0x104e
void __cdecl func_0x104E( void )
{
    goto data_0x3F88;
}

// VA=0x105e
void __cdecl func_0x105E( void )
{
    goto data_0x3F88;
}

// VA=0x106e
void __cdecl func_0x106E( void )
{
    goto data_0x3F88;
}

// VA=0x107e
void __cdecl func_0x107E( void )
{
    goto data_0x3F88;
}

// VA=0x108e
void __cdecl func_0x108E( void )
{
    goto data_0x3F88;
}

// VA=0x109e
void __cdecl func_0x109E( void )
{
    goto data_0x3F88;
}

// VA=0x10ae
void __cdecl func_0x10AE( void )
{
    goto data_0x3F88;
}

// VA=0x10c0
void __cdecl __cxa_finalize_2( int64_t p1 )
{
    goto __cxa_finalize;
}

// VA=0x10d0
int __cdecl puts_2( char * __s )
{
    goto puts_1;
}

// VA=0x10e0
double __cdecl pow_2( double __x, double __y )
{
    goto pow_1;
}

// VA=0x10f0
noreturn void __cdecl __stack_chk_fail_2( void )
{
    goto __stack_chk_fail_1;
}

// VA=0x1100
int __cdecl system_2( char * __command )
{
    goto system_1;
}

// VA=0x1110
double __cdecl cos_2( double __x )
{
    goto cos_1;
}

// VA=0x1120
double __cdecl tan_2( double __x )
{
    goto tan_1;
}

// VA=0x1130
void __cdecl __printf_chk_2( int32_t p1, int64_t p2 )
{
    goto __printf_chk;
}

// VA=0x1140
double __cdecl sin_2( double __x )
{
    goto sin_1;
}

// VA=0x1150
void __cdecl __isoc99_scanf_2( int64_t p1, int64_t p2 )
{
    goto __isoc99_scanf;
}

// VA=0x1160
int32_t __cdecl main( void )
{
    askdo();
    return 0;
}

// VA=0x1180
noreturn void __cdecl _start( void )
{
    int64_t return_address; // [rsp+0]
     stack_0x8; // [rsp+8]
    int64_t rax; // rax
    int64_t rdx; // rdx

    __libc_start_main( &main, return_address, &stack_0x8, 0, 0, rdx, (&stack_0x8 & 0xFFFFFFFFFFFFFFF0) - 8, rax );
    __asm.hlt();
    // Note: Program behavior is undefined if control flow reaches this location.
}

// VA=0x11b0
void __cdecl deregister_tm_clones( void )
{
}

// VA=0x11e0
void __cdecl register_tm_clones( void )
{
}

// VA=0x1220
void __cdecl __do_global_dtors_aux( void )
{
    if( completed.0 == 0 ) {
        if( __cxa_finalize != 0 ) {
            __cxa_finalize_2( __dso_handle );
        }
        deregister_tm_clones();
        completed.0 = 1;
        return;
    }
}

// VA=0x1270
int64_t __cdecl askdo( void )
{
    uint32_t local_0x50; // [rsp-80]
    uint64_t local_0x48; // [rsp-72]
    uint16_t local_0x3A; // [rsp-58]
    uint64_t local_0x38; // [rsp-56]
    uint64_t local_0x20; // [rsp-32]
    int64_t st0; // st0
    int64_t st1; // st1
    int64_t st2; // st2
    void * fs; // fs
    double v4; // zmm0
    double v3; // zmm0
    double v2; // zmm0
    double v1; // zmm0

    local_0x20 = *((uint8_t *)fs + 40);
    system_2( "clear" );
    puts_2( &data_0x2078 );
    __printf_chk_2( 2, &data_0x201A );
    __printf_chk_2( 2, &data_0x2078 );
    puts_2( "\n0. Clear all\n1. Addition\n2. Subtraction\n3. Multiplication\n4. Division\n5. sin (deg)\n6. cos (deg)\n7.tan (deg)\n8. n Power\n9. n Root" );
    __printf_chk_2( 2, "Enter function option number/memory input num>9: " );
    __isoc99_scanf_2( "%Lf", &askdo_input );
    __asm.fld( askdo_input );
    __asm.fldz();
    __asm.fld( st0 );
    __asm.fxch( st0, st2 );
    __asm.fucomi( st0, st2 );
    __asm.fstp( st2 );
    __asm.fstp( st0 );
    __asm.fld( 1092616192 );
    __asm.fxch( st0, st1 );
    __asm.fcomi( st0, st1 );
    __asm.fstp( st1 );
    __asm.fld( st0 );
    __asm.fstp( result );
    __asm.fstp( memory );
    system_2( "clear" );
    askdo();
    __asm.fldz();
    __asm.fld( memory );
    __asm.fucomip( st0, st1 );
    __asm.fstp( st0 );
    __printf_chk_2( 2, "Enter performing number:" );
    __isoc99_scanf_2( "%Lf", &func_name );
    __asm.fld( askdo_input );
    __asm.fnstcw( local_0x3A );
    __asm.fldcw( (uint16_t)(uint32_t)local_0x3A & 0xFFFFFFFFFFFF00FF | (uint8_t)(local_0x3A >> 8 | 0xC) << 8 );
    __asm.fistp( local_0x50 );
    __asm.fldcw( local_0x3A );
    if( local_0x50 > 9 ) {
        __asm.fld( result );
    } else {
        switch( local_0x50 ) {
            case 0: {
                __asm.fld( result );
                __asm.fstp( memory );
                system_2( "clear" );
                askdo();
                if( *((uint8_t *)fs + 40) == local_0x20 ) {
                    return 0;
                }
                __stack_chk_fail_2();
                // Note: Program behavior is undefined if control flow reaches this location.
                return;
            }
            case 1: {
                __asm.fld( memory );
                __asm.fld( func_name );
                __asm.faddp( st1, st0 );
                __asm.fld( st0 );
                __asm.fstp( result );
                break;
            }
            case 2: {
                __asm.fld( memory );
                __asm.fld( func_name );
                __asm.fsubp( st1, st0 );
                __asm.fld( st0 );
                __asm.fstp( result );
                break;
            }
            case 3: {
                __asm.fld( memory );
                __asm.fld( func_name );
                __asm.fmulp( st1, st0 );
                __asm.fld( st0 );
                __asm.fstp( result );
                break;
            }
            case 4: {
                __asm.fld( memory );
                __asm.fld( func_name );
                __asm.fdivp( st1, st0 );
                __asm.fld( st0 );
                __asm.fstp( result );
                break;
            }
            case 5: {
                __asm.fld( func_name );
                __asm.fdiv( 4633260481409690083 );
                __asm.fstp( local_0x50 );
                v1 = sin_2( 0 );
                __asm.fld( v1 );
                __asm.fld( st0 );
                __asm.fstp( result );
                break;
            }
            case 6: {
                __asm.fld( func_name );
                __asm.fdiv( 4633260481409690083 );
                __asm.fstp( local_0x50 );
                v2 = cos_2( 0 );
                __asm.fld( v2 );
                __asm.fld( st0 );
                __asm.fstp( result );
                break;
            }
            case 7: {
                __asm.fld( func_name );
                __asm.fdiv( 4633260481409690083 );
                __asm.fstp( local_0x50 );
                v3 = tan_2( 0 );
                __asm.fld( v3 );
                __asm.fld( st0 );
                __asm.fstp( result );
                break;
            }
            default: {
                switch( local_0x50 ) {
                    case 8: {
                        __printf_chk_2( 2, "Enter exponent value: " );
                        __isoc99_scanf_2( "%Lf", &local_0x38 );
                        __asm.fld( local_0x38 );
                        break;
                    }
                    case 9: {
                        __printf_chk_2( 2, "Enter root cap value: " );
                        __isoc99_scanf_2( "%Lf", &local_0x38 );
                        __asm.fld1();
                        __asm.fld( local_0x38 );
                        __asm.fdivp( st1, st0 );
                        break;
                    }
                    default: {
                        __asm.fld( result );
                        __asm.fstp( memory );
                        system_2( "clear" );
                        askdo();
                        if( *((uint8_t *)fs + 40) == local_0x20 ) {
                            return 0;
                        }
                        __stack_chk_fail_2();
                        // Note: Program behavior is undefined if control flow reaches this location.
                        return;
                    }
                }
                __asm.fstp( local_0x50 );
                __asm.fld( func_name );
                __asm.fstp( local_0x48 );
                v4 = pow_2( 0, 0 );
                __asm.fld( v4 );
                __asm.fld( st0 );
                __asm.fstp( result );
                break;
            }
        }
    }
    __asm.fstp( memory );
    system_2( "clear" );
    askdo();
    if( *((uint8_t *)fs + 40) == local_0x20 ) {
        return 0;
    }
    __stack_chk_fail_2();
    // Note: Program behavior is undefined if control flow reaches this location.
}

// VA=0x1690
int64_t __cdecl repeat( void )
{
    int64_t v1; // rax

    __asm.fld( result );
    __asm.fstp( memory );
    system_2( "clear" );
    return askdo();
}

// VA=0x16c0
inline void __cdecl _fini( void )
{
}

// VA=0x4060
void __unknown __libc_start_main_1( void )
{
    goto &__libc_start_main_1;
}

// VA=0x4068
void __unknown _ITM_deregisterTMCloneTable_1( void )
{
    goto &_ITM_deregisterTMCloneTable_1;
}

// VA=0x4070
void __unknown __gmon_start___1( void )
{
    goto &__gmon_start___1;
}

// VA=0x4078
void __unknown _ITM_registerTMCloneTable_1( void )
{
    goto &_ITM_registerTMCloneTable_1;
}

// VA=0x4080
void __unknown __cxa_finalize_1( void )
{
    goto &__cxa_finalize_1;
}

// VA=0x4088
int __cdecl puts( char * __s )
{
    goto &puts;
}

// VA=0x4090
double __cdecl pow( double __x, double __y )
{
    goto &pow;
}

// VA=0x4098
noreturn void __cdecl __stack_chk_fail( void )
{
    goto &__stack_chk_fail;
}

// VA=0x40a0
int __cdecl system( char * __command )
{
    goto &system;
}

// VA=0x40a8
double __cdecl cos( double __x )
{
    goto &cos;
}

// VA=0x40b0
double __cdecl tan( double __x )
{
    goto &tan;
}

// VA=0x40b8
void __unknown __printf_chk_1( void )
{
    goto &__printf_chk_1;
}

// VA=0x40c0
double __cdecl sin( double __x )
{
    goto &sin;
}

// VA=0x40c8
void __unknown __isoc99_scanf_1( void )
{
    goto &__isoc99_scanf_1;
}


