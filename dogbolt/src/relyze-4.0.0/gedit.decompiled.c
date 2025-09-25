// VA=0x102d
void __cdecl func_0x102D( void )
{
    goto data_0x3F40;
}

// VA=0x103f
void __cdecl func_0x103F( void )
{
    goto data_0x3F40;
}

// VA=0x104f
void __cdecl func_0x104F( void )
{
    goto data_0x3F40;
}

// VA=0x105f
void __cdecl func_0x105F( void )
{
    goto data_0x3F40;
}

// VA=0x106f
void __cdecl func_0x106F( void )
{
    goto data_0x3F40;
}

// VA=0x107f
void __cdecl func_0x107F( void )
{
    goto data_0x3F40;
}

// VA=0x108f
void __cdecl func_0x108F( void )
{
    goto data_0x3F40;
}

// VA=0x109f
void __cdecl func_0x109F( void )
{
    goto data_0x3F40;
}

// VA=0x10af
void __cdecl func_0x10AF( void )
{
    goto data_0x3F40;
}

// VA=0x10bf
void __cdecl func_0x10BF( void )
{
    goto data_0x3F40;
}

// VA=0x10cf
void __cdecl func_0x10CF( void )
{
    goto data_0x3F40;
}

// VA=0x10df
void __cdecl func_0x10DF( void )
{
    goto data_0x3F40;
}

// VA=0x10ef
void __cdecl func_0x10EF( void )
{
    goto data_0x3F40;
}

// VA=0x10ff
void __cdecl func_0x10FF( void )
{
    goto data_0x3F40;
}

// VA=0x110f
void __cdecl func_0x110F( void )
{
    goto data_0x3F40;
}

// VA=0x111f
void __cdecl func_0x111F( void )
{
    goto data_0x3F40;
}

// VA=0x112f
void __cdecl func_0x112F( void )
{
    goto data_0x3F40;
}

// VA=0x113f
void __cdecl func_0x113F( void )
{
    goto data_0x3F40;
}

// VA=0x1150
void __cdecl __cxa_finalize_2( int64_t p1 )
{
    goto __cxa_finalize;
}

// VA=0x1160
int32_t __cdecl g_application_run_2( int64_t p1, int32_t p2, int64_t p3 )
{
    goto g_application_run;
}

// VA=0x1170
int64_t __cdecl g_type_check_instance_cast_2( int64_t p1, int32_t p2 )
{
    goto g_type_check_instance_cast;
}

// VA=0x1180
noreturn void __cdecl __stack_chk_fail_2( void )
{
    goto __stack_chk_fail_1;
}

// VA=0x1190
int64_t __cdecl gedit_dirs_get_gedit_locale_dir_2( void )
{
    goto gedit_dirs_get_gedit_locale_dir;
}

// VA=0x11a0
void __cdecl bindtextdomain_2( int64_t p1, int64_t p2 )
{
    goto bindtextdomain;
}

// VA=0x11b0
void __cdecl bind_textdomain_codeset_2( int64_t p1, int64_t p2 )
{
    goto bind_textdomain_codeset;
}

// VA=0x11c0
void __cdecl g_object_add_weak_pointer_2( int64_t p1, int64_t p2 )
{
    goto g_object_add_weak_pointer;
}

// VA=0x11d0
int64_t __cdecl g_application_get_type_2( void )
{
    goto g_application_get_type;
}

// VA=0x11e0
void __cdecl g_object_run_dispose_2( int64_t p1 )
{
    goto g_object_run_dispose;
}

// VA=0x11f0
void __cdecl gedit_debug_message_2( int32_t p1, int64_t p2, int32_t p3, int64_t p4, int64_t p5, int32_t p6 )
{
    goto gedit_debug_message;
}

// VA=0x1200
void __cdecl gedit_dirs_init_2( void )
{
    goto gedit_dirs_init;
}

// VA=0x1210
char * __cdecl setlocale_2( int __category, char * __locale )
{
    goto setlocale_1;
}

// VA=0x1220
int64_t __cdecl gedit_app_get_type_2( void )
{
    goto gedit_app_get_type;
}

// VA=0x1230
int64_t __cdecl g_object_new_2( int64_t p1, int64_t p2, int64_t p3, int64_t p4, int32_t p5, int32_t p6 )
{
    goto g_object_new;
}

// VA=0x1240
void __cdecl textdomain_2( int64_t p1 )
{
    goto textdomain;
}

// VA=0x1250
void __cdecl g_object_unref_2( int64_t p1 )
{
    goto g_object_unref;
}

// VA=0x1260
void __cdecl gedit_dirs_shutdown_2( void )
{
    goto gedit_dirs_shutdown;
}

// VA=0x1270
void __cdecl gedit_settings_unref_singleton_2( void )
{
    goto gedit_settings_unref_singleton;
}

// VA=0x1280
int64_t __cdecl main( int32_t p1, int64_t p2 )
{
    int64_t local_0x38; // [rsp-56]
    uint64_t local_0x30; // [rsp-48]
    void * fs; // fs
    int64_t v1; // rax
    int64_t v2; // rax
    int64_t v3; // rax
    int32_t v4; // rax
    int64_t v5; // rax
    int32_t v6; // rax
    int64_t v7; // rax
    int64_t v8; // rax
    int64_t v9; // rax

    local_0x30 = *((uint8_t *)fs + 40);
    v1 = gedit_app_get_type_2();
    gedit_dirs_init_2();
    setlocale_2( 6, 8201 );
    v2 = gedit_dirs_get_gedit_locale_dir_2();
    bindtextdomain_2( 8218, v2 );
    bind_textdomain_codeset_2( 8218, "UTF-8" );
    textdomain_2( 8218 );
    v3 = g_object_new_2( v1, "application-id", "org.gnome.gedit", "flags", 12, 0 );
    local_0x38 = v3;
    v4 = g_application_get_type_2();
    v5 = g_type_check_instance_cast_2( v3, v4 );
    v6 = g_application_run_2( v5, (uint32_t)p1, p2 );
    gedit_settings_unref_singleton_2();
    v7 = g_type_check_instance_cast_2( v3, 80 );
    g_object_run_dispose_2( v7 );
    v8 = g_type_check_instance_cast_2( v3, 80 );
    g_object_add_weak_pointer_2( v8, &local_0x38 );
    g_object_unref_2( local_0x38 );
    if( local_0x38 != 0 ) {
        v9 = g_type_check_instance_cast_2( local_0x38, 80 );
        gedit_debug_message_2( 256, "../gedit/gedit.c", 161, "main", "Leaking with %i refs", *(v9 + 8) );
    }
    gedit_dirs_shutdown_2();
    if( *((uint8_t *)fs + 40) == local_0x30 ) {
        return (uint32_t)v6;
    }
    __stack_chk_fail_2();
    // Note: Program behavior is undefined if control flow reaches this location.
}

// VA=0x13f0
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

// VA=0x1420
void __cdecl func_0x1420( void )
{
}

// VA=0x1450
void __cdecl func_0x1450( void )
{
}

// VA=0x1490
void __cdecl func_0x1490( void )
{
    if( _edata == 0 ) {
        if( __cxa_finalize != 0 ) {
            __cxa_finalize_2( data_0x4008 );
        }
        func_0x1420();
        _edata = 1;
        return;
    }
}

// VA=0x14d0
void __cdecl func_0x14D0( void )
{
    func_0x1450();
}

// VA=0x4018
void __unknown _ITM_deregisterTMCloneTable_1( void )
{
    goto &_ITM_deregisterTMCloneTable_1;
}

// VA=0x4020
void __unknown __cxa_finalize_1( void )
{
    goto &__cxa_finalize_1;
}

// VA=0x4028
void __unknown __gmon_start___1( void )
{
    goto &__gmon_start___1;
}

// VA=0x4030
void __unknown _ITM_registerTMCloneTable_1( void )
{
    goto &_ITM_registerTMCloneTable_1;
}

// VA=0x4038
void __unknown __libc_start_main_1( void )
{
    goto &__libc_start_main_1;
}

// VA=0x4040
void __unknown g_application_run_1( void )
{
    goto &g_application_run_1;
}

// VA=0x4048
void __unknown g_type_check_instance_cast_1( void )
{
    goto &g_type_check_instance_cast_1;
}

// VA=0x4050
noreturn void __cdecl __stack_chk_fail( void )
{
    goto &__stack_chk_fail;
}

// VA=0x4058
void __unknown gedit_dirs_get_gedit_locale_dir_1( void )
{
    goto &gedit_dirs_get_gedit_locale_dir_1;
}

// VA=0x4060
void __unknown bindtextdomain_1( void )
{
    goto &bindtextdomain_1;
}

// VA=0x4068
void __unknown bind_textdomain_codeset_1( void )
{
    goto &bind_textdomain_codeset_1;
}

// VA=0x4070
void __unknown g_object_add_weak_pointer_1( void )
{
    goto &g_object_add_weak_pointer_1;
}

// VA=0x4078
void __unknown g_application_get_type_1( void )
{
    goto &g_application_get_type_1;
}

// VA=0x4080
void __unknown g_object_run_dispose_1( void )
{
    goto &g_object_run_dispose_1;
}

// VA=0x4088
void __unknown gedit_debug_message_1( void )
{
    goto &gedit_debug_message_1;
}

// VA=0x4090
void __unknown gedit_dirs_init_1( void )
{
    goto &gedit_dirs_init_1;
}

// VA=0x4098
char * __cdecl setlocale( int __category, char * __locale )
{
    goto &setlocale;
}

// VA=0x40a0
void __unknown gedit_app_get_type_1( void )
{
    goto &gedit_app_get_type_1;
}

// VA=0x40a8
void __unknown g_object_new_1( void )
{
    goto &g_object_new_1;
}

// VA=0x40b0
void __unknown textdomain_1( void )
{
    goto &textdomain_1;
}

// VA=0x40b8
void __unknown g_object_unref_1( void )
{
    goto &g_object_unref_1;
}

// VA=0x40c0
void __unknown gedit_dirs_shutdown_1( void )
{
    goto &gedit_dirs_shutdown_1;
}

// VA=0x40c8
void __unknown gedit_settings_unref_singleton_1( void )
{
    goto &gedit_settings_unref_singleton_1;
}


