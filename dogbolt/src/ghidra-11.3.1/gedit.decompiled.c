#include "out.h"



void _DT_INIT(void)

{
  __gmon_start__();
  return;
}



void FUN_00101020(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



void __cxa_finalize(void)

{
  __cxa_finalize();
  return;
}



void g_application_run(void)

{
  g_application_run();
  return;
}



void g_type_check_instance_cast(void)

{
  g_type_check_instance_cast();
  return;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void gedit_dirs_get_gedit_locale_dir(void)

{
  gedit_dirs_get_gedit_locale_dir();
  return;
}



void bindtextdomain(void)

{
  bindtextdomain();
  return;
}



void bind_textdomain_codeset(void)

{
  bind_textdomain_codeset();
  return;
}



void g_object_add_weak_pointer(void)

{
  g_object_add_weak_pointer();
  return;
}



void g_application_get_type(void)

{
  g_application_get_type();
  return;
}



void g_object_run_dispose(void)

{
  g_object_run_dispose();
  return;
}



void gedit_debug_message(void)

{
  gedit_debug_message();
  return;
}



void gedit_dirs_init(void)

{
  gedit_dirs_init();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * setlocale(int __category,char *__locale)

{
  char *pcVar1;
  
  pcVar1 = setlocale(__category,__locale);
  return pcVar1;
}



void gedit_app_get_type(void)

{
  gedit_app_get_type();
  return;
}



void g_object_new(void)

{
  g_object_new();
  return;
}



void textdomain(void)

{
  textdomain();
  return;
}



void g_object_unref(void)

{
  g_object_unref();
  return;
}



void gedit_dirs_shutdown(void)

{
  gedit_dirs_shutdown();
  return;
}



void gedit_settings_unref_singleton(void)

{
  gedit_settings_unref_singleton();
  return;
}



undefined4 main(undefined4 param_1,undefined8 param_2)

{
  undefined4 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  long lVar4;
  long in_FS_OFFSET;
  long local_38;
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  uVar2 = gedit_app_get_type();
  gedit_dirs_init();
  setlocale(6,"");
  uVar3 = gedit_dirs_get_gedit_locale_dir();
  bindtextdomain("gedit",uVar3);
  bind_textdomain_codeset("gedit",&DAT_00102004);
  textdomain("gedit");
  lVar4 = g_object_new(uVar2,"application-id","org.gnome.gedit","flags",0xc,0);
  local_38 = lVar4;
  uVar2 = g_application_get_type();
  uVar2 = g_type_check_instance_cast(lVar4,uVar2);
  uVar1 = g_application_run(uVar2,param_1,param_2);
  gedit_settings_unref_singleton();
  uVar2 = g_type_check_instance_cast(local_38,0x50);
  g_object_run_dispose(uVar2);
  uVar2 = g_type_check_instance_cast(local_38,0x50);
  g_object_add_weak_pointer(uVar2,&local_38);
  g_object_unref(local_38);
  if (local_38 != 0) {
    lVar4 = g_type_check_instance_cast(local_38,0x50);
    gedit_debug_message(0x100,"../gedit/gedit.c",0xa1,&DAT_00102055,"Leaking with %i refs",
                        *(undefined4 *)(lVar4 + 8));
  }
  gedit_dirs_shutdown();
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar1;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  __libc_start_main(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Removing unreachable block (ram,0x00101433)
// WARNING: Removing unreachable block (ram,0x0010143f)

void FUN_00101420(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00101474)
// WARNING: Removing unreachable block (ram,0x00101480)

void FUN_00101450(void)

{
  return;
}



void _FINI_0(void)

{
  if (_edata != '\0') {
    return;
  }
  __cxa_finalize(PTR_LOOP_00104008);
  FUN_00101420();
  _edata = 1;
  return;
}



void _INIT_0(void)

{
  FUN_00101450();
  return;
}



void _DT_FINI(void)

{
  return;
}



