#include "out.h"



void _DT_INIT(void)

{
  __gmon_start__();
  return;
}



void FUN_00102020(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



void __cxa_finalize(void)

{
  __cxa_finalize();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void InitOutput(streambuf *param_1)

{
  InitOutput(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t strlen(char *__s)

{
  size_t sVar1;
  
  sVar1 = strlen(__s);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void CheckIfSimulateMode(CommandLine *param_1)

{
  CheckIfSimulateMode(param_1);
  return;
}



void __thiscall CommandLine::~CommandLine(CommandLine *this)

{
  ~CommandLine(this);
  return;
}



void dgettext(void)

{
  dgettext();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void Configuration::FindI(char *param_1,int *param_2)

{
  FindI(param_1,param_2);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void CheckIfCalledByScript(int param_1,char **param_2)

{
  CheckIfCalledByScript(param_1,param_2);
  return;
}



void __cxa_atexit(void)

{
  __cxa_atexit();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * operator_new(ulong param_1)

{
  void *pvVar1;
  
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void operator_delete(void *param_1,ulong param_2)

{
  operator_delete(param_1,param_2);
  return;
}



void __thiscall CommandLine::CommandLine(CommandLine *this)

{
  CommandLine(this);
  return;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ostream * std::__ostream_insert<char,std::char_traits<char>>
                    (ostream *param_1,char *param_2,long param_3)

{
  ostream *poVar1;
  
  poVar1 = __ostream_insert<char,std::char_traits<char>>(param_1,param_2,param_3);
  return poVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void DispatchCommandLine(CommandLine *param_1,vector *param_2)

{
  DispatchCommandLine(param_1,param_2);
  return;
}



void ParseCommandLine(void)

{
  ParseCommandLine();
  return;
}



void __thiscall std::ios_base::Init::Init(Init *this)

{
  Init(this);
  return;
}



void std::ios::clear(void)

{
  clear();
  return;
}



void _Unwind_Resume(void)

{
                    // WARNING: Subroutine does not return
  _Unwind_Resume();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void Configuration::CndSet(char *param_1,int param_2)

{
  CndSet(param_1,param_2);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void Configuration::Set(char *param_1,int *param_2)

{
  Set(param_1,param_2);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void InitSignals(void)

{
  InitSignals();
  return;
}



void FUN_001022e0(void)

{
  void *pvVar1;
  undefined8 *unaff_R12;
  
  pvVar1 = (void *)*unaff_R12;
  if (pvVar1 != (void *)0x0) {
    operator_delete(pvVar1,unaff_R12[2] - (long)pvVar1);
  }
                    // WARNING: Subroutine does not return
  _Unwind_Resume();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined2 FUN_00102300(int param_1,char **param_2)

{
  undefined2 uVar1;
  int iVar2;
  long in_FS_OFFSET;
  void *local_78 [2];
  long local_68;
  CommandLine local_58 [24];
  long local_40;
  
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  CommandLine::CommandLine(local_58);
                    // try { // try from 00102373 to 00102377 has its CatchHandler @ 00102465
  ParseCommandLine((vector *)local_78,local_58,0,&_config,&_system,param_1,param_2,FUN_001025c0,
                   FUN_00102630);
                    // try { // try from 00102394 to 00102451 has its CatchHandler @ 0010245c
  iVar2 = Configuration::FindI(__config,(int *)"quiet");
  if (iVar2 == 2) {
    Configuration::CndSet(__config,0x1033b2);
    Configuration::Set(__config,(int *)"quiet");
  }
  InitSignals();
  InitOutput(_DAT_001061f8);
  CheckIfCalledByScript(param_1,param_2);
  CheckIfSimulateMode(local_58);
  uVar1 = DispatchCommandLine(local_58,(vector *)local_78);
  if (local_78[0] != (void *)0x0) {
    operator_delete(local_78[0],local_68 - (long)local_78[0]);
  }
  CommandLine::~CommandLine(local_58);
  if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar1;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void _INIT_1(void)

{
  std::ios_base::Init::Init((Init *)&DAT_00105019);
  __cxa_atexit(std::ios_base::Init::~Init,&DAT_00105019,&PTR_LOOP_00105008);
  return;
}



void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  __libc_start_main(FUN_00102300,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Removing unreachable block (ram,0x00102513)
// WARNING: Removing unreachable block (ram,0x0010251f)

void FUN_00102500(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00102554)
// WARNING: Removing unreachable block (ram,0x00102560)

void FUN_00102530(void)

{
  return;
}



void _FINI_0(void)

{
  if (DAT_00105018 != '\0') {
    return;
  }
  __cxa_finalize(PTR_LOOP_00105008);
  FUN_00102500();
  DAT_00105018 = 1;
  return;
}



void _INIT_0(void)

{
  FUN_00102530();
  return;
}



undefined8 FUN_001025c0(void)

{
  char *__s;
  size_t sVar1;
  
  __s = (char *)dgettext(&DAT_00103289,
                         "Usage: apt [options] command\n\napt is a commandline package manager and provides commands for\nsearching and managing as well as querying information about packages.\nIt provides the same functionality as the specialized APT tools,\nlike apt-get and apt-cache, but enables options more suitable for\ninteractive use by default.\n"
                        );
  if (__s != (char *)0x0) {
    sVar1 = strlen(__s);
    std::__ostream_insert<char,std::char_traits<char>>((ostream *)&std::cout,__s,sVar1);
    return 1;
  }
  std::ios::clear((long)&std::cout + *(long *)(std::cout + -0x18),
                  *(uint *)(&_config + *(long *)(std::cout + -0x18)) | 1);
  return 1;
}



undefined8 * FUN_00102630(undefined8 *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  ulong uVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  long in_FS_OFFSET;
  byte bVar6;
  code *local_308 [3];
  char *local_2f0;
  code *local_2e8;
  undefined8 local_2e0;
  undefined *local_2d8;
  code *local_2d0;
  undefined8 local_2c8;
  char *local_2c0;
  code *local_2b8;
  undefined8 local_2b0;
  char *local_2a8;
  code *local_2a0;
  undefined8 local_298;
  char *local_290;
  code *local_288;
  undefined8 local_280;
  char *local_278;
  code *local_270;
  undefined8 local_268;
  char *local_260;
  code *local_258;
  undefined8 local_250;
  char *local_248;
  code *local_240;
  undefined8 local_238;
  char *local_230;
  code *local_228;
  undefined8 local_220;
  char *local_218;
  code *local_210;
  undefined8 local_208;
  char *local_200;
  code *local_1f8;
  undefined8 local_1f0;
  char *local_1e8;
  code *local_1e0;
  undefined8 local_1d8;
  char *local_1d0;
  code *local_1c8;
  undefined8 local_1c0;
  undefined *local_1b8;
  code *local_1b0;
  undefined8 local_1a8;
  char *local_1a0;
  code *local_198;
  undefined8 local_190;
  char *local_188;
  code *local_180;
  undefined8 local_178;
  char *local_170;
  code *local_168;
  undefined8 local_160;
  char *local_158;
  code *local_150;
  undefined8 local_148;
  char *local_140;
  code *local_138;
  undefined8 local_130;
  char *local_128;
  code *local_120;
  undefined8 local_118;
  char *local_110;
  code *local_108;
  undefined8 local_100;
  char *local_f8;
  code *local_f0;
  undefined8 local_e8;
  char *local_e0;
  code *local_d8;
  undefined8 local_d0;
  char *local_c8;
  code *local_c0;
  undefined8 local_b8;
  char *local_b0;
  code *local_a8;
  undefined8 local_a0;
  char *local_98;
  code *local_90;
  undefined8 local_88;
  char *local_80;
  code *local_78;
  undefined8 local_70;
  undefined *local_68;
  code *local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  long local_30;
  
  bVar6 = 0;
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  local_308[0] = (code *)&DAT_0010328d;
  local_308[1] = DoList;
  local_308[2] = (code *)dgettext(&DAT_00103289,"list packages based on package names");
  local_2f0 = "search";
  local_2e8 = DoSearch;
  local_2e0 = dgettext(&DAT_00103289,"search in package descriptions");
  local_2d8 = &DAT_00103299;
  local_2d0 = ShowPackage;
  local_2c8 = dgettext(&DAT_00103289,"show package details");
  local_2b8 = DoInstall;
  local_2c0 = "install";
  local_2b0 = dgettext(&DAT_00103289,"install packages");
  local_2a0 = DoInstall;
  local_2a8 = "reinstall";
  local_298 = dgettext(&DAT_00103289,"reinstall packages");
  local_288 = DoInstall;
  local_290 = "remove";
  local_280 = dgettext(&DAT_00103289,"remove packages");
  local_270 = DoInstall;
  local_278 = "autoremove";
  local_268 = dgettext(&DAT_00103289,"Remove automatically all unused packages");
  local_258 = DoInstall;
  local_260 = "auto-remove";
  local_248 = "autopurge";
  local_230 = "purge";
  local_218 = "update";
  local_240 = DoInstall;
  local_228 = DoInstall;
  local_250 = 0;
  local_238 = 0;
  local_220 = 0;
  local_210 = DoUpdate;
  local_208 = dgettext(&DAT_00103289,"update list of available packages");
  local_200 = "upgrade";
  local_1f8 = DoUpgrade;
  local_1f0 = dgettext(&DAT_00103289,"upgrade the system by installing/upgrading packages");
  local_1e8 = "full-upgrade";
  local_1e0 = DoDistUpgrade;
  local_1d8 = dgettext(&DAT_00103289,"upgrade the system by removing/installing/upgrading packages")
  ;
  local_1d0 = "edit-sources";
  local_1c8 = EditSources;
  local_1c0 = dgettext(&DAT_00103289,"edit the source information file");
  local_1b8 = &DAT_00103322;
  local_1a8 = 0;
  local_1b0 = DoMoo;
  local_1a0 = "satisfy";
  local_198 = DoBuildDep;
  local_190 = dgettext(&DAT_00103289,"satisfy dependency strings");
  local_180 = DoDistUpgrade;
  local_188 = "dist-upgrade";
  local_170 = "showsrc";
  local_178 = 0;
  local_168 = ShowSrcPackage;
  local_158 = "depends";
  local_160 = 0;
  local_150 = Depends;
  local_140 = "rdepends";
  local_148 = 0;
  local_138 = RDepends;
  local_128 = "policy";
  local_130 = 0;
  local_120 = Policy;
  local_110 = "build-dep";
  local_f8 = "clean";
  local_118 = 0;
  local_f0 = DoClean;
  local_e0 = "autoclean";
  local_108 = DoBuildDep;
  local_d8 = DoAutoClean;
  local_100 = 0;
  local_e8 = 0;
  local_d0 = 0;
  local_c8 = "auto-clean";
  local_c0 = DoAutoClean;
  local_b0 = "source";
  *param_1 = 0;
  local_a8 = DoSource;
  local_98 = "download";
  param_1[1] = 0;
  local_90 = DoDownload;
  local_80 = "changelog";
  param_1[2] = 0;
  local_78 = DoChangelog;
  local_b8 = 0;
  local_a0 = 0;
  local_88 = 0;
  local_70 = 0;
  local_68 = &DAT_001033a7;
  local_60 = ShowPackage;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
                    // try { // try from 00102b70 to 00102b74 has its CatchHandler @ 00102be9
  puVar1 = (undefined8 *)operator_new(0x2d0);
  *param_1 = puVar1;
  param_1[2] = puVar1 + 0x5a;
  *puVar1 = local_308[0];
  puVar1[0x59] = local_40;
  lVar2 = (long)puVar1 - (long)((ulong)(puVar1 + 1) & 0xfffffffffffffff8);
  puVar4 = (undefined8 *)((long)local_308 - lVar2);
  puVar5 = (undefined8 *)((ulong)(puVar1 + 1) & 0xfffffffffffffff8);
  for (uVar3 = (ulong)((int)lVar2 + 0x2d0U >> 3); uVar3 != 0; uVar3 = uVar3 - 1) {
    *puVar5 = *puVar4;
    puVar4 = puVar4 + (ulong)bVar6 * -2 + 1;
    puVar5 = puVar5 + (ulong)bVar6 * -2 + 1;
  }
  param_1[1] = puVar1 + 0x5a;
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return param_1;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void _DT_FINI(void)

{
  return;
}



