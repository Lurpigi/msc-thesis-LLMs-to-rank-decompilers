#include "out.h"



int _init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  
  iVar1 = __gmon_start__();
  return iVar1;
}



void FUN_00101020(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



void FUN_001010c0(void)

{
  __cxa_finalize();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int puts(char *__s)

{
  int iVar1;
  
  iVar1 = puts(__s);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

double pow(double __x,double __y)

{
  double dVar1;
  
  dVar1 = pow(__x,__y);
  return dVar1;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int system(char *__command)

{
  int iVar1;
  
  iVar1 = system(__command);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

double cos(double __x)

{
  double dVar1;
  
  dVar1 = cos(__x);
  return dVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

double tan(double __x)

{
  double dVar1;
  
  dVar1 = tan(__x);
  return dVar1;
}



void __printf_chk(void)

{
  __printf_chk();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

double sin(double __x)

{
  double dVar1;
  
  dVar1 = sin(__x);
  return dVar1;
}



void __isoc99_scanf(void)

{
  __isoc99_scanf();
  return;
}



undefined8 main(void)

{
  askdo();
  return 0;
}



void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  __libc_start_main(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Removing unreachable block (ram,0x001011c3)
// WARNING: Removing unreachable block (ram,0x001011cf)

void deregister_tm_clones(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00101204)
// WARNING: Removing unreachable block (ram,0x00101210)

void register_tm_clones(void)

{
  return;
}



void __do_global_dtors_aux(void)

{
  if (completed_0 != '\0') {
    return;
  }
  FUN_001010c0(__dso_handle);
  deregister_tm_clones();
  completed_0 = 1;
  return;
}



void frame_dummy(void)

{
  register_tm_clones();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 askdo(void)

{
  bool bVar1;
  longdouble lVar2;
  bool bVar3;
  bool bVar4;
  long lVar5;
  undefined7 uVar7;
  ulong uVar6;
  ulong extraout_RDX;
  ulong extraout_RDX_00;
  ulong extraout_RDX_01;
  long in_FS_OFFSET;
  double dVar8;
  longdouble local_38;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  system("clear");
  puts("\x1b[1;32m---------------------------------------\x1b[0m");
  uVar6 = CONCAT62(uRam000000000010405a,_DAT_00104058);
  __printf_chk(2,&DAT_0010201a);
  __printf_chk(2,&DAT_00102078);
  puts(
      "\n0. Clear all\n1. Addition\n2. Subtraction\n3. Multiplication\n4. Division\n5. sin (deg)\n6. cos (deg)\n7.tan (deg)\n8. n Power\n9. n Root"
      );
  __printf_chk(2,"Enter function option number/memory input num>9: ");
  __isoc99_scanf(&DAT_0010202a,askdo_input);
  lVar2 = (longdouble)0;
  if ((longdouble)askdo_input._0_10_ == lVar2) {
    memory = SUB108(lVar2,0);
    _DAT_00104058 = (undefined2)((unkuint10)lVar2 >> 0x40);
    result._0_10_ = lVar2;
    system("clear");
    askdo();
    uVar6 = extraout_RDX_01;
  }
  if ((longdouble)10.0 <= (longdouble)askdo_input._0_10_) {
    memory = (undefined8)askdo_input._0_10_;
    _DAT_00104058 = SUB102(askdo_input._0_10_,8);
    result._0_10_ = askdo_input._0_10_;
    system("clear");
    askdo();
    uVar6 = extraout_RDX_00;
  }
  if ((longdouble)CONCAT28(_DAT_00104058,memory) == (longdouble)0) {
    lVar5 = (uVar6 >> 8 & 0xffffff) << 8;
    if ((longdouble)1 != (longdouble)askdo_input._0_10_) {
      lVar5 = 0;
    }
    bVar3 = (longdouble)1 == (longdouble)askdo_input._0_10_;
    uVar7 = (undefined7)((ulong)lVar5 >> 8);
    if ((longdouble)3.0 != (longdouble)askdo_input._0_10_) {
      uVar7 = 0;
    }
    bVar4 = (longdouble)3.0 == (longdouble)askdo_input._0_10_;
    if (((longdouble)2.0 != (longdouble)askdo_input._0_10_ && !bVar3) && !bVar4) {
      bVar1 = !NAN((longdouble)4.0) && !NAN((longdouble)askdo_input._0_10_);
      uVar6 = CONCAT71(uVar7,bVar1);
      bVar3 = ((longdouble)2.0 == (longdouble)askdo_input._0_10_ || bVar3) || bVar4;
      if ((longdouble)4.0 == (longdouble)askdo_input._0_10_) {
        bVar3 = bVar1;
      }
      if (!bVar3) goto LAB_001013ce;
    }
    __printf_chk(2,"Enter memory number/primary number:");
    __isoc99_scanf(&DAT_0010202a,&memory);
    uVar6 = extraout_RDX;
  }
LAB_001013ce:
  __printf_chk(2,"Enter performing number:",uVar6);
  __isoc99_scanf(&DAT_0010202a,func_name);
  switch((int)ROUND((longdouble)askdo_input._0_10_)) {
  default:
    break;
  case 1:
    result._0_10_ = (longdouble)func_name._0_10_ + (longdouble)CONCAT28(_DAT_00104058,memory);
    break;
  case 2:
    result._0_10_ = (longdouble)CONCAT28(_DAT_00104058,memory) - (longdouble)func_name._0_10_;
    break;
  case 3:
    result._0_10_ = (longdouble)func_name._0_10_ * (longdouble)CONCAT28(_DAT_00104058,memory);
    break;
  case 4:
    result._0_10_ = (longdouble)CONCAT28(_DAT_00104058,memory) / (longdouble)func_name._0_10_;
    break;
  case 5:
    dVar8 = sin((double)((longdouble)func_name._0_10_ / (longdouble)57.2957795));
    result._0_10_ = (unkbyte10)dVar8;
    break;
  case 6:
    dVar8 = cos((double)((longdouble)func_name._0_10_ / (longdouble)57.2957795));
    result._0_10_ = (unkbyte10)dVar8;
    break;
  case 7:
    dVar8 = tan((double)((longdouble)func_name._0_10_ / (longdouble)57.2957795));
    result._0_10_ = (unkbyte10)dVar8;
    break;
  case 8:
    __printf_chk(2,"Enter exponent value: ");
    __isoc99_scanf(&DAT_0010202a,&local_38);
    goto LAB_001014ba;
  case 9:
    __printf_chk(2,"Enter root cap value: ");
    __isoc99_scanf(&DAT_0010202a,&local_38);
    local_38 = (longdouble)1 / local_38;
LAB_001014ba:
    dVar8 = pow((double)(longdouble)func_name._0_10_,(double)local_38);
    result._0_10_ = (unkbyte10)dVar8;
  }
  memory = (undefined8)result._0_10_;
  _DAT_00104058 = SUB102(result._0_10_,8);
  system("clear");
  askdo();
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void repeat(void)

{
  _memory = result._0_10_;
  system("clear");
  askdo();
  return;
}



void _fini(void)

{
  return;
}



