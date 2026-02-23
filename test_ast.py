import difflib
import unittest
import tree_sitter_c
from tree_sitter import Language, Parser
from ghidra_bench.utils.com import get_ast


class TestGetAbstractPseudocode(unittest.TestCase):

    def test_empty_function(self):
        code = "void main() {}"
        expected = "type id(){\n}"
        self.assertEqual(get_ast(code, indent_step=2), expected)

    def test_function_call(self):
        code = "void main() { foo(); }"
        expected = (
            "type id(){\n"
            "  call();\n"
            "}"
        )
        self.assertEqual(get_ast(code, indent_step=2), expected)

    def test_nested_calls(self):
        code = "void main() { foo(bar()); }"
        # foo(bar()) -> call(call())
        expected = (
            "type id(){\n"
            "  call(call());\n"
            "}"
        )
        self.assertEqual(get_ast(code, indent_step=2), expected)

    def test_if_statement(self):
        code = """
        void test() {
            if (x) {
                foo();
            }
        }
        """
        expected = (
            "type id(){\n"
            "  if(id){\n"
            "    call();\n"
            "  }\n"
            "}"
        )
        self.assertEqual(get_ast(code, indent_step=2), expected)

    def test_if_else_statement(self):
        code = """
        void test() {
            if (x) {
                printf("ciao", x);
            } else {
                bar();
            }
        }
        """
        expected = (
            "type id(){\n"
            "  if(id){\n"
            "    call(str, id);\n"
            "  }else{\n"
            "    call();\n"
            "  }\n"
            "}"
        )
        self.assertEqual(get_ast(code, indent_step=2), expected)

    def test_if_no_braces(self):
        """Test if without braces (single statement)"""
        code = "void test() { if (x) foo(); }"
        expected = (
            "type id(){\n"
            "  if(id)call();\n"
            "}"
        )
        self.assertEqual(get_ast(code, indent_step=2), expected)

    def test_loops(self):
        code = """
        void loop() {
            while(1) { a(); }
            for(;;) { b(); }
            do { c(); } while(0);
        }
        """
        expected = (
            "type id(){\n"
            "  while(num){\n"
            "    call();\n"
            "  }\n"
            "  for(; ; ){\n"
            "    call();\n"
            "  }\n"
            "  do{\n"
            "    call();\n"
            "  }while(num);\n"
            "}"
        )
        self.assertEqual(get_ast(code, indent_step=2), expected)

    def test_switch_case(self):
        code = """
        void s(){
            switch(x){
                case 1:
                    foo();
                    break;
                case 2:
                    bar();
                    break;
            }
        }
        """
        # x -> id, 1 -> num, 2 -> num
        expected = (
            "type id(){\n"
            "  switch(id){\n"
            "    case num:\n"
            "      call();\n"
            "      break;\n"
            "    case num:\n"
            "      call();\n"
            "      break;\n"
            "  }\n"
            "}"
        )
        self.assertEqual(get_ast(code, indent_step=2), expected)

    def test_goto_and_label(self):
        code = """
        void g(){ 
            goto label; 
            label:
            return;
        }
        """
        expected = (
            "type id(){\n"
            "  goto lbl;\n"
            "  lbl:\n"
            "  return;\n"
            "}"
        )
        self.assertEqual(get_ast(code, indent_step=2), expected)

    def test_ternary_operator(self):
        code = "void t() { int a = x ? y : z; }"
        expected = (
            "type id(){\n"
            "  type id = (id ? id : id);\n"
            "}"
        )
        self.assertEqual(get_ast(code, indent_step=2), expected)

    def test_complex_nesting_and_pointers(self):
        code = """
        void complex(){
            if (cond){
                while(1){
                    foo(x ? a : b);
                }
            }else{
                goto lbl;
            }
            lbl:
            int *a = b < c;
            f->g(h[i]);
            (*(int *)(p + 4)) = 5;
        }
        """
        expected = (
            "type id(){\n"
            "  if(id){\n"
            "    while(num){\n"
            "      call((id ? id : id));\n"
            "    }\n"
            "  }else{\n"
            "    goto lbl;\n"
            "  }\n"
            "  lbl:\n"
            "  type *id = id < id;\n"
            "  call(id[id]);\n" # f->g(...) is parsed as call_expression, so it becomes call(...)
            "  (*(type)(id op num)) = num;\n"
            "}"
        )
        
        self.assertEqual(get_ast(code, indent_step=2), expected)
        
    def test_field_access_arrow(self):
        code = "void f() { x->y = 1; z.w = 2; }"
        expected = (
            "type id(){\n"
            "  id->id = num;\n"
            "  id.id = num;\n"
            "}"
        )
        self.assertEqual(get_ast(code, indent_step=2), expected)
    
    def test_operators(self):
        code = "void op() { a = b + c; d = e && f; g = h == i; }"
        expected = (
            "type id(){\n"
            "  id = id op id;\n"
            "  id = id && id;\n"
            "  id = id == id;\n"
            "}"
        )
        self.assertEqual(get_ast(code, indent_step=2), expected)

def get_diff_text(text_a, text_b):
    a_lines = text_a.splitlines()
    b_lines = text_b.splitlines()
    
    diff = difflib.unified_diff(
        a_lines, 
        b_lines, 
        n=max(len(a_lines), len(b_lines)),
        lineterm=''
    )
    
    diff_lines = list(diff)
    if not diff_lines:
        return ""

    clean_diff = []
    for line in diff_lines[2:]:
        if line.startswith('@@'):
            continue 
        elif line.startswith('+'):
            clean_diff.append("&" + line[1:])
        elif line.startswith('-'):
            clean_diff.append("%" + line[1:])
        else:
            clean_diff.append(line)
            
    return "\n".join(clean_diff)



if __name__ == '__main__':
    #unittest.main()
 
    #code="\nint xls_parseWorkBook(long *param_1)\n\n{\n  long lVar1;\n  ushort uVar2;\n  uint in_EAX;\n  int iVar3;\n  int iVar4;\n  long lVar5;\n  ushort *__ptr;\n  ulong uVar6;\n  void *__ptr_00;\n  undefined2 uVar7;\n  char *pcVar8;\n  short sVar9;\n  undefined8 uStack_38;\n  \n  if (param_1 == (long *)0x0) {\n    iVar4 = 7;\n  }\n  else {\n    uStack_38 = (ulong)in_EAX;\n    verbose(\"xls_parseWorkBook\");\n    iVar4 = 1;\n    lVar1 = (long)&uStack_38 + 4;\n    __ptr = (ushort *)0x0;\n    uVar7 = 0;\n    sVar9 = 0;\n    do {\n      if (10 < *(int *)PTR_xls_debug_00104fd8) {\n        printf(\"READ WORKBOOK filePos=%ld\\n\",(long)(int)param_1[1]);\n        lVar5 = *param_1;\n        printf(\"  OLE: start=%d pos=%u size=%u fatPos=%u\\n\",(ulong)*(uint *)(lVar5 + 8),\n               (ulong)*(uint *)(lVar5 + 0x10),(ulong)*(uint *)(lVar5 + 0x20),\n               (ulong)*(uint *)(lVar5 + 0x28));\n      }\n      lVar5 = ole2_read(lVar1,1,4,*param_1);\n      if (lVar5 != 4) {\n        iVar4 = 3;\n        break;\n      }\n      xlsConvertBof(lVar1);\n      if (*(int *)PTR_xls_debug_00104fd8 != 0) {\n        xls_showBOF(lVar1);\n      }\n      if (uStack_38 >> 0x30 != 0) {\n        __ptr = (ushort *)realloc(__ptr,uStack_38 >> 0x30);\n        if (__ptr == (ushort *)0x0) {\n          if (*(int *)PTR_xls_debug_00104fd8 == 0) {\n            return 5;\n          }\n          fprintf(*(FILE **)PTR_stderr_00104ff8,\"Error: failed to allocate buffer of size %d\\n\",\n                  (ulong)uStack_38._6_2_);\n          return 5;\n        }\n        uVar6 = ole2_read(__ptr,1,uStack_38._6_2_,*param_1);\n        if (uVar6 != uStack_38 >> 0x30) {\n          iVar4 = 3;\n          if (*(int *)PTR_xls_debug_00104fd8 != 0) {\n            fwrite(\"Error: failed to read OLE block\\n\",0x20,1,*(FILE **)PTR_stderr_00104ff8);\n          }\n          goto LAB_00101bb4;\n        }\n      }\n      iVar3 = xls_isRecordTooSmall(param_1,lVar1,__ptr);\n      if (iVar3 != 0) {\n        iVar4 = 4;\n        break;\n      }\n      if (uStack_38._4_2_ < 0x92) {\n        switch(uStack_38._4_2_) {\n        case 0x18:\n          if (*(int *)PTR_xls_debug_00104fd8 != 0) {\n            printf(\"   DEFINEDNAME: \");\n            if (uStack_38._6_2_ != 0) {\n              uVar6 = 0;\n              do {\n                printf(\"%2.2x \",(ulong)*(byte *)((long)__ptr + uVar6));\n                uVar6 = uVar6 + 1;\n              } while (uVar6 < uStack_38 >> 0x30);\n            }\n            putchar(10);\n          }\n          break;\n        case 0x31:\nswitchD_00101509_caseD_31:\n          xlsConvertFont(__ptr);\n          lVar5 = xls_addFont(param_1,__ptr,uStack_38._6_2_);\n          if (*(int *)PTR_xls_debug_00104fd8 != 0) {\n            printf(\" height: %d\\n\",(ulong)*__ptr);\n            printf(\"   flag: 0x%x\\n\",(ulong)__ptr[1]);\n            printf(\"  color: 0x%x\\n\",(ulong)__ptr[2]);\n            printf(\" weight: %d\\n\",(ulong)__ptr[3]);\n            printf(\"escapem: 0x%x\\n\",(ulong)__ptr[4]);\n            printf(\"underln: 0x%x\\n\",(ulong)(byte)__ptr[5]);\n            printf(\" family: 0x%x\\n\",(ulong)*(byte *)((long)__ptr + 0xb));\n            printf(\"charset: 0x%x\\n\",(ulong)(byte)__ptr[6]);\n            if (lVar5 != 0) {\n              printf(\"   name: %s\\n\",lVar5);\n            }\n          }\n          break;\n        default:\n          if (uStack_38._4_2_ == 0x85) {\n            xlsConvertBoundsheet(__ptr);\n            iVar4 = xls_addSheet(param_1,__ptr,uStack_38._6_2_);\n            goto joined_r0x00101ad1;\n          }\nswitchD_00101509_caseD_b:\n          if (*(int *)PTR_xls_debug_00104fd8 != 0) {\n            printf(\"    Not Processed in parseWorkBook():  BOF=0x%4.4X size=%d\\n\",\n                   (ulong)uStack_38._4_2_,(ulong)uStack_38._6_2_);\n          }\n          break;\n        case 0xb:\n        case 0xc:\n        case 0xd:\n        case 0xe:\n        case 0xf:\n        case 0x10:\n        case 0x11:\n        case 0x12:\n        case 0x13:\n        case 0x14:\n        case 0x15:\n        case 0x16:\n        case 0x17:\n        case 0x19:\n        case 0x1a:\n        case 0x1b:\n        case 0x1c:\n        case 0x1d:\n        case 0x1e:\n        case 0x1f:\n        case 0x20:\n        case 0x21:\n        case 0x23:\n        case 0x24:\n        case 0x25:\n        case 0x26:\n        case 0x27:\n        case 0x28:\n        case 0x29:\n        case 0x2a:\n        case 0x2b:\n        case 0x2c:\n        case 0x2d:\n        case 0x2e:\n        case 0x30:\n        case 0x32:\n        case 0x33:\n        case 0x34:\n        case 0x35:\n        case 0x36:\n        case 0x37:\n        case 0x38:\n        case 0x39:\n        case 0x3a:\n        case 0x3b:\n        case 0x3e:\n        case 0x3f:\n        case 0x40:\n        case 0x41:\n          goto switchD_00101509_caseD_b;\n        case 0x3d:\n          xlsConvertWindow(__ptr);\n          *(ushort *)(param_1 + 2) = __ptr[5];\n          if (*(int *)PTR_xls_debug_00104fd8 != 0) {\n            printf(\"WINDOW1: \");\n            printf(\"xWn    : %d\\n\",(ulong)(*__ptr / 0x14));\n            printf(\"yWn    : %d\\n\",(ulong)(__ptr[1] / 0x14));\n            printf(\"dxWn   : %d\\n\",(ulong)(__ptr[2] / 0x14));\n            printf(\"dyWn   : %d\\n\",(ulong)(__ptr[3] / 0x14));\n            printf(\"grbit  : %d\\n\",(ulong)__ptr[4]);\n            printf(\"itabCur: %d\\n\",(ulong)__ptr[5]);\n            printf(\"itabFi : %d\\n\",(ulong)__ptr[6]);\n            printf(\"ctabSel: %d\\n\",(ulong)__ptr[7]);\n            uVar6 = (ulong)__ptr[8];\n            pcVar8 = \"wTabRat: %d\\n\";\n            goto LAB_00101b26;\n          }\n          break;\n        case 0x42:\n          uVar6 = (ulong)*__ptr;\n          *(ushort *)((long)param_1 + 0x12) = *__ptr;\n          if (*(int *)PTR_xls_debug_00104fd8 != 0) {\n            pcVar8 = \"codepage: %d\\n\";\n            goto LAB_00101b26;\n          }\n          break;\n        case 0x3c:\n          if (iVar4 == 0) {\n            if ((sVar9 == 0xfc) &&\n               (iVar4 = xls_appendSST(param_1,__ptr,uStack_38._6_2_), iVar4 != 0))\n            goto LAB_00101b6a;\n            uStack_38 = CONCAT26(uVar7,CONCAT24(sVar9,(undefined4)uStack_38));\n          }\n          break;\n        case 0x22:\n          uVar6 = (ulong)(byte)*__ptr;\n          *(byte *)((long)param_1 + 0xd) = (byte)*__ptr;\n          if (*(int *)PTR_xls_debug_00104fd8 != 0) {\n            pcVar8 = \"   mode: 0x%x\\n\";\nLAB_00101b26:\n            printf(pcVar8,uVar6);\n          }\n          break;\n        case 10:\n          break;\n        case 0x2f:\n          iVar4 = 6;\n          goto LAB_00101b6a;\n        }\n      }\n      else if (uStack_38._4_2_ < 0x231) {\n        if (uStack_38._4_2_ < 0xfc) {\n          if (uStack_38._4_2_ == 0x92) {\n            if ((10 < *(int *)PTR_xls_debug_00104fd8) && (uVar2 = *__ptr, uVar2 != 0)) {\n              lVar5 = 0;\n              do {\n                printf(\"   Index=0x%2.2x %2.2x%2.2x%2.2x\\n\",(ulong)((int)lVar5 + 8),\n                       (ulong)(byte)__ptr[lVar5 * 2 + 1],\n                       (ulong)*(byte *)((long)__ptr + lVar5 * 4 + 3),\n                       (ulong)(byte)__ptr[lVar5 * 2 + 2]);\n                lVar5 = lVar5 + 1;\n              } while ((uint)uVar2 != (uint)lVar5);\n            }\n          }\n          else {\n            if (uStack_38._4_2_ != 0xe0) goto switchD_00101509_caseD_b;\n            if (*(char *)((long)param_1 + 0xc) == '\\0') {\n              xlsConvertXf8(__ptr);\n              iVar4 = xls_addXF8(param_1,__ptr);\n              if (iVar4 == 0) {\n                if (*(int *)PTR_xls_debug_00104fd8 != 0) {\n                  xls_showXF(__ptr);\n                }\n                goto switchD_00101509_caseD_a;\n              }\n              break;\n            }\n            xlsConvertXf5(__ptr);\n            iVar4 = xls_addXF5(param_1,__ptr);\n            if (iVar4 != 0) break;\n            if (*(int *)PTR_xls_debug_00104fd8 != 0) {\n              printf(\"   font: %d\\n\",(ulong)*__ptr);\n              printf(\" format: %d\\n\",(ulong)__ptr[1]);\n              printf(\"   type: %.4x\\n\",(ulong)__ptr[2]);\n              printf(\"  align: %.4x\\n\",(ulong)__ptr[3]);\n              printf(\"rotatio: %.4x\\n\",(ulong)__ptr[4]);\n              printf(\"  ident: %.4x\\n\",(ulong)__ptr[5]);\n              printf(\"usedatt: %.4x\\n\",(ulong)__ptr[6]);\n              uVar6 = (ulong)__ptr[7];\n              pcVar8 = \"linesty: %.4x\\n\";\n              goto LAB_00101b26;\n            }\n          }\n        }\n        else if (uStack_38._4_2_ == 0xfc) {\n          xlsConvertSst(__ptr);\n          iVar4 = xls_addSST(param_1,__ptr,uStack_38._6_2_);\njoined_r0x00101ad1:\n          if (iVar4 != 0) break;\n        }\n        else if (uStack_38._4_2_ != 0xff) goto switchD_00101509_caseD_b;\n      }\n      else if (uStack_38._4_2_ < 0x41e) {\n        if (uStack_38._4_2_ == 0x231) goto switchD_00101509_caseD_31;\n        if (uStack_38._4_2_ != 0x293) goto switchD_00101509_caseD_b;\n        if (*(int *)PTR_xls_debug_00104fd8 != 0) {\n          printf(\"    idx: 0x%x\\n\",(ulong)(*__ptr & 0x7ff));\n          if ((short)*__ptr < 0) {\n            printf(\"  ident: 0x%x\\n\",(ulong)(byte)__ptr[1]);\n            uVar6 = (ulong)*(byte *)((long)__ptr + 3);\n            pcVar8 = \"  level: 0x%x\\n\";\n            goto LAB_00101b26;\n          }\n          __ptr_00 = (void *)get_string(__ptr + 1,(uStack_38 >> 0x30) - 2,1,param_1);\n          printf(\"  name=%s\\n\",__ptr_00);\n          free(__ptr_00);\n        }\n      }\n      else {\n        if (uStack_38._4_2_ == 0x41e) {\n          xlsConvertFormat(__ptr);\n          iVar4 = xls_addFormat(param_1,__ptr,uStack_38._6_2_);\n          goto joined_r0x00101ad1;\n        }\n        if (uStack_38._4_2_ != 0x809) goto switchD_00101509_caseD_b;\n        uVar2 = *__ptr;\n        *(bool *)((long)param_1 + 0xc) = uVar2 != 0x600;\n        *(ushort *)((long)param_1 + 0xe) = __ptr[1];\n        if (*(int *)PTR_xls_debug_00104fd8 != 0) {\n          pcVar8 = \"BIFF8\";\n          if (uVar2 != 0x600) {\n            pcVar8 = \"BIFF5\";\n          }\n          printf(\"version: %s\\n\",pcVar8);\n          uVar6 = (ulong)*(ushort *)((long)param_1 + 0xe);\n          pcVar8 = \"   type: %.2X\\n\";\n          goto LAB_00101b26;\n        }\n      }\nswitchD_00101509_caseD_a:\n      iVar4 = 0;\n      if (*(char *)(*param_1 + 0x3c) != '\\0') break;\n      uVar7 = uStack_38._6_2_;\n      sVar9 = uStack_38._4_2_;\n    } while (uStack_38._4_2_ != 10);\nLAB_00101b6a:\n    if (__ptr != (ushort *)0x0) {\nLAB_00101bb4:\n      free(__ptr);\n    }\n  }\n  return iVar4;\n}\n\n"
    
    code="""
    //This function does random stuff dont try to understand it
    void complex(int a, char *b) {
        long *f;
        int h[10];
        if (a > 0) {
            while (a < 10) {
                printf("Value: %d\n", a);
                a++;
            }  
        } else {
            goto end;//random comment
        }
        h[0] = 42;
        end:    
        char c = b[id];
        f->g(h[i]);
        (*(int *)(p + -4)) = 5;
    }   
    """

    code2="""
    //This function does random stuff dont try to understand it
    void complex(int a, char *b) {
        long *f;
        int h[10];
        if (a > 0) {
            while (a < 10) {
                printf("Value: %d\n", a);
                a++;
            }  
        } else {
            goto end;//random comment
        }
        h[0] = "*";
        end:    
        char c = b->id;
        f->g(h[i]);
        (*(int *)(p - 4)) = 5;
    }   
    """

    # code="""
    # void file_replace(struct magic_set *ms, const char *pat, const char *rep)
    # {
    #     file_regex_t rx;
    #     int rc, rv = -1;
    #     }
    # """

    print(get_ast(code, indent_step=2)) #
    print(get_diff_text(get_ast(code, indent_step=2), get_ast(code2, indent_step=2)))
    print(get_diff_text(code, code2))