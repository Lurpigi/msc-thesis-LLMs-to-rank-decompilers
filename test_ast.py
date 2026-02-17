import difflib
import unittest
import tree_sitter_c
from tree_sitter import Language, Parser


def get_abstract_pseudocode(code, indent_step=2):
    C_LANGUAGE = Language(tree_sitter_c.language())
    parser = Parser(C_LANGUAGE)

    tree = parser.parse(code.encode('utf8'))
    structure = []
    depth = 0

    def append_indent():
        if indent_step > 0:
            structure.append("\n" + " " * (depth * indent_step))
        else:
            structure.append(" ")

    def clean_ast_output(ast_str):
        lines = ast_str.splitlines()
        
        cleaned_lines = []
        for line in lines:
            stripped_right = line.rstrip()
            if line.strip():
                cleaned_lines.append(stripped_right)
        return "\n".join(cleaned_lines)

    def traverse(node):
        nonlocal depth

        if node is None:
            return

        if node.type == 'labeled_statement' and b'::' in node.text:
            for child in node.children:
                if child.type != ':':
                    traverse(child)
            return

        if node.type == 'function_definition':
            traverse(node.child_by_field_name('type'))
            structure.append(" ")
            traverse(node.child_by_field_name('declarator'))
            traverse(node.child_by_field_name('body'))
            return
        
        if node.type == 'function_declarator':
            traverse(node.child_by_field_name('declarator'))
            structure.append("(")
            params = node.child_by_field_name('parameters')
            if params:
                first = True
                for child in params.children:
                    if child.type not in ['(', ')', ',']:
                        if not first: structure.append(", ")
                        traverse(child)
                        first = False
            structure.append(")")
            return
        
        if node.type == 'compound_statement':
            structure.append("{")
            if indent_step > 0: depth += 1
            
            for child in node.children:
                if child.type in ['{', '}']: continue
                append_indent()
                traverse(child)

            if indent_step > 0: depth -= 1; append_indent()
            else: structure.append(" ")
            structure.append("}")
            return

        if node.type == 'expression_statement':
            for child in node.children:
                traverse(child)
            structure.append(";") 
            return

        if node.type == 'return_statement':
            structure.append("return")
            has_value = False
            for child in node.children:
                if child.type != 'return' and child.type != ';':
                    has_value = True
                    break
            
            if has_value:
                structure.append(" ")
                for child in node.children:
                    if child.type != 'return' and child.type != ';':
                        traverse(child)
            
            structure.append(";")
            return

        if node.type == 'if_statement':
            structure.append("if")
            traverse(node.child_by_field_name('condition'))
            #structure.append(")")
            traverse(node.child_by_field_name('consequence'))
            else_node = node.child_by_field_name('alternative')
            if else_node:
                if else_node.type == 'if_statement':
                    structure.append("else ")
                    traverse(else_node)
                else:
                    structure.append("else")
                    traverse(else_node)
            return
        
        #loops 

        if node.type == 'while_statement':
            structure.append("while")
            traverse(node.child_by_field_name('condition'))
            #structure.append(")")
            traverse(node.child_by_field_name('body'))
            return

        if node.type == 'do_statement':
            structure.append("do")
            traverse(node.child_by_field_name('body'))
            structure.append("while")
            traverse(node.child_by_field_name('condition'))
            structure.append(";")
            return

        if node.type == 'for_statement':
            structure.append("for(")
            init = node.child_by_field_name('initializer')
            if init:
                traverse(init) 
                if init.type != 'declaration': 
                    structure.append("; ")
            else:
                structure.append(";")
            structure.append(" ")

            cond = node.child_by_field_name('condition')
            if cond:
                traverse(cond)
            structure.append("; ")
            upd = node.child_by_field_name('update')
            if upd:
                traverse(upd)
            
            structure.append(")")
            traverse(node.child_by_field_name('body'))
            return

        if node.type == 'switch_statement':
            structure.append("switch")
            traverse(node.child_by_field_name('condition'))
            structure.append("{")
            if indent_step > 0: depth += 1
            
            body = node.child_by_field_name('body')
            if body:
                for child in body.children:
                    if child.type in ['{', '}']: continue
                    append_indent()
                    traverse(child)
            
            if indent_step > 0: depth -= 1; append_indent()
            structure.append("}")
            return

        if node.type == 'case_statement':
            structure.append("case ")
            val = node.child_by_field_name('value')
            if val: traverse(val)
            else: structure.append("def")
            structure.append(":")
            if indent_step > 0: depth += 1
            for child in node.children:
                if child.type not in ['case', 'default', ':', 'number_literal'] and child != val:
                    append_indent()
                    traverse(child)
            if indent_step > 0: depth -= 1
            return

        if node.type == 'break_statement':
            structure.append("break;")
            return
            
        if node.type == 'continue_statement':
            structure.append("continue;")
            return

        if node.type == 'goto_statement':
            structure.append("goto lbl;")
            return
            
        if node.type == 'labeled_statement':
            if b'::' in node.children[0].text:
                 for child in node.children:
                    if child.type != ':': traverse(child)
                 return

            structure.append("lbl:")
            append_indent()
            
            label_node = node.children[0] 
            
            for child in node.children:
                if child.id == label_node.id:
                    continue
                if child.type == ':':
                    continue
                
                traverse(child)
            return

        if node.type == 'unary_expression' or node.type == 'pointer_expression':
            if node.child_count > 0:
                op_node = node.children[0]
                op = op_node.text.decode('utf8')
                if op in ['*', '&', '!', '-', '~']:
                    structure.append(op)
                else:
                    structure.append("op")
            traverse(node.child_by_field_name('argument'))
            return

        if node.type == 'pointer_declarator':
            structure.append("*")
            traverse(node.child_by_field_name('declarator'))
            return
            
        if node.type == 'abstract_pointer_declarator':
            structure.append("*")
            for child in node.children:
                if child.type != '*': traverse(child)
            return
        
        if node.type == 'field_expression':
            traverse(node.child_by_field_name('argument'))
            operator = "."
            for child in node.children:
                if child.type == '->':
                    operator = "->"
                    break
                elif child.type == '.':
                    operator = "."
                    break
            
            structure.append(operator)
            traverse(node.child_by_field_name('field'))
            return

        # expressions

        if node.type == 'binary_expression':
            traverse(node.child_by_field_name('left'))
            op = node.children[1].text.decode('utf8')
            structure.append(f" {op} ")
            traverse(node.child_by_field_name('right'))
            return
        
        if node.type == 'update_expression':
            # for child in node.children:
            #     print(f"Update expression child: {child.type} - {child.text}")
            op = node.children[0].type
            #print(f"Update expression operator: {op}")
            if op in ['++', '--']:
                structure.append(node.children[0].text.decode('utf8'))
                traverse(node.children[1])
            else:
                traverse(node.children[0])
                structure.append(node.children[1].text.decode('utf8'))
            return

        if node.type == 'assignment_expression':
            traverse(node.child_by_field_name('left'))
            structure.append(" = ")
            traverse(node.child_by_field_name('right'))
            return

        if node.type == 'cast_expression':
            structure.append("(type)")
            traverse(node.child_by_field_name('value'))
            return

        if node.type == 'call_expression':
            structure.append("call(")
            args = node.child_by_field_name('arguments')
            if args:
                first = True
                for child in args.children:
                    if child.type not in ['(', ')', ',']:
                        if not first: structure.append(", ")
                        traverse(child)
                        first = False
            structure.append(")")
            return

        if node.type == 'conditional_expression':
            structure.append("(")
            traverse(node.child_by_field_name('condition'))
            structure.append(" ? ")
            traverse(node.child_by_field_name('consequence'))
            structure.append(" : ")
            traverse(node.child_by_field_name('alternative'))
            structure.append(")")
            return

        if node.type == 'parenthesized_expression':
            structure.append("(")
            for child in node.children:
                 if child.type not in ['(', ')']: traverse(child)
            structure.append(")")
            return

        if node.type == 'declaration':
            structure.append("type ")
            first = True
            for child in node.children:
                if child.type in [
                    'primitive_type', 'type_identifier', 'struct_specifier', 
                    'enum_specifier', 'union_specifier', 'storage_class_specifier', 
                    'type_qualifier', 'sizeless_type', 'sized_type_specifier',
                    'class_specifier', 'attribute_specifier', 'ms_declspec_modifier',
                    ';', ','
                ]: 
                    continue
                if not first: 
                    structure.append(", ")
                
                traverse(child) 
                first = False
            
            structure.append(";")
            return
        
        if node.type == 'parameter_declaration':
            traverse(node.child_by_field_name('type'))
            
            decl = node.child_by_field_name('declarator')
            if decl:
                structure.append(" ")
                traverse(decl)
            return

        if node.type == 'init_declarator':
             traverse(node.child_by_field_name('declarator'))
             structure.append(" = ")
             traverse(node.child_by_field_name('value'))
             return
        
        if node.type == 'number_literal':
            n = node.text.decode('utf8')
            #print(f"Number literal: {n}")
            structure.append(n)
            return
            
        if node.type in ['string_literal', 'char_literal', 'concatenated_string']:
            structure.append("str")
            return
            
        if node.type in ['true', 'false', 'null']:
            structure.append("bool" if node.type != 'null' else "null")
            return
            
        if node.type in ['primitive_type', 'type_identifier']:
            structure.append("type")
            return
        
        if node.type == 'pointer_declarator':
            structure.append("*")
            traverse(node.child_by_field_name('declarator'))
            return
        
        if node.type == 'subscript_expression':
            traverse(node.child_by_field_name('argument'))
            structure.append("[")
            traverse(node.child_by_field_name('index'))
            structure.append("]")
            return
        
        if node.type == 'array_declarator':
            traverse(node.child_by_field_name('declarator'))
            structure.append("[")
            size = node.child_by_field_name('size')
            if size:
                traverse(size)
            structure.append("]")
            return
        
        # Leaf nodes
        if node.child_count == 0:
            if node.type in ['identifier', 'field_identifier']:
                structure.append("id")
                return
            if len(node.type) == 1 and node.type in ";,(){}[]":
                 return 

        for child in node.children:
            traverse(child)

    traverse(tree.root_node)
    
    return clean_ast_output("".join(structure))

class TestGetAbstractPseudocode(unittest.TestCase):

    def test_empty_function(self):
        code = "void main() {}"
        expected = "type id(){\n}"
        self.assertEqual(get_abstract_pseudocode(code, indent_step=2), expected)

    def test_function_call(self):
        code = "void main() { foo(); }"
        expected = (
            "type id(){\n"
            "  call();\n"
            "}"
        )
        self.assertEqual(get_abstract_pseudocode(code, indent_step=2), expected)

    def test_nested_calls(self):
        code = "void main() { foo(bar()); }"
        # foo(bar()) -> call(call())
        expected = (
            "type id(){\n"
            "  call(call());\n"
            "}"
        )
        self.assertEqual(get_abstract_pseudocode(code, indent_step=2), expected)

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
        self.assertEqual(get_abstract_pseudocode(code, indent_step=2), expected)

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
        self.assertEqual(get_abstract_pseudocode(code, indent_step=2), expected)

    def test_if_no_braces(self):
        """Test if without braces (single statement)"""
        code = "void test() { if (x) foo(); }"
        expected = (
            "type id(){\n"
            "  if(id)call();\n"
            "}"
        )
        self.assertEqual(get_abstract_pseudocode(code, indent_step=2), expected)

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
        self.assertEqual(get_abstract_pseudocode(code, indent_step=2), expected)

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
        self.assertEqual(get_abstract_pseudocode(code, indent_step=2), expected)

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
        self.assertEqual(get_abstract_pseudocode(code, indent_step=2), expected)

    def test_ternary_operator(self):
        code = "void t() { int a = x ? y : z; }"
        expected = (
            "type id(){\n"
            "  type id = (id ? id : id);\n"
            "}"
        )
        self.assertEqual(get_abstract_pseudocode(code, indent_step=2), expected)

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
        
        self.assertEqual(get_abstract_pseudocode(code, indent_step=2), expected)
        
    def test_field_access_arrow(self):
        code = "void f() { x->y = 1; z.w = 2; }"
        expected = (
            "type id(){\n"
            "  id->id = num;\n"
            "  id.id = num;\n"
            "}"
        )
        self.assertEqual(get_abstract_pseudocode(code, indent_step=2), expected)
    
    def test_operators(self):
        code = "void op() { a = b + c; d = e && f; g = h == i; }"
        expected = (
            "type id(){\n"
            "  id = id op id;\n"
            "  id = id && id;\n"
            "  id = id == id;\n"
            "}"
        )
        self.assertEqual(get_abstract_pseudocode(code, indent_step=2), expected)

def get_diff_text(text_a, text_b, context_lines=3):

    a_lines = text_a.splitlines()
    b_lines = text_b.splitlines()
    
    diff = difflib.unified_diff(
        a_lines, 
        b_lines, 
        fromfile='Candidate A', 
        tofile='Candidate B', 
        n=context_lines,
        lineterm=''
    )
    
    diff_str = "\n".join(diff)
        
    return diff_str



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
        char c = b[0];
        f->g(h[i]);
        (*(int *)(p + 4)) = 5;
    }   
    """

    # code="""
    # void file_replace(struct magic_set *ms, const char *pat, const char *rep)
    # {
    #     file_regex_t rx;
    #     int rc, rv = -1;
    #     }
    # """

    print(get_abstract_pseudocode(code, indent_step=2)) #get_diff_text(get_abstract_pseudocode(code, indent_step=2), get_abstract_pseudocode(code2, indent_step=2)))