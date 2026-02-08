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
            if op in ['&&', '||']: structure.append(f" {op} ")
            elif op in ['==', '!=', '<', '>', '<=', '>=']: structure.append(f" {op} ")
            else: structure.append(" op ")
            traverse(node.child_by_field_name('right'))
            return

        if node.type == 'unary_expression':
            op = node.children[0].text.decode('utf8')
            if op == '!': structure.append("!")
            elif op == '-': structure.append("-")
            else: structure.append("op")
            traverse(node.child_by_field_name('argument'))
            return
        
        if node.type == 'update_expression':
            if node.children[0].type in ['++', '--']:
                structure.append("upd ")
                traverse(node.children[1])
            else:
                traverse(node.children[0])
                structure.append(" upd")
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
                if child.type in ['primitive_type', 'type_identifier', 'struct_specifier', ';', 'storage_class_specifier']: continue
                if child.type == 'init_declarator':
                    if not first: structure.append(", ")
                    traverse(child)
                    first = False
                elif child.type == 'identifier':
                     if not first: structure.append(", ")
                     structure.append("id")
                     first = False
            structure.append(";")
            return

        if node.type == 'init_declarator':
             traverse(node.child_by_field_name('declarator'))
             structure.append(" = ")
             traverse(node.child_by_field_name('value'))
             return
        
        if node.type == 'number_literal':
            structure.append("num")
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

        # Leaf nodes
        if node.child_count == 0:
            if node.type in ['identifier', 'field_identifier']:
                structure.append("id")
                return
            if len(node.type) == 1 and node.type in ";,(){}[]":
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

if __name__ == '__main__':
    #unittest.main()
 
    code="xls_error_t xls_parseWorkBook(xlsWorkBook* pWB)\n{\n    if(!pWB) return LIBXLS_ERROR_NULL_ARGUMENT;\n\n    BOF bof1 = { .id = 0, .size = 0 };\n    BOF bof2 = { .id = 0, .size = 0 };\n    BYTE* buf = NULL;\n\tBYTE once = 0;\n    xls_error_t retval = LIBXLS_OK;\n\n    verbose (\"xls_parseWorkBook\");\n    do {\n\t\tif(xls_debug > 10) {\n\t\t\tprintf(\"READ WORKBOOK filePos=%ld\\n\",  (long)pWB->filepos);\n\t\t\tprintf(\"  OLE: start=%d pos=%u size=%u fatPos=%u\\n\",\n                    pWB->olestr->start, (unsigned int)pWB->olestr->pos,\n                    (unsigned int)pWB->olestr->size, (unsigned int)pWB->olestr->fatpos); \n\t\t}\n\n        if (ole2_read(&bof1, 1, 4, pWB->olestr) != 4) {\n            retval = LIBXLS_ERROR_READ;\n            goto cleanup;\n        }\n        xlsConvertBof(&bof1);\n \t\tif(xls_debug) xls_showBOF(&bof1);\n\n        if (bof1.size) {\n            if ((buf = realloc(buf, bof1.size)) == NULL) {\n                if (xls_debug) fprintf(stderr, \"Error: failed to allocate buffer of size %d\\n\", (int)bof1.size);\n                retval = LIBXLS_ERROR_MALLOC;\n                goto cleanup;\n            }\n            if (ole2_read(buf, 1, bof1.size, pWB->olestr) != bof1.size) {\n                if (xls_debug) fprintf(stderr, \"Error: failed to read OLE block\\n\");\n                retval = LIBXLS_ERROR_READ;\n                goto  cleanup;\n            }\n        }\n\n        if (xls_isRecordTooSmall(pWB, &bof1, buf)) {\n            retval = LIBXLS_ERROR_PARSE;\n            goto cleanup;\n        }\n\n        switch (bof1.id) {\n        case XLS_RECORD_EOF:\n            //verbose(\"EOF\");\n            break;\n        case XLS_RECORD_BOF:\t// BIFF5-8\n            pWB->is5ver = (buf[0] + (buf[1] << 8) != 0x600);\n            pWB->type = buf[2] + (buf[3] << 8);\n            if(xls_debug) {\n                printf(\"version: %s\\n\", pWB->is5ver ? \"BIFF5\" : \"BIFF8\" );\n                printf(\"   type: %.2X\\n\", pWB->type);\n            }\n            break;\n\n        case XLS_RECORD_CODEPAGE:\n            pWB->codepage = buf[0] + (buf[1] << 8);\n\t\t\tif(xls_debug) printf(\"codepage: %d\\n\", pWB->codepage);\n            break;\n\n        case XLS_RECORD_CONTINUE:\n\t\t\tif(once) {\n\t\t\t\tif (bof2.id==XLS_RECORD_SST) {\n\t\t\t\t\tif ((retval = xls_appendSST(pWB,buf,bof1.size)) != LIBXLS_OK)\n                        goto cleanup;\n                }\n\t\t\t\tbof1=bof2;\n\t\t\t}\n            break;\n\n\t\tcase XLS_RECORD_WINDOW1:\n\t\t\t{\n\t\t\t\tWIND1 *w = (WIND1*)buf;\n                xlsConvertWindow(w);\n\t\t\t\tpWB->activeSheetIdx = w->itabCur;\n\t\t\t\tif(xls_debug) {\n\t\t\t\t\tprintf(\"WINDOW1: \");\n\t\t\t\t\tprintf(\"xWn    : %d\\n\", w->xWn/20);\n\t\t\t\t\tprintf(\"yWn    : %d\\n\", w->yWn/20);\n\t\t\t\t\tprintf(\"dxWn   : %d\\n\", w->dxWn/20);\n\t\t\t\t\tprintf(\"dyWn   : %d\\n\", w->dyWn/20);\n\t\t\t\t\tprintf(\"grbit  : %d\\n\", w->grbit);\n\t\t\t\t\tprintf(\"itabCur: %d\\n\", w->itabCur);\n\t\t\t\t\tprintf(\"itabFi : %d\\n\", w->itabFirst);\n\t\t\t\t\tprintf(\"ctabSel: %d\\n\", w->ctabSel);\n\t\t\t\t\tprintf(\"wTabRat: %d\\n\", w->wTabRatio);\n\t\t\t\t}\n\t\t\t}\n\t\t\tbreak;\n\n        case XLS_RECORD_SST:\n\t\t\t//printf(\"ADD SST\\n\");\n            xlsConvertSst((SST *)buf);\n            if ((retval = xls_addSST(pWB,(SST*)buf,bof1.size)) != LIBXLS_OK) {\n                goto cleanup;\n            }\n            break;\n\n        case XLS_RECORD_EXTSST:\n            break;\n\n        case XLS_RECORD_BOUNDSHEET:\n\t\t\t{\n\t\t\t\t//printf(\"ADD SHEET\\n\");\n\t\t\t\tBOUNDSHEET *bs = (BOUNDSHEET *)buf;\n                xlsConvertBoundsheet(bs);\n\t\t\t\t// different for BIFF5 and BIFF8\n                if ((retval = xls_addSheet(pWB, bs, bof1.size)) != LIBXLS_OK) {\n                    goto cleanup;\n                }\n\t\t\t}\n            break;\n\n        case XLS_RECORD_XF:\n\t\t\tif(pWB->is5ver) {\n\t\t\t\tXF5 *xf;\n\t\t\t\txf = (XF5 *)buf;\n                xlsConvertXf5(xf);\n\n\t\t\t\tif ((retval = xls_addXF5(pWB,xf)) != LIBXLS_OK) {\n                    goto cleanup;\n                }\n\t\t\t\tif(xls_debug) {\n\t\t\t\t\tprintf(\"   font: %d\\n\", xf->font);\n\t\t\t\t\tprintf(\" format: %d\\n\", xf->format);\n\t\t\t\t\tprintf(\"   type: %.4x\\n\", xf->type);\n\t\t\t\t\tprintf(\"  align: %.4x\\n\", xf->align);\n\t\t\t\t\tprintf(\"rotatio: %.4x\\n\", xf->color);\n\t\t\t\t\tprintf(\"  ident: %.4x\\n\", xf->fill);\n\t\t\t\t\tprintf(\"usedatt: %.4x\\n\", xf->border);\n\t\t\t\t\tprintf(\"linesty: %.4x\\n\", xf->linestyle);\n\t\t\t\t}\n\t\t\t} else {\n\t\t\t\tXF8 *xf;\n\t\t\t\txf = (XF8 *)buf;\n                xlsConvertXf8(xf);\n\n\t\t\t\tif ((retval = xls_addXF8(pWB,xf)) != LIBXLS_OK) {\n                    goto cleanup;\n                }\n\n\t\t\t\tif(xls_debug) {\n\t\t\t\t\txls_showXF(xf);\n\t\t\t\t}\n\t\t\t}\n            break;\n\n        case XLS_RECORD_FONT:\n        case XLS_RECORD_FONT_ALT:\n\t\t\t{\n\t\t\t\tchar *s;\n\t\t\t\tFONT *f = (FONT*)buf;\n                xlsConvertFont(f);\n\t\t\t\ts = xls_addFont(pWB,f, bof1.size);\n\t\t\t\tif(xls_debug) {\n\t\t\t\t\tprintf(\" height: %d\\n\", f->height);\n\t\t\t\t\tprintf(\"   flag: 0x%x\\n\", f->flag);\n\t\t\t\t\tprintf(\"  color: 0x%x\\n\", f->color);\n\t\t\t\t\tprintf(\" weight: %d\\n\", f->bold);\n\t\t\t\t\tprintf(\"escapem: 0x%x\\n\", f->escapement);\n\t\t\t\t\tprintf(\"underln: 0x%x\\n\", f->underline);\n\t\t\t\t\tprintf(\" family: 0x%x\\n\", f->family);\n\t\t\t\t\tprintf(\"charset: 0x%x\\n\", f->charset);\n\t\t\t\t\tif(s) printf(\"   name: %s\\n\", s);\n\t\t\t\t}\n\t\t\t}\n\t\t\tbreak;\n\n        case XLS_RECORD_FORMAT:\n            xlsConvertFormat((FORMAT *)buf);\n            if ((retval = xls_addFormat(pWB, (FORMAT*)buf, bof1.size)) != LIBXLS_OK) {\n                goto cleanup;\n            }\n            break;\n\n\t\tcase XLS_RECORD_STYLE:\n\t\t\tif(xls_debug) {\n\t\t\t\tstruct { unsigned short idx; unsigned char ident; unsigned char lvl; } *styl;\n\t\t\t\tstyl = (void *)buf;\n\n\t\t\t\tprintf(\"    idx: 0x%x\\n\", styl->idx & 0x07FF);\n\t\t\t\tif(styl->idx & 0x8000) {\n\t\t\t\t\tprintf(\"  ident: 0x%x\\n\", styl->ident);\n\t\t\t\t\tprintf(\"  level: 0x%x\\n\", styl->lvl);\n\t\t\t\t} else {\n\t\t\t\t\tchar *s = get_string((char *)&buf[2], bof1.size - 2, 1, pWB);\n\t\t\t\t\tprintf(\"  name=%s\\n\", s);\n                    free(s);\n\t\t\t\t}\n\t\t\t}\n\t\t\tbreak;\n\n        case XLS_RECORD_PALETTE:\n\t\t\tif(xls_debug > 10) {\n\t\t\t\tunsigned char *p = buf + 2;\n\t\t\t\tint idx, len;\n\n\t\t\t\tlen = buf[0] + (buf[1] << 8);\n\t\t\t\tfor(idx=0; idx<len; ++idx) {\n\t\t\t\t\tprintf(\"   Index=0x%2.2x %2.2x%2.2x%2.2x\\n\", idx+8, p[0], p[1], p[2] );\n\t\t\t\t\tp += 4;\n\t\t\t\t}\n\t\t\t}\n\t\t\tbreak;\n\n\t\tcase XLS_RECORD_1904:\n\t\t\tpWB->is1904 = *(BYTE *)buf;\t// the field is a short, but with little endian the first byte is 0 or 1\n\t\t\tif(xls_debug) {\n\t\t\t\tprintf(\"   mode: 0x%x\\n\", pWB->is1904);\n\t\t\t}\n\t\t\tbreak;\n\n\t\tcase XLS_RECORD_FILEPASS:\n\t\t\tretval = LIBXLS_ERROR_UNSUPPORTED_ENCRYPTION;\n\t\t\tgoto cleanup;\n\t\t\n\t\tcase XLS_RECORD_DEFINEDNAME:\n\t\t\tif(xls_debug) {\n\t\t\t\tint i;\n                printf(\"   DEFINEDNAME: \");\n\t\t\t\tfor(i=0; i<bof1.size; ++i) printf(\"%2.2x \", buf[i]);\n\t\t\t\tprintf(\"\\n\");\n\t\t\t}\n\t\t\tbreak;\n\t\t\t\n        default:\n\t\t\tif(xls_debug)\n\t\t\t{\n\t\t\t\t//xls_showBOF(&bof1);\n\t\t\t\tprintf(\"    Not Processed in parseWorkBook():  BOF=0x%4.4X size=%d\\n\", bof1.id, bof1.size);\n\t\t\t}\n            break;\n        }\n        bof2=bof1;\n\t\tonce=1;\n    }\n    while ((!pWB->olestr->eof)&&(bof1.id!=XLS_RECORD_EOF));\n\ncleanup:\n    if (buf)\n        free(buf);\n\n    return retval;\n}\n"

    print(get_abstract_pseudocode(code, indent_step=2))