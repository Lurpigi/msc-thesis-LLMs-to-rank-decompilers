import unittest
import tree_sitter_c
from tree_sitter import Language, Parser

def get_ast(code, indent_step=0):
    try:
        C_LANGUAGE = Language(tree_sitter_c.language())
        parser = Parser(C_LANGUAGE)
    except Exception as e:
        C_LANGUAGE = Language(tree_sitter_c.language())
        parser = Parser()
        parser.set_language(C_LANGUAGE)

    tree = parser.parse(code.encode('utf8'))
    structure = []
    depth = 0

    def append_indent():
        if indent_step > 0:
            structure.append("\n" + " " * (depth * indent_step))
        else:
            structure.append(" ")

    def traverse(node):
        nonlocal depth

        # Block
        if node.type == 'compound_statement':
            structure.append("{")
            if indent_step > 0:
                depth += 1
            
            for child in node.children:
                if child.type in ['{', '}']: 
                    continue
                
                append_indent()
                traverse(child)

            if indent_step > 0:
                depth -= 1
                append_indent()
            else:
                structure.append(" ")
            
            structure.append("}")
            return
            
        if node.type == 'expression_statement':
            for child in node.children:
                traverse(child)
            # structure.append(";") 
            return
            
        if node.type == 'return_statement':
            structure.append("return")
            for child in node.children:
                if child.type != 'return':
                    #structure.append(" ")
                    traverse(child)
            return

        if node.type == 'if_statement':
            structure.append("if(")
            traverse(node.child_by_field_name('condition'))
            structure.append(")")
            
            traverse(node.child_by_field_name('consequence'))
            
            else_node = node.child_by_field_name('alternative')
            if else_node:
                structure.append("else")
                traverse(else_node)
            return

        if node.type == 'while_statement':
            structure.append("while(")
            traverse(node.child_by_field_name('condition'))
            structure.append(")")
            traverse(node.child_by_field_name('body'))
            return

        if node.type == 'for_statement':
            structure.append("for(")
            for child in node.children_by_field_name('initializer'): traverse(child)
            structure.append(";")
            for child in node.children_by_field_name('condition'): traverse(child)
            structure.append(";")
            for child in node.children_by_field_name('update'): traverse(child)
            structure.append(")")
            traverse(node.child_by_field_name('body'))
            return

        if node.type == 'do_statement':
            structure.append("do")
            traverse(node.child_by_field_name('body'))
            structure.append("while(")
            traverse(node.child_by_field_name('condition'))
            structure.append(")")
            return

        if node.type == 'switch_statement':
            structure.append("switch(")
            traverse(node.child_by_field_name('condition'))
            structure.append("){")
            
            if indent_step > 0:
                depth += 1
            
            body = node.child_by_field_name('body')
            if body:
                for child in body.children:
                    if child.type in ['{', '}']: continue
                    append_indent()
                    traverse(child)
            
            if indent_step > 0:
                depth -= 1
                append_indent()
                
            structure.append("}")
            return

        if node.type == 'case_statement':
            structure.append("case ")
            value = node.child_by_field_name('value')
            if value:
                traverse(value)
            structure.append(":")
            
            # Indent content of case
            if indent_step > 0:
                depth += 1
                
            for child in node.children:
                if child.type not in ['case', ':', 'number_literal'] and child != value:
                    append_indent()
                    traverse(child)
            
            if indent_step > 0:
                depth -= 1
            return

        if node.type == 'goto_statement':
            structure.append("goto label")
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

        # Ternary
        if node.type == 'conditional_expression':
            structure.append("(")
            traverse(node.child_by_field_name('condition'))
            structure.append("? ")
            traverse(node.child_by_field_name('consequence'))
            structure.append(": ")
            traverse(node.child_by_field_name('alternative'))
            structure.append(")")
            return

        # Fallback 
        for child in node.children:
            traverse(child)

    traverse(tree.root_node)
    
    # Clean up leading/trailing whitespace
    return "".join(structure).strip()

class TestGetAst(unittest.TestCase):

    def test_empty_function(self):
        code = "void main() {}"
        self.assertEqual(get_ast(code), "{}")

    def test_function_call(self):
        code = "void main() { foo(); }"
        self.assertEqual(get_ast(code), "{call()}")

    def test_nested_calls(self):
        code = "void main() { foo(bar()); }"
        self.assertEqual(get_ast(code), "{call(call())}")

    def test_if_statement(self):
        code = """
        void test() {
            if (x) {
                foo();
            }
        }
        """
        self.assertEqual(get_ast(code), "{if(){call()}}")

    def test_if_else_statement(self):
        code = """
        void test() {
            if (x) {
                foo();
            } else {
                bar();
            }
        }
        """
        self.assertEqual(get_ast(code), "{if(){call()}else{call()}}")

    def test_if_no_braces(self):
        """Test if without braces (single statement)"""
        code = "void test() { if (x) foo(); }"
        self.assertEqual(get_ast(code), "{if()call()}")

    def test_loops(self):
        code = """
        void loop() {
            while(1) { a(); }
            for(;;) { b(); }
            do { c(); } while(0);
        }
        """
        expected = "{while(){call()}for(){call()}do_while(){call()}}"
        self.assertEqual(get_ast(code), expected)

    def test_switch_case(self):
        code = """
        void s() {
            switch(x) {
                case 1:
                    foo();
                    break;
                case 2:
                    bar();
                    break;
            }
        }
        """
        expected = "{switch(){case:call()case:call()}}"
        self.assertEqual(get_ast(code), expected)

    def test_goto(self):
        code = "void g() { goto label; }"
        self.assertEqual(get_ast(code), "{goto}")

    def test_ternary_operator(self):
        code = "void t() { int a = x ? y : z; }"
        self.assertEqual(get_ast(code), "{(?::)}")

    def test_complex_nesting(self):
        code = """
        void complex() {
            if (cond) {
                while (1) {
                    foo(x ? a : b);
                }
            } else {
                goto error;
            }
        }
        """
        expected = "{if(){while(){call((?::))}}else{goto}}"
        self.assertEqual(get_ast(code), expected)

if __name__ == '__main__':
    #unittest.main()
    code = """
        void complex() {
            if (cond){;}
            if (cond) {
                while (1) {
                    foo(x ? a : b);
                }
            } else {
                goto error;
            }
            int a = b < c;
            std::coco::ax((char)a);
        }
        """
    print(get_ast(code,2))