package llmplugin.utils;

public class clearCode {
	public clearCode() {}
	
	public static String clean(String code) {
		// Remove leading and trailing whitespace
		code = code.trim();
		
		// Remove line numbers (e.g., "1: ", "23: ")
		code = code.replaceAll("(?m)^\\s*\\d+:\\s*", "");
		
		// Remove comments (e.g., "// comment", "/* comment */")
		code = code.replaceAll("//.*", ""); // Single-line comments
		code = code.replaceAll("/\\*.*?\\*/", ""); // Multi-line comments
		
		// Remove extra spaces and tabs
		code = code.replaceAll("[ \\t]+", " ");
		
		// Remove empty lines
		code = code.replaceAll("(?m)^[ \\t]*\\r?\\n", "");
		
		return code.trim();
	}

}
