package llmplugin.utils;

/**
 * Utility class for formatting C code with proper indentation
 */
public class CCodeFormatter {
    
    /**
     * Formats C code with proper indentation
     * @param code the raw C code string to format
     * @return properly formatted C code with indentation
     */
    public static String formatCCode(String code) {
        if (code == null || code.trim().isEmpty()) {
            return code;
        }
        
        // If the code is all on one line, preprocess it
        if (!code.contains("\n")) {
            code = preprocessSingleLineCode(code);
        }
        
        return advancedFormat(code);
    }
    
    /**
     * Preprocesses single-line C code by adding strategic newlines
     */
    private static String preprocessSingleLineCode(String code) {
        StringBuilder result = new StringBuilder();
        boolean inString = false;
        boolean inChar = false;
        boolean inLineComment = false;
        boolean inMultiLineComment = false;
        boolean escapeNext = false;
        
        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);
            char next = (i < code.length() - 1) ? code.charAt(i + 1) : '\0';
            
            // Handle escape characters
            if (escapeNext) {
                result.append(c);
                escapeNext = false;
                continue;
            }
            
            // Handle strings
            if (!inLineComment && !inMultiLineComment && c == '"' && !inChar) {
                inString = !inString;
                result.append(c);
                continue;
            }
            
            // Handle char literals
            if (!inLineComment && !inMultiLineComment && c == '\'' && !inString) {
                inChar = !inChar;
                result.append(c);
                continue;
            }
            
            // Handle escape inside strings/chars
            if ((inString || inChar) && c == '\\') {
                escapeNext = true;
                result.append(c);
                continue;
            }
            
            // Handle multi-line comments
            if (!inString && !inChar && !inLineComment) {
                if (!inMultiLineComment && c == '/' && next == '*') {
                    inMultiLineComment = true;
                    result.append(c).append(next);
                    i++; // skip next char
                    continue;
                } else if (inMultiLineComment && c == '*' && next == '/') {
                    inMultiLineComment = false;
                    result.append(c).append(next);
                    i++; // skip next char
                    
                    // SPECIAL CASE: If after the comment there's a function declaration, add newline
                    if (i + 1 < code.length()) {
                        char afterComment = code.charAt(i + 1);
                        if (Character.isLetter(afterComment) || afterComment == '_') {
                            // Might be the start of a function return type
                            result.append('\n');
                        }
                    }
                    continue;
                }
            }
            
            // Handle single-line comments
            if (!inString && !inChar && !inMultiLineComment && c == '/' && next == '/') {
                inLineComment = true;
            }
            
            result.append(c);
            
            // Add newline at strategic points (only if not in strings/comments)
            if (!inString && !inChar && !inLineComment && !inMultiLineComment) {
                // SPECIAL CASE: After multi-line comments preceding function declarations
                if (i >= 2 && code.charAt(i-1) == '/' && code.charAt(i-2) == '*') {
                    // This is handled above in the multi-line comment block
                }
                // After semicolon
                else if (c == ';') {
                    result.append('\n');
                }
                // After braces
                else if (c == '{' || c == '}') {
                    result.append('\n');
                }
                // Before else, if, while in certain contexts
                else if (i < code.length() - 2) {
                    String nextChars = code.substring(i + 1, Math.min(i + 6, code.length()));
                    if ((c == '}' && nextChars.startsWith("else")) ||
                        (c == '}' && nextChars.startsWith("while")) ||
                        (c == ';' && nextChars.startsWith("if"))) {
                        result.append('\n');
                    }
                }
            }
            
            // End of line comment (when encountering newline, but here we don't have newline)
            if (inLineComment && (c == '\n' || i == code.length() - 1)) {
                inLineComment = false;
            }
        }
        
        return result.toString();
    }
    
    /**
     * Advanced formatting with proper indentation
     */
    private static String advancedFormat(String code) {
        StringBuilder formatted = new StringBuilder();
        int indentLevel = 0;
        boolean inMultiLineComment = false;
        String[] lines = code.split("\n");
        
        for (int lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            String originalLine = lines[lineIndex];
            String line = originalLine.trim();
            
            if (line.isEmpty()) {
                formatted.append("\n");
                continue;
            }
            
            // Handle multi-line comments
            if (inMultiLineComment || line.startsWith("/*")) {
                boolean commentEnded = false;
                if (line.contains("*/")) {
                    inMultiLineComment = false;
                    commentEnded = true;
                } else if (line.startsWith("/*") && !line.contains("*/")) {
                    inMultiLineComment = true;
                }
                
                // Add indentation for multi-line comments
                for (int i = 0; i < indentLevel; i++) {
                    formatted.append("\t");
                }
                formatted.append(line).append("\n");
                
                if (commentEnded) {
                    inMultiLineComment = false;
                }
                continue;
            }
            
            // Handle single-line comments
            if (line.startsWith("//")) {
                for (int i = 0; i < indentLevel; i++) {
                    formatted.append("\t");
                }
                formatted.append(line).append("\n");
                continue;
            }
            
            // SPECIAL CASE: If the line is a multi-line comment followed by code on the same line
            if (line.contains("*/") && line.indexOf("*/") < line.length() - 2) {
                int commentEnd = line.indexOf("*/") + 2;
                String commentPart = line.substring(0, commentEnd).trim();
                String codePart = line.substring(commentEnd).trim();
                
                // Add the comment
                for (int i = 0; i < indentLevel; i++) {
                    formatted.append("\t");
                }
                formatted.append(commentPart).append("\n");
                
                // Process the code part as a new line
                lines[lineIndex] = codePart;
                lineIndex--; // Reprocess this line as code
                continue;
            }
            
            // Decrease indentation before processing the line
            String trimmed = line.trim();
            if (trimmed.startsWith("}") || 
                trimmed.startsWith("} else") || 
                trimmed.startsWith("})") || 
                trimmed.endsWith("};")) {
                indentLevel = Math.max(0, indentLevel - 1);
            }
            
            // Add current indentation
            for (int i = 0; i < indentLevel; i++) {
                formatted.append("\t");
            }
            
            formatted.append(trimmed).append("\n");
            
            // Increase indentation after processing the line
            if (trimmed.endsWith("{") || 
                (trimmed.startsWith("struct") && trimmed.endsWith("{")) ||
                (trimmed.startsWith("enum") && trimmed.endsWith("{")) ||
                (trimmed.startsWith("union") && trimmed.endsWith("{")) ||
                trimmed.startsWith("case") || 
                trimmed.startsWith("default:")) {
                indentLevel++;
            }
            
            // Special handling for if/for/while without braces
            if ((trimmed.startsWith("if ") || trimmed.startsWith("for ") || trimmed.startsWith("while ")) &&
                !trimmed.endsWith("{") && !trimmed.endsWith(";")) {
                // Check if next line is a single statement
                if (lineIndex < lines.length - 1) {
                    String nextLine = lines[lineIndex + 1].trim();
                    if (!nextLine.isEmpty() && !nextLine.startsWith("//") && !nextLine.startsWith("/*") &&
                        !nextLine.equals("}") && !nextLine.startsWith("else")) {
                        indentLevel++;
                    }
                }
            }
        }
        
        return formatted.toString();
    }
    
    /**
     * Simple formatting for quick results - IMPROVED to handle comments on the same line
     */
    public static String simpleFormat(String code) {
        if (code == null || code.trim().isEmpty()) {
            return code;
        }
        
        // If the code is all on one line, preprocess it
        if (!code.contains("\n")) {
            code = preprocessSingleLineCode(code);
        }
        
        StringBuilder formatted = new StringBuilder();
        int indentLevel = 0;
        String[] lines = code.split("\n");
        
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                formatted.append("\n");
                continue;
            }
            
            // SPECIAL CASE: Handle multi-line comments followed by code on the same line
            if (trimmed.contains("*/") && trimmed.indexOf("*/") < trimmed.length() - 2) {
                int commentEnd = trimmed.indexOf("*/") + 2;
                String commentPart = trimmed.substring(0, commentEnd);
                String codePart = trimmed.substring(commentEnd).trim();
                
                // Add the comment with current indentation
                for (int i = 0; i < indentLevel; i++) {
                    formatted.append("\t");
                }
                formatted.append(commentPart).append("\n");
                
                // Process the code part with the same indentation
                for (int i = 0; i < indentLevel; i++) {
                    formatted.append("\t");
                }
                formatted.append(codePart).append("\n");
                continue;
            }
            
            // Skip pure comment lines for indentation calculation
            boolean isPureComment = trimmed.startsWith("//") || 
                                   (trimmed.startsWith("/*") && trimmed.endsWith("*/"));
            
            // Decrease indent before lines that close blocks
            if (!isPureComment && (trimmed.startsWith("}") || trimmed.equals(");") || 
                trimmed.startsWith("} else") || trimmed.startsWith("} while"))) {
                indentLevel = Math.max(0, indentLevel - 1);
            }
            
            // Add current indentation
            for (int i = 0; i < indentLevel; i++) {
                formatted.append("\t");
            }
            
            formatted.append(trimmed).append("\n");
            
            // Increase indent after lines that open blocks (only if not pure comment)
            if (!isPureComment) {
                if (trimmed.endsWith("{") || 
                    (trimmed.startsWith("struct") && trimmed.contains("{")) ||
                    (trimmed.startsWith("enum") && trimmed.contains("{")) ||
                    (trimmed.startsWith("union") && trimmed.contains("{"))) {
                    indentLevel++;
                }
                
                // Special case for else without braces
                if (trimmed.startsWith("else") && !trimmed.endsWith("{") && !trimmed.endsWith(";")) {
                    indentLevel++;
                }
            }
        }
        
        return formatted.toString();
    }
    
    /**
     * NEW METHOD: Formatting specifically for cases where comments are attached to code
     */
    public static String formatWithCommentHandling(String code) {
        if (code == null || code.trim().isEmpty()) {
            return code;
        }
        
        // First separate multi-line comments from code on the same line
        code = separateCommentsFromCode(code);
        
        // Then apply simple formatting
        return simpleFormat(code);
    }
    
    /**
     * Separates multi-line comments from code on the same line
     */
    private static String separateCommentsFromCode(String code) {
        StringBuilder result = new StringBuilder();
        boolean inMultiLineComment = false;
        boolean inString = false;
        boolean inChar = false;
        StringBuilder currentLine = new StringBuilder();
        
        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);
            char next = (i < code.length() - 1) ? code.charAt(i + 1) : '\0';
            
            // Handle strings and chars
            if (!inMultiLineComment) {
                if (c == '"' && !inChar) inString = !inString;
                if (c == '\'' && !inString) inChar = !inChar;
            }
            
            // Handle multi-line comments
            if (!inString && !inChar) {
                if (!inMultiLineComment && c == '/' && next == '*') {
                    // If we have code before the comment, add it
                    if (currentLine.length() > 0) {
                        result.append(currentLine.toString()).append("\n");
                        currentLine = new StringBuilder();
                    }
                    inMultiLineComment = true;
                    currentLine.append("/*");
                    i++; // skip next char
                    continue;
                } else if (inMultiLineComment && c == '*' && next == '/') {
                    currentLine.append("*/");
                    i++; // skip next char
                    result.append(currentLine.toString()).append("\n");
                    currentLine = new StringBuilder();
                    inMultiLineComment = false;
                    continue;
                }
            }
            
            if (inMultiLineComment) {
                currentLine.append(c);
            } else {
                currentLine.append(c);
                
                // If we find a newline, process the current line
                if (c == '\n') {
                    result.append(currentLine.toString());
                    currentLine = new StringBuilder();
                }
            }
        }
        
        // Add the last line if present
        if (currentLine.length() > 0) {
            result.append(currentLine.toString());
        }
        
        return result.toString();
    }
}