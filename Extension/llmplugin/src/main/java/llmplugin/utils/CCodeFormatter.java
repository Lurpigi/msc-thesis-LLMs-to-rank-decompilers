package llmplugin.utils;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

/**
 * Utility class for formatting C code with proper indentation
 */
public class CCodeFormatter {
    
    /**
     * Formats C code with proper indentation
     * @param code the raw C code string to format
     * @return properly formatted C code with indentation
     * @throws InterruptedException 
     * @throws IOException 
     */
    public static String formatCCode(String code) throws IOException, InterruptedException {
        if (code == null || code.trim().isEmpty()) {
            return code;
        }
        
        
        // If the code is all on one line, preprocess it
        if (!code.contains("\n")) {
            code = preprocessSingleLineCode(code);
        }
        
        return advancedFormat(code).replace("*/", "*/\n");
    }
    
    public static String formatWithClangFormat(String rawCode) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder("clang-format", "-style=Google"); // o il tuo stile preferito
        Process proc = pb.start();

        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(proc.getOutputStream()))) {
            writer.write(rawCode);
            // può essere necessario flush e chiudere lo stream di input:
            writer.flush();
        }

        // Leggi l’output formattato
        StringBuilder formatted = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                formatted.append(line).append("\n");
            }
        }

        int exit = proc.waitFor();
        if (exit != 0) {
            // qualcosa è andato storto, puoi leggere stderr per diagnostica
            try (BufferedReader err = new BufferedReader(new InputStreamReader(proc.getErrorStream()))) {
                String errLine;
                StringBuilder errMsg = new StringBuilder();
                while ((errLine = err.readLine()) != null) {
                    errMsg.append(errLine).append("\n");
                }
                throw new RuntimeException("clang-format failed: " + errMsg);
            }
        }
        return formatted.toString();
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
                // After semicolons (but not in for loops)
                if (c == ';') {
                    // Check if this is part of a for loop
                    boolean isForLoop = false;
                    int j = i - 1;
                    int parenCount = 0;
                    while (j >= 0) {
                        if (code.charAt(j) == '(') parenCount++;
                        else if (code.charAt(j) == ')') parenCount--;
                        else if (code.charAt(j) == 'f' && j >= 2 && 
                                 code.substring(j-2, j+1).equals("for")) {
                            isForLoop = (parenCount > 0);
                            break;
                        }
                        j--;
                    }
                    
                    if (!isForLoop) {
                        result.append('\n');
                    }
                }
                // After braces
                else if (c == '{' || c == '}') {
                    result.append('\n');
                }
            }
            
            // Reset line comment at end of line (simulated)
            if (inLineComment && i == code.length() - 1) {
                inLineComment = false;
            }
        }
        
        return result.toString();
    }
    
    /**
     * Advanced formatting with proper indentation - IMPROVED VERSION
     */
    private static String advancedFormat(String code) {
        StringBuilder formatted = new StringBuilder();
        int indentLevel = 0;
        boolean inMultiLineComment = false;
        String[] lines = code.split("\n");
        
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            
            if (line.isEmpty()) {
                formatted.append("\n");
                continue;
            }
            
            // Handle multi-line comments
            if (inMultiLineComment || line.startsWith("/*")) {
                if (line.contains("*/")) {
                    inMultiLineComment = false;
                    // Add proper indentation for comment
                    for (int j = 0; j < indentLevel; j++) {
                        formatted.append("    ");
                    }
                    formatted.append(line).append("\n");
                } else {
                    inMultiLineComment = true;
                    // Add proper indentation for comment
                    for (int j = 0; j < indentLevel; j++) {
                        formatted.append("    ");
                    }
                    formatted.append(line).append("\n");
                }
                continue;
            }
            
            // Handle single-line comments
            if (line.startsWith("//")) {
                for (int j = 0; j < indentLevel; j++) {
                    formatted.append("    ");
                }
                formatted.append(line).append("\n");
                continue;
            }
            
            // Decrease indentation for closing braces
            if (line.startsWith("}") || line.equals(");") || 
                line.startsWith("} else") || line.startsWith("} while") ||
                line.startsWith("} else if")) {
                indentLevel = Math.max(0, indentLevel - 1);
            }
            
            // Add current indentation
            for (int j = 0; j < indentLevel; j++) {
                formatted.append("    ");
            }
            
            formatted.append(line).append("\n");
            
            // Increase indentation for opening braces and other block starters
            if (line.endsWith("{") || 
                (line.startsWith("struct") && line.endsWith("{")) ||
                (line.startsWith("enum") && line.endsWith("{")) ||
                (line.startsWith("union") && line.endsWith("{")) ||
                (line.startsWith("case") && line.endsWith(":")) ||
                line.equals("default:")) {
                indentLevel++;
            }
            
            // Special case: if statement without braces
            if ((line.startsWith("if ") || line.startsWith("for ") || line.startsWith("while ")) &&
                !line.endsWith("{") && !line.endsWith(";")) {
                // Check if next line is a single statement
                if (i + 1 < lines.length) {
                    String nextLine = lines[i + 1].trim();
                    if (!nextLine.isEmpty() && !nextLine.startsWith("//") && !nextLine.startsWith("/*") &&
                        !nextLine.equals("}") && !nextLine.startsWith("else")) {
                        indentLevel++;
                    }
                }
            }
        }
        
        return formatted.toString();
    }
}