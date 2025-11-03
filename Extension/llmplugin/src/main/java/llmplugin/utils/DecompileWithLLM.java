package llmplugin.utils;

import ghidra.app.decompiler.*;
import ghidra.app.services.ConsoleService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;

public class DecompileWithLLM {
    private ConsoleService console;
    private static final String FLASK_API_URL = "http://localhost:8900/generate";

    
    public DecompileWithLLM(ConsoleService console) {
        this.console = console;
    }
    
    public DecompileWithLLM() {
	}

    /**
	 * Enhance the decompiler output using multiple styles and an LLM to choose the best one.
	 */
    public String enhanceDecompiler(Program program, Function func, TaskMonitor monitor) {
    	DecompInterface ifc = null;
        try {
            DecompileOptions options = new DecompileOptions();
            ifc = new DecompInterface();
            ifc.setOptions(options);
            ifc.openProgram(program);

            String[] styles = {"different", "decompile"};
            Map<String, String> results = new LinkedHashMap<>();

            printLog.log("Starting decompilation styles...", this, console);
            for (String style : styles) {
                if(ifc.setSimplificationStyle(style))
                	printLog.log("Set simplification style to: " + style, this, console);
				else
					printLog.warn("Failed to set simplification style to: " + style, this, console);
                if (monitor.isCancelled()) {
					printLog.log("Decompilation cancelled by user.", this, console);
					return "// Decompilation cancelled.";
				}
                DecompileResults res = ifc.decompileFunction(func, 60, monitor);

                if (!res.decompileCompleted()) {
                    results.put(style, "// decomp failed: " + res.getErrorMessage());
                } else {
                    ClangTokenGroup markup = res.getCCodeMarkup();
                    if (markup != null) {
                        results.put(style, markup.toString());
                    } else {
                        results.put(style, "// Decompilation produced no C code for style: " + style);
                    }
                }
            }
            ifc.closeProgram();

            // Prepare prompt for LLM
            StringBuilder prompt = new StringBuilder("You are an expert in reverse engineering and C/C++ code analysis.\n"
                    + "You will be given multiple decompilation outputs of the same binary.\n"
                    + "Your task is to choose the most human and the one with less perplexity using **only the structural readability of the code**, not variable naming or stylistic details.\n");
            int idx = 1;
            for (Map.Entry<String, String> e : results.entrySet()) {
                prompt.append("Version ").append(idx).append(" (").append(clearCode.clean(e.getKey())).append("):\n")
                      .append(e.getValue()).append("\n\n");
                idx++;
            }
            prompt.append("Answer ONLY with the number of the version you choose:");

            if (monitor.isCancelled()) {
				printLog.log("Decompilation cancelled by user.", this, console);
				return "// Decompilation cancelled.";
            }
            printLog.log("Prompt sent to LLM:\n" + prompt.toString(), this, console);
            
            // Query the Flask HuggingFace service
            FlaskLLMResponse llmResponse = queryFlaskService(prompt.toString());
            
            if (llmResponse == null) {
                printLog.warn("LLM service returned null response. Falling back to default.", this, console);
                return results.get(styles[0]);
            }
            
            int choice = llmResponse.getChoice();
            if (choice <= 0 || choice > styles.length) {
                printLog.warn("LLM returned invalid choice: " + choice + ". Falling back to default.", this, console);
                choice = 1; // Fallback
            }
            
            // Get the chosen code and prepend perplexity as comment
            String chosenCode = results.get(styles[choice-1]);
            return formatCodeWithPerplexity(chosenCode, llmResponse.getPerplexity(), 
                                                                llmResponse.getMeanLogbits(), func.getName());

        } catch (Exception e) {
            printLog.err("Error during decompilation enhancement: " + e.getMessage(), this, console);
            throw new RuntimeException("Failed to enhance decompiler", e);
        } finally {
            try { ifc.closeProgram(); } catch (Exception ignore) {}
        }
    }

    /**
     * Send a prompt to the Flask HuggingFace service
     */
    private FlaskLLMResponse queryFlaskService(String prompt) {
        HttpClient client = HttpClient.newHttpClient();
        
        // Prepare JSON payload for Flask service
        String jsonPayload = String.format("{\"prompt\": \"%s\"}", escapeJson(prompt));
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(FLASK_API_URL))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofMinutes(10)) // Increased timeout for HuggingFace
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload, StandardCharsets.UTF_8))
                .build();

        try {
            printLog.log("Sending request to Flask HuggingFace API...", this, console);
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                String responseBody = response.body();
                printLog.log("Received response from Flask API: " + responseBody, this, console);
                
                return parseFlaskResponse(responseBody);
            }
			printLog.err("Flask API returned error status: " + response.statusCode() + " - " + response.body(), this, console);
        } catch (IOException | InterruptedException e) {
            printLog.err("Failed to query Flask API: " + e.getMessage(), this, console);
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt(); // Restore interrupted status
            }
        }
        return null;
    }

    private int extractFirstDigitFromString(String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isDigit(c)) {
                return c - '0';
            }
        }
        return 0;
    }

    
    /**
     * Parse the Flask service response
     */
    private FlaskLLMResponse parseFlaskResponse(String responseBody) {
        try {
            JsonElement rootElement = JsonParser.parseString(responseBody);
            JsonObject root = rootElement.getAsJsonObject();

            String generatedText = "";
            if (root.has("generated_text") && root.get("generated_text").isJsonPrimitive()) {
                generatedText = root.get("generated_text").getAsString().trim();
            }

            Double perplexity = null;
            if (root.has("input_perplexity") && root.get("input_perplexity").isJsonPrimitive()) {
                perplexity = root.get("input_perplexity").getAsDouble();
            }

            Double meanLogbits = null;
            if (root.has("input_mean_logbits") && root.get("input_mean_logbits").isJsonPrimitive()) {
                meanLogbits = root.get("input_mean_logbits").getAsDouble();
            }

            int choice = extractFirstDigitFromString(generatedText);

            return new FlaskLLMResponse(choice, perplexity, meanLogbits, generatedText);
        } catch (Exception e) {
            printLog.err("Error parsing Flask response with Gson: " + e.getMessage(), this, console);
            return null;
        }
    }
    
    /**
     * Extract choice number from generated text
     */
    private int extractChoiceFromText(String generatedText) {
        if (generatedText == null || generatedText.isEmpty()) {
            return 0;
        }
        
        // Look for the first number in the generated text
        Pattern numberPattern = Pattern.compile("\\d+");
        Matcher numberMatcher = numberPattern.matcher(generatedText);
        
        if (numberMatcher.find()) {
            try {
                return Integer.parseInt(numberMatcher.group());
            } catch (NumberFormatException e) {
                printLog.warn("Failed to parse choice number from: " + numberMatcher.group(), this, console);
            }
        }
        
        printLog.warn("No valid choice number found in generated text: " + generatedText, this, console);
        return 0;
    }
    
    /**
     * Format the code with perplexity information as the first comment
     */
    private String formatCodeWithPerplexity(String code, Double perplexity, Double meanLogbits, String functionName) {
        StringBuilder sb = new StringBuilder();
        
        // Add perplexity and metrics as the first comment
        if (perplexity != null) {
            sb.append("/* Perplexity: ").append(String.format("%.4f", perplexity)).append(" */");
        }
        if (meanLogbits != null) {
            sb.append("/* Mean Logbits: ").append(String.format("%.4f", meanLogbits)).append(" */");
        }
        sb.append(code);
        
        return sb.toString();
    }

    /**
	 * Escape special characters in JSON strings.
	 */
    private String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
    
    /**
     * Inner class to hold Flask service response data
     */
    private static class FlaskLLMResponse {
        private int choice;
        private Double perplexity;
        private Double meanLogbits;
        private String generatedText;
        
        public FlaskLLMResponse(int choice, Double perplexity, Double meanLogbits, String generatedText) {
            this.choice = choice;
            this.perplexity = perplexity;
            this.meanLogbits = meanLogbits;
            this.generatedText = generatedText;
        }
        
        public int getChoice() { return choice; }
        public Double getPerplexity() { return perplexity; }
        public Double getMeanLogbits() { return meanLogbits; }
        public String getGeneratedText() { return generatedText; }
    }
}