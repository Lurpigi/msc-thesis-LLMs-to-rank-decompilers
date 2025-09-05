package llmplugin.utils;

import ghidra.app.decompiler.*;
import ghidra.app.services.ConsoleService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DecompileWithLLM {
    private String llamaModel;
    private ConsoleService console;
    private static final String OLLAMA_API_URL = "http://localhost:11434/api/generate";

    public DecompileWithLLM(String llamaModel) {
        this.llamaModel = llamaModel;
    }
    
    public DecompileWithLLM(String llamaModel, ConsoleService console) {
        this.llamaModel = llamaModel;
        this.console = console;
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

                String[] styles = {"decompile", "normalize", "firstpass", "register"};
                Map<String, String> results = new LinkedHashMap<>();

                printLog.log("Starting decompilation styles...", this, console);
                for (String style : styles) {
                    ifc.setSimplificationStyle(style);
                    ifc.resetDecompiler();
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
                printLog.log("Decompilation styles completed. Preparing to query LLM...", this, console);

                // Prepare prompt for LLM
                StringBuilder prompt = new StringBuilder("You are an expert in reverse engineering and C/C++ code analysis.\n"
                        + "You will be given multiple decompilation outputs of the same binary.\n"
                        + "Your task is to choose the most human and the one with less perplexity using **only the structural readability of the code**, not variable naming or stylistic details.\n");
                int idx = 0;
                for (Map.Entry<String, String> e : results.entrySet()) {
                    prompt.append("Version ").append(idx).append(" (").append(e.getKey()).append("):\n")
                          .append(e.getValue()).append("\n\n");
                    idx++;
                }
                prompt.append("Answer ONLY with the number of the version you choose (es. '2'):");

                if (monitor.isCancelled()) {
					printLog.log("Decompilation cancelled by user.", this, console);
					return "// Decompilation cancelled.";
                }
                printLog.log("Prompt sent to LLM:\n" + prompt.toString(), this, console);
                int choice = queryLLMChoice(prompt.toString());
                if (choice < 0 || choice >= styles.length) {
                    printLog.warn("LLM returned invalid choice: " + choice + ". Falling back to default.", this, console);
                    choice = 0; // Fallback
                }
                return results.get(styles[choice]);

            } catch (Exception e) {
                printLog.err("Error during decompilation enhancement: " + e.getMessage(), this, console);
                // By throwing a RuntimeException, we cause the CompletableFuture to complete exceptionally.
                throw new RuntimeException("Failed to enhance decompiler", e);
            } finally {
                    try { ifc.closeProgram(); } catch (Exception ignore) {}
                }
       
    }

    /**
     * Send a prompt to the LLM via Ollama API on a background thread and get the result.
     */
    private int queryLLMChoice(String prompt) {

            HttpClient client = HttpClient.newHttpClient();
            String jsonPayload = String.format("{\"model\": \"%s\", \"prompt\": \"%s\", \"stream\": false}",
                    llamaModel, escapeJson(prompt));
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(OLLAMA_API_URL))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofMinutes(1))
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload, StandardCharsets.UTF_8))
                    .build();

            try {
                printLog.log("Sending request to Ollama API...", this, console);
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 200) {
                    String responseBody = response.body();
                    Pattern pattern = Pattern.compile("\"response\"\\s*:\\s*\"(.*?)\"");
                    Matcher matcher = pattern.matcher(responseBody.replace("\\n", " "));
                    
                    if (matcher.find()) {
                        String llmOutput = matcher.group(1).trim();
                        for (String token : llmOutput.split("\\s+")) {
                            try {
                                return Integer.parseInt(token.replaceAll("[^0-9]", ""));
                            } catch (NumberFormatException ignored) { /* continue */ }
                        }
                    }
                    printLog.warn("LLM response did not contain a valid choice. Response: " + responseBody, this, console);
                } else {
                    printLog.err("Ollama API returned error status: " + response.statusCode() + " - " + response.body(), this, console);
                }
            } catch (IOException | InterruptedException e) {
                printLog.err("Failed to query Ollama API: " + e.getMessage(), this, console);
                 if (e instanceof InterruptedException) {
                    Thread.currentThread().interrupt(); // Restore interrupted status
                }
            }
            return 0; // Default choice on failure
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
}



