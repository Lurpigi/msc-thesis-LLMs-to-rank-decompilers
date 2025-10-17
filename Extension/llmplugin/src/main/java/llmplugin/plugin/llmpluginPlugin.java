/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package llmplugin.plugin;

import javax.swing.*;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import llmplugin.utils.DecompilationCache;
import llmplugin.utils.DecompileWithLLM;
import llmplugin.utils.printLog;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "using llm to enhance decompilation",
	description = "A plugin that uses large language models (LLMs) to enhance the decompilation process in Ghidra."
)
//@formatter:on
public class llmpluginPlugin extends ProgramPlugin {

    private DecompileWithLLM decompiler;
    private ConsoleService console;
    private Function currentFunction;
    private DecompilationCache cache;
    private LLMDecompilerProvider llmProvider;

    public llmpluginPlugin(PluginTool tool) {
        super(tool);
        this.cache = new DecompilationCache();
        this.llmProvider = new LLMDecompilerProvider(this, "LLM Enhanced Decompilation");
        tool.addComponentProvider(llmProvider, false); // 'false' means not initially visible
        Msg.info(this, "llmplugin Plugin instantiated");
    }

    @Override
    public void init() {
        super.init();

        String model = tool.getOptions("MyPlugin")
                .getString("llm.model", "llama3.2:3b");
        
		console = tool.getService(ConsoleService.class);
		Msg.info(this, "llmpluginPlugin initialized with model: " + model);
		if (console != null) {
			//console.getStdOut().println("Using model: " + model);
			decompiler = new DecompileWithLLM(model,console);
		}else {
			Msg.error(this, "Console Service Not Found - Could not find ConsoleService to display output.");
			decompiler = new DecompileWithLLM(model);
		}
   
    }
    
    
    

    @Override
    protected void locationChanged(ProgramLocation loc) {
        super.locationChanged(loc);
        
        if (loc == null || currentProgram == null) {
            return;
        }
        printLog.log("Location changed: " + loc, this, console);
        Function func = currentProgram.getFunctionManager()
                                      .getFunctionContaining(loc.getAddress());
        if (func != null && !func.equals(currentFunction)) {
        	currentFunction = func;
            new Thread(() -> handleFunction(func)).start();
        }
    }

    private void handleFunction(Function func) {
        // Check cache first
        String functionKey = DecompilationCache.createFunctionKey(currentProgram, func);
        String cachedCode = cache.get(functionKey);
        
        if (cachedCode != null) {
            printLog.log("Using cached LLM enhancement for: " + func.getName(), this, console);
            displayInProvider(func.getName(), cachedCode);
            return;
        }
        
        tool.execute(new Task("LLM Decompile " + func.getName(), true, false, false) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    String code = decompiler.enhanceDecompiler(currentProgram, func, monitor);
                    if (monitor.isCancelled()) return;
                    
                    // Cache the result
                    cache.put(functionKey, code, "llm-enhanced");
                    
                    SwingUtilities.invokeLater(() -> {
                        displayInProvider(func.getName(), code);
                        printLog.log("Code enhanced and cached for " + func.getName(), llmpluginPlugin.this, console);
                    });
                    
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() ->
                        printLog.err("Enhancement failed: " + e.getMessage(), llmpluginPlugin.this, console)
                    );
                }
            }
        });
    }
    
    private void displayInProvider(String functionName, String code) {
        llmProvider.displayEnhancedCode(functionName, code);
    }
    
    @Override
    protected void dispose() {
        if (llmProvider != null) {
            tool.removeComponentProvider(llmProvider);
        }
        super.dispose();
    }
    
    

    

}