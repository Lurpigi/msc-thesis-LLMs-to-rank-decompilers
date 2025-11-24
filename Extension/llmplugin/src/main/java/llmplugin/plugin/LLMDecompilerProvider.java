package llmplugin.plugin;


import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
import java.util.Date;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JToolBar;
import javax.swing.SwingUtilities;

import ghidra.framework.plugintool.ComponentProviderAdapter;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

public class LLMDecompilerProvider extends ComponentProviderAdapter {
    private RSyntaxTextArea codeTextArea;
    private JPanel panel;
    //private llmpluginPlugin plugin;

    public LLMDecompilerProvider(llmpluginPlugin plugin, String name) {
        super(plugin.getTool(), name, name);
        //this.plugin = plugin;
        buildComponent();
    }

    private void buildComponent() {
    	panel = new JPanel(new BorderLayout());

        //RSyntaxTextArea
        codeTextArea = new RSyntaxTextArea(25, 80);
        codeTextArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_C); // Set language to C
        codeTextArea.setCodeFoldingEnabled(true); // Optional: enables code folding
        codeTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        codeTextArea.setEditable(false);

        // Use RTextScrollPane to enable line numbers and other features
        JScrollPane scrollPane = new RTextScrollPane(codeTextArea);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Add toolbar with clear, copy buttons
        JToolBar toolbar = new JToolBar();
        //JButton clearButton = new JButton("Clear");
        JButton copyButton = new JButton("Copy");
        
        //clearButton.addActionListener(e -> clearDisplay());
        copyButton.addActionListener(e -> copyToClipboard());
        
        //toolbar.add(clearButton);
        toolbar.add(copyButton);
        panel.add(toolbar, BorderLayout.NORTH);
    }

    public void displayEnhancedCode(final String functionName, final String code) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                String title = "LLM Enhanced: " + functionName;
                setSubTitle(title);
                
                
                String finalOutput = String.format("// LLM Enhanced Decompilation: %s\n%s", 
                    functionName, code);
                codeTextArea.setText(finalOutput);
                
                // Make sure the provider is visible
                tool.showComponentProvider(LLMDecompilerProvider.this, true);
            }
        });
    }
    

    private void clearDisplay() {
        codeTextArea.setText("");
        setSubTitle("");
    }

    private void copyToClipboard() {
        StringSelection selection = new StringSelection(codeTextArea.getText());
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(selection, selection);
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }
}