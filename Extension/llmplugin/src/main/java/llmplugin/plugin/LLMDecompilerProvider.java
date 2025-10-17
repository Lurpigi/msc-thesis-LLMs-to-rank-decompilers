package llmplugin.plugin;


import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.Date;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JToolBar;
import javax.swing.SwingUtilities;

import docking.ComponentProvider;
import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.HTMLUtilities;
import llmplugin.utils.CCodeFormatter;

public class LLMDecompilerProvider extends ComponentProviderAdapter {
    private JTextArea codeTextArea;
    private JPanel panel;
    //private llmpluginPlugin plugin;

    public LLMDecompilerProvider(llmpluginPlugin plugin, String name) {
        super(plugin.getTool(), name, name);
        //this.plugin = plugin;
        buildComponent();
    }

    private void buildComponent() {
        panel = new JPanel(new BorderLayout());
        
        codeTextArea = new JTextArea(25, 80);
        codeTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        codeTextArea.setEditable(false);
        
        JScrollPane scrollPane = new JScrollPane(codeTextArea);
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
                
                // Format the code using the CCodeFormatter
                String formattedCode = CCodeFormatter.formatCCode(code);
                
                String finalOutput = String.format("// LLM Enhanced Decompilation: %s\n// %s\n\n%s", 
                    functionName, new Date(), formattedCode);
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