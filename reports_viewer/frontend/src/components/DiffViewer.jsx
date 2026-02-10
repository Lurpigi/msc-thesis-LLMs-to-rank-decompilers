import React, { useMemo } from 'react';
import * as Diff from 'diff';
import clsx from 'clsx';

const CodeBlock = ({ title, content, diff, type }) => {
    return (
        <div className="flex-1 bg-white border border-gray-200 rounded-lg overflow-hidden shadow-sm min-w-0">
            <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                <h3 className="text-sm font-medium text-gray-700">{title}</h3>
            </div>
            <div className="p-4 overflow-x-auto">
                <pre className="text-xs font-mono whitespace-pre-wrap">
                    {diff ? diff.map((part, index) => {
                         // For diffs, usually we want to hide parts that are NOT relevant for this block?
                         // But here we're passing specific filtered diffs or the whole diff?
                         // If we pass 'type' (base/pr), we can filter here.
                         
                         // Actually, the previous manual logic was:
                         // Base: if (part.added) return null; apply removed color.
                         // PR: if (part.removed) return null; apply added color.
                         
                        if (type === 'base' && part.added) return null;
                        if (type === 'pr' && part.removed) return null;

                        let color = 'text-gray-800';
                        if (type === 'base' && part.removed) color = 'bg-red-100 text-red-900';
                        if (type === 'pr' && part.added) color = 'bg-green-100 text-green-900';
                        
                        // If no type (Source), just show text (handled by content prop usually)
                        return <span key={index} className={color}>{part.value}</span>
                    }) : (
                        <code className="text-gray-800">{content}</code>
                    )}
                </pre>
            </div>
        </div>
    );
};

export default function DiffViewer({ func, prData, showCode, showSource }) {
    const baseContent = showCode ? func.function_base : func.base_ast;
    const prContent = showCode ? func.function_pr : func.pr_ast;
    const sourceContent = showCode ? func.source_code : func.source_ast;

    // Calculate Diff
    const diff = useMemo(() => {
        if (!baseContent || !prContent) return [];
        return Diff.diffWords(baseContent, prContent);
    }, [baseContent, prContent]);

    return (
        <div className={`grid grid-cols-1 md:grid-cols-2 ${showSource ? 'lg:grid-cols-3' : ''} gap-6`}>
            {/* Base Block */}
            <CodeBlock 
                title={showCode ? "Base Code" : "Base AST"} 
                diff={diff}
                type="base"
            />

            {/* PR Block */}
            <CodeBlock 
                title={showCode ? "PR Code" : "PR AST"} 
                diff={diff}
                type="pr"
            />

            {/* Source Block (Optional) */}
            {showSource && (
                <CodeBlock 
                    title={showCode ? "Source Code" : "Source AST"} 
                    content={sourceContent}
                />
            )}
        </div>
    );
}
