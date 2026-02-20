import { useState, useEffect } from 'react'
import { Tab, Listbox, ListboxButton, ListboxOption, ListboxOptions } from '@headlessui/react'
import clsx from 'clsx'
import * as Diff from 'diff'
import DogboltLossHeatmap from './DogboltLossHeatmap'

const CodeBlock = ({ title, content, diff, type }) => {
    return (
        <div className="flex-1 bg-white border border-gray-200 rounded-lg overflow-hidden shadow-sm min-w-0">
            <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                <h3 className="text-sm font-medium text-gray-700">{title}</h3>
            </div>
            <div className="p-4 overflow-x-auto">
                <pre className="text-xs font-mono whitespace-pre-wrap">
                    {diff ? diff.map((part, index) => {
                        if (type === 'A' && part.added) return null;
                        if (type === 'B' && part.removed) return null;

                        let color = 'text-gray-800';
                        if (type === 'A' && part.removed) color = 'bg-red-100 text-red-900';
                        if (type === 'B' && part.added) color = 'bg-green-100 text-green-900';
                        
                        return <span key={index} className={color}>{part.value}</span>
                    }) : (
                        <code className="text-gray-800">{content}</code>
                    )}
                </pre>
            </div>
        </div>
    );
};

const getOpt = (binary) => binary?.match(/-O[0-3sz]/)?.[0]?.replace(/-/, '') || '';

const ComparisonRow = ({ item, showCode, showSource, taskLossData }) => {
    const contentA = showCode ? item.code_A : item.ast_A;
    const contentB = showCode ? item.code_B : item.ast_B;
    const sourceContent = showCode ? item.source_code : item.ast_Source;

    const diff = Diff.diffWords(contentA || '', contentB || '');

    const pplA = showCode ? item.perplexity_A : item.perplexity_ast_A;
    const pplB = showCode ? item.perplexity_B : item.perplexity_ast_B;
    const delta = (pplB !== undefined && pplA !== undefined) ? (pplB - pplA) : null;

    return (
        <div className="space-y-4 border-b border-gray-200 pb-12 last:border-0 last:pb-0">
            <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                    <span className="text-sm font-bold text-indigo-600 px-2 py-0.5 bg-indigo-50 rounded border border-indigo-100 uppercase">
                        {item.decompiler_A}
                    </span>
                    <span className="text-gray-400">vs</span>
                    <span className="text-sm font-bold text-indigo-600 px-2 py-0.5 bg-indigo-50 rounded border border-indigo-100 uppercase">
                        {item.decompiler_B}
                    </span>
                </div>
                <div className="flex items-center space-x-6">
                   <div className="flex flex-col items-end">
                        <span className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-1">Perplexity Score</span>
                        <div className="flex space-x-4">
                            <div className="flex flex-col items-center">
                                <span className="text-[10px] text-gray-400 uppercase">A</span>
                                <span className="text-xl font-bold text-gray-700">{pplA?.toFixed(2)}</span>
                            </div>
                            <div className="flex flex-col items-center">
                                <span className="text-[10px] text-gray-400 uppercase">B</span>
                                <span className="text-xl font-bold text-gray-700">{pplB?.toFixed(2)}</span>
                            </div>
                            <div className="flex flex-col items-center border-l border-gray-100 pl-4">
                                <span className="text-[10px] text-gray-400 uppercase">Delta</span>
                                <span className={clsx(
                                    "text-xl font-bold",
                                    delta < 0 ? "text-green-600" : delta > 0 ? "text-red-600" : "text-gray-500"
                                )}>
                                    {delta > 0 ? '+' : ''}{delta?.toFixed(2)}
                                </span>
                            </div>
                            <div className="flex flex-col items-center border-l border-gray-200 pl-4">
                                <span className="text-[10px] text-indigo-400 uppercase">Source</span>
                                <span className="text-xl font-bold text-indigo-600">{(showCode ? item.perplexity_source : item.perplexity_ast_source)?.toFixed(2)}</span>
                            </div>
                        </div>
                   </div>
                </div>
            </div>

            <div className={`grid grid-cols-1 md:grid-cols-2 ${showSource ? 'lg:grid-cols-3' : ''} gap-4`}>
                <CodeBlock title={`Decompiler A: ${item.decompiler_A}`} diff={diff} type="A" />
                <CodeBlock title={`Decompiler B: ${item.decompiler_B}`} diff={diff} type="B" />
                {showSource && <CodeBlock title="Source Code" content={sourceContent} />}
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 mt-4">
                {/* Qualitative Winners */}
                <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-4 overflow-hidden">
                    <div className="flex items-center space-x-2 mb-3 border-b border-gray-100 pb-2">
                        <svg className="h-4 w-4 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                           <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <span className="text-xs font-bold text-gray-800 uppercase tracking-wider">Qualitative Comparison (Blind)</span>
                    </div>
                    <div className="space-y-6">
                        <div>
                            <div className="flex items-center space-x-3 mb-2">
                                <span className="text-xs font-bold text-indigo-500 uppercase tracking-tight">Code Winner:</span>
                                <span className={clsx(
                                    "px-4 py-1.5 rounded-md text-lg font-black uppercase shadow-md leading-none",
                                    item.winner === 'A' ? "bg-yellow-500 text-white ring-2 ring-yellow-100" : 
                                    item.winner === 'B' ? "bg-green-500 text-white ring-2 ring-green-100" : 
                                    item.winner === 'ERROR' ? "bg-red-600 text-white ring-2 ring-red-100" : "bg-gray-400 text-white"
                                )}>
                                    {item.winner || 'TIE'}
                                </span>
                            </div>
                            <p className="text-sm text-gray-700 italic mt-2 leading-relaxed" title={item.motivation}>{item.motivation}</p>
                        </div>
                        <div>
                            <div className="flex items-center space-x-3 mb-2">
                                <span className="text-xs font-bold text-indigo-500 uppercase tracking-tight">AST Winner:</span>
                                <span className={clsx(
                                    "px-4 py-1.5 rounded-md text-lg font-black uppercase shadow-md leading-none",
                                    item.winner_ast === 'A' ? "bg-yellow-500 text-white ring-2 ring-yellow-100" : 
                                    item.winner_ast === 'B' ? "bg-green-500 text-white ring-2 ring-green-100" : 
                                    item.winner_ast === 'ERROR' ? "bg-red-600 text-white ring-2 ring-red-100" : "bg-gray-400 text-white"
                                )}>
                                    {item.winner_ast || 'TIE'}
                                </span>
                            </div>
                            <p className="text-sm text-gray-700 italic mt-2 leading-relaxed" title={item.motivation_ast}>{item.motivation_ast}</p>
                        </div>
                    </div>
                </div>

                {/* Ground Truth Fidelity (S-Winners) */}
                <div className="bg-white rounded-lg border border-indigo-100 shadow-sm p-4 overflow-hidden">
                    <div className="flex items-center space-x-2 mb-3 border-b border-indigo-50 pb-2">
                        <svg className="h-4 w-4 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                           <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <span className="text-xs font-bold text-indigo-800 uppercase tracking-wider">Qualitative Comparison (Ground Truth)</span>
                    </div>
                    <div className="space-y-6">
                        <div>
                            <div className="flex items-center space-x-3 mb-2">
                                <span className="text-xs font-bold text-indigo-500 uppercase tracking-tight">GT Code Winner:</span>
                                <span className={clsx(
                                    "px-4 py-1.5 rounded-md text-lg font-black uppercase shadow-md leading-none",
                                    item.winner_s === 'A' ? "bg-yellow-500 text-white ring-2 ring-yellow-100" : 
                                    item.winner_s === 'B' ? "bg-green-500 text-white ring-2 ring-green-100" : 
                                    item.winner_s === 'ERROR' ? "bg-red-600 text-white ring-2 ring-red-100" : "bg-gray-400 text-white"
                                )}>
                                    {item.winner_s || 'TIE'}
                                </span>
                            </div>
                            <p className="text-sm text-gray-700 italic mt-2 leading-relaxed" title={item.motivation_s}>{item.motivation_s}</p>
                        </div>
                        <div>
                            <div className="flex items-center space-x-3 mb-2">
                                <span className="text-xs font-bold text-indigo-500 uppercase tracking-tight">GT AST Winner:</span>
                                <span className={clsx(
                                    "px-4 py-1.5 rounded-md text-lg font-black uppercase shadow-md leading-none",
                                    item.winner_ast_s === 'A' ? "bg-yellow-500 text-white ring-2 ring-yellow-100" : 
                                    item.winner_ast_s === 'B' ? "bg-green-500 text-white ring-2 ring-green-100" : 
                                    item.winner_ast_s === 'ERROR' ? "bg-red-600 text-white ring-2 ring-red-100" : "bg-gray-400 text-white"
                                )}>
                                    {item.winner_ast_s || 'TIE'}
                                </span>
                            </div>
                            <p className="text-sm text-gray-700 italic mt-2 leading-relaxed" title={item.motivation_ast_s}>{item.motivation_ast_s}</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Token Loss Heatmap */}
            {taskLossData && (
                <DogboltLossHeatmap
                    taskLossData={taskLossData}
                    decompilerA={item.decompiler_A}
                    decompilerB={item.decompiler_B}
                />
            )}
        </div>
    )
}

export default function DogboltBench() {
    const [data, setData] = useState(null)
    const [lossData, setLossData] = useState(null)
    const [selectedModel, setSelectedModel] = useState(null)
    const [selectedBinary, setSelectedBinary] = useState(null)
    const [showSource, setShowSource] = useState(false)
    const [showCode, setShowCode] = useState(false) // false = AST, true = Code

    useEffect(() => {
        // Fetch both report and loss data in parallel
        Promise.all([
            fetch('/data/dogbolt/dogbolt_report.json').then(res => res.json()),
            fetch('/data/dogbolt/dogbolt_report_loss.json').then(res => res.json()),
        ]).then(([reportData, lossJson]) => {
                if (reportData.error) {
                    console.error(reportData.error);
                    return;
                }
                
                // Group data by model_id and binary (moved from backend)
                const structuredData = {};
                Object.entries(reportData).forEach(([model_id, items]) => {
                    structuredData[model_id] = {};
                    items.forEach(item => {
                        const binary = item.binary;
                        if (!structuredData[model_id][binary]) {
                            structuredData[model_id][binary] = [];
                        }
                        structuredData[model_id][binary].push(item);
                    });
                });

                setData(structuredData)
                if (lossJson) setLossData(lossJson)
                const models = Object.keys(structuredData);
                if (models.length > 0) {
                    setSelectedModel(models[0]);
                    const binaries = Object.keys(structuredData[models[0]]);
                    if (binaries.length > 0) setSelectedBinary(binaries[0]);
                }
            })
    }, [])

    const handleModelChange = (model) => {
        setSelectedModel(model);
        const binaries = Object.keys(data[model]);
        if (binaries.length > 0) setSelectedBinary(binaries[0]);
    }

    if (!data) return <div className="text-center py-12 text-gray-500">Loading Dogbolt reports...</div>

    const models = Object.keys(data);
    const binaries = selectedModel ? Object.keys(data[selectedModel]) : [];
    const currentItems = (selectedModel && selectedBinary) ? data[selectedModel][selectedBinary] : [];

    return (
        <div className="space-y-6">
            {/* Model Tabs */}
            <div className="border-b border-gray-200">
                <nav className="-mb-px flex space-x-8 overflow-x-auto" aria-label="Tabs">
                    {models.map((model) => (
                        <button
                            key={model}
                            onClick={() => handleModelChange(model)}
                            className={clsx(
                                selectedModel === model
                                    ? 'border-indigo-500 text-indigo-600'
                                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300',
                                'whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm'
                            )}
                        >
                            {model}
                        </button>
                    ))}
                </nav>
            </div>

            {/* Binary Selector & Controls */}
            <div className="sticky top-0 z-20 bg-gray-50/80 backdrop-blur-sm -mx-4 px-4 py-4 sm:-mx-6 sm:px-6 mb-6 border-b border-gray-200 shadow-sm">
                <div className="bg-white px-4 py-5 shadow sm:rounded-lg sm:px-6 flex flex-col sm:flex-row justify-between items-center gap-4 border border-gray-100">
                    <div className="w-full sm:w-1/2 relative z-10">
                        <label className="block text-sm font-medium text-gray-700 mb-1">Select Binary</label>
                        <Listbox value={selectedBinary} onChange={setSelectedBinary}>
                            <div className="relative mt-1">
                                <ListboxButton className="relative w-full cursor-default rounded-md bg-white py-2 pl-3 pr-10 text-left border border-gray-300 shadow-sm focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                                    <span className="block truncate font-mono text-xs">{selectedBinary}</span>
                                    <span className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2">
                                        <svg className="h-5 w-5 text-gray-400" viewBox="0 0 20 20" fill="currentColor">
                                            <path fillRule="evenodd" d="M10 3a.75.75 0 01.55.24l3.25 3.5a.75.75 0 11-1.1 1.02L10 4.852 7.3 7.76a.75.75 0 01-1.1-1.02l3.25-3.5A.75.75 0 0110 3zm-3.76 9.2a.75.75 0 011.06.04l2.7 2.908 2.7-2.908a.75.75 0 111.1 1.02l-3.25 3.5a.75.75 0 01-1.1 0l-3.25-3.5a.75.75 0 01.04-1.06z" clipRule="evenodd" />
                                        </svg>
                                    </span>
                                </ListboxButton>
                                <ListboxOptions className="absolute z-10 mt-1 max-h-60 w-full overflow-auto rounded-md bg-white py-1 text-base shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none sm:text-xs font-mono">
                                    {binaries.map((b) => (
                                        <ListboxOption
                                            key={b}
                                            value={b}
                                            className={({ active }) =>
                                                clsx(
                                                    active ? 'bg-indigo-600 text-white' : 'text-gray-900',
                                                    'relative cursor-default select-none py-2 pl-3 pr-9'
                                                )
                                            }
                                        >
                                            {({ selected, active }) => (
                                                <div className="flex justify-between items-center bg-transparent">
                                                    <span className={clsx(selected ? 'font-semibold' : 'font-normal', 'truncate')}>
                                                        {b}
                                                    </span>
                                                   <span className={clsx(active ? 'text-indigo-200' : 'text-gray-400', 'ml-2 text-xs')}>
                                                        {getOpt(b) || '?'}
                                                    </span>
                                                </div>
                                            )}
                                        </ListboxOption>
                                    ))}
                                </ListboxOptions>
                            </div>
                        </Listbox>
                    </div>

                    <div className="flex items-center space-x-6">
                        <div className="flex items-center">
                            <span className="mr-2 text-sm text-gray-700">AST</span>
                            <button
                                onClick={() => setShowCode(!showCode)}
                                className={clsx(
                                    showCode ? 'bg-indigo-600' : 'bg-gray-200',
                                    'relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500'
                                )}
                            >
                                <span className={clsx(
                                    showCode ? 'translate-x-5' : 'translate-x-0',
                                    'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200'
                                )} />
                            </button>
                            <span className="ml-2 text-sm text-gray-700">Code</span>
                        </div>

                        <div className="flex items-center">
                            <span className="mr-2 text-sm text-gray-700">Show Source</span>
                            <button
                                onClick={() => setShowSource(!showSource)}
                                className={clsx(
                                    showSource ? 'bg-indigo-600' : 'bg-gray-200',
                                    'relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500'
                                )}
                            >
                                <span className={clsx(
                                    showSource ? 'translate-x-5' : 'translate-x-0',
                                    'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200'
                                )} />
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            {/* Info Bar: Binary & Optimization */}
            {selectedBinary && (
                <div className="flex items-center space-x-4 text-sm text-gray-600 px-1 mb-6">
                    <span className="bg-gray-100 rounded-md px-2 py-1 border border-gray-200">
                         Binary: <span className="font-mono text-gray-800">{selectedBinary}</span>
                    </span>
                    <span className="bg-blue-50 rounded-md px-2 py-1 border border-blue-200 text-blue-800">
                         Optimization: <span className="font-bold">{getOpt(selectedBinary) || 'Unknown'}</span>
                    </span>
                </div>
            )}

            {/* Heatmap Section */}
            {(() => {
                if (currentItems.length === 0) return null;
                const firstItem = currentItems[0];
                const taskKey = `${firstItem.binary}::${firstItem.function}`;
                const taskLoss = lossData?.[selectedModel]?.[taskKey];
                
                // Collect all unique decompilers involved in these comparisons
                const decompilerSet = new Set();
                currentItems.forEach(item => {
                    if (item.decompiler_A) decompilerSet.add(item.decompiler_A);
                    if (item.decompiler_B) decompilerSet.add(item.decompiler_B);
                });
                const decompilers = Array.from(decompilerSet).sort();

                return (
                    <div className="mb-8 px-1">
                        <DogboltLossHeatmap taskLossData={taskLoss} decompilers={decompilers} />
                    </div>
                );
            })()}

            {/* Comparisons Section */}
            <div className="bg-white shadow sm:rounded-lg overflow-hidden border border-gray-100">
                <div className="px-4 py-5 sm:p-6 space-y-12">
                     <h2 className="text-xl font-bold text-gray-900 border-l-4 border-indigo-500 pl-4">
                        Decompiler Comparisons for <span className="font-mono text-indigo-600">{selectedBinary}</span>
                    </h2>

                    {currentItems.map((item, idx) => {
                        return (
                            <ComparisonRow
                                key={idx}
                                item={item}
                                showCode={showCode}
                                showSource={showSource}
                            />
                        );
                    })}
                </div>
            </div>
        </div>
    )
}
