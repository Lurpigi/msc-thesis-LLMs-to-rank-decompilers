import React from 'react';
import clsx from 'clsx';

export default function Stats({ func, prData }) {
    if (!func) return null;

    // 1. Fix Property Access: 'metrics' is directly on the function object.
    const m = func.metrics || {};

    // 2. Fix Model Iteration to find winners
    // prData.results = { "qwen-coder": [ {function: "name", ...}, ... ], "other-model": [...] }
    const functionName = func.function;
    const models = Object.keys(prData.results || {});
    
    const modelResults = models.map(modelKey => {
        const funcs = prData.results[modelKey];
        const f = funcs.find(item => item.function === functionName);
        return {
            model: modelKey,
            data: f
        };
    }).filter(item => item.data);

    if (modelResults.length === 0) return null;

    return (
        <div className="space-y-6 mt-8">
            <h3 className="text-lg font-medium leading-6 text-gray-900">Perplexity Metrics</h3>
            {/* Metrics Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                 <div className="bg-white overflow-hidden shadow rounded-lg">
                    <div className="px-4 py-5 sm:p-6">
                        <dt className="text-sm font-medium text-gray-500 truncate">Source PPL</dt>
                        <dd className="mt-1 text-3xl font-semibold text-gray-900">{m.source_ppl?.toFixed(4)}</dd>
                    </div>
                 </div>
                 <div className="bg-white overflow-hidden shadow rounded-lg">
                    <div className="px-4 py-5 sm:p-6">
                        <dt className="text-sm font-medium text-gray-500 truncate">Base PPL</dt>
                        <dd className="mt-1 text-3xl font-semibold text-gray-900">{m.base_ppl?.toFixed(4)}</dd>
                    </div>
                 </div>
                 <div className="bg-white overflow-hidden shadow rounded-lg">
                    <div className="px-4 py-5 sm:p-6">
                        <dt className="text-sm font-medium text-gray-500 truncate">PR PPL</dt>
                        <dd className="mt-1 text-3xl font-semibold text-gray-900">{m.pr_ppl?.toFixed(4)}</dd>
                    </div>
                 </div>
                 <div className="bg-white overflow-hidden shadow rounded-lg">
                    <div className="px-4 py-5 sm:p-6">
                        <dt className="text-sm font-medium text-gray-500 truncate">Delta PPL</dt>
                        <dd className={`mt-1 text-3xl font-semibold ${m.delta_ppl < 0 ? 'text-green-600' : 'text-red-600'}`}>
                            {m.delta_ppl?.toFixed(4)}
                        </dd>
                    </div>
                 </div>
            </div>
            
            {/* AST Metrics */}
            <h4 className="text-md font-medium text-gray-900 mt-4">AST Metrics</h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                 <div className="bg-white overflow-hidden shadow rounded-lg">
                    <div className="px-4 py-5 sm:p-6">
                        <dt className="text-sm font-medium text-gray-500 truncate">Source AST PPL</dt>
                        <dd className="mt-1 text-2xl font-semibold text-gray-900">{m.source_ast_ppl?.toFixed(4)}</dd>
                    </div>
                 </div>
                 <div className="bg-white overflow-hidden shadow rounded-lg">
                    <div className="px-4 py-5 sm:p-6">
                        <dt className="text-sm font-medium text-gray-500 truncate">Base AST PPL</dt>
                        <dd className="mt-1 text-2xl font-semibold text-gray-900">{m.base_ast_ppl?.toFixed(4)}</dd>
                    </div>
                 </div>
                 <div className="bg-white overflow-hidden shadow rounded-lg">
                    <div className="px-4 py-5 sm:p-6">
                        <dt className="text-sm font-medium text-gray-500 truncate">PR AST PPL</dt>
                        <dd className="mt-1 text-2xl font-semibold text-gray-900">{m.pr_ast_ppl?.toFixed(4)}</dd>
                    </div>
                 </div>
                 <div className="bg-white overflow-hidden shadow rounded-lg">
                    <div className="px-4 py-5 sm:p-6">
                        <dt className="text-sm font-medium text-gray-500 truncate">Delta AST PPL</dt>
                        <dd className={`mt-1 text-2xl font-semibold ${
                            (m.pr_ast_ppl - m.base_ast_ppl) < 0 ? 'text-green-600' : 'text-red-600'
                        }`}>
                            {(m.pr_ast_ppl - m.base_ast_ppl)?.toFixed(4)}
                        </dd>
                    </div>
                 </div>
            </div>

            {/* Winners Table */}
            <h3 className="text-lg font-medium leading-6 text-gray-900 mt-8">Model Comparison Winners</h3>
            <div className="flex flex-col">
                <div className="-my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
                    <div className="py-2 align-middle inline-block min-w-full sm:px-6 lg:px-8">
                        <div className="shadow overflow-hidden border-b border-gray-200 sm:rounded-lg">
                            <table className="min-w-full divide-y divide-gray-200">
                                <thead className="bg-gray-50">
                                    <tr>
                                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Model
                                        </th>
                                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Evaluation Criteria
                                        </th>
                                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Winner
                                        </th>
                                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Motivation
                                        </th>
                                    </tr>
                                </thead>
                                <tbody className="bg-white divide-y divide-gray-200">
                                    {modelResults.map((res, idx) => {
                                        const analyses = [
                                            { key: 'llm_qualitative', label: 'Code: Humanity & Readability' },
                                            { key: 'llm_qualitative_source', label: 'Code: Fidelity & Cleanliness (GT)' },
                                            { key: 'llm_ast', label: 'AST: Humanity & Readability' },
                                            { key: 'llm_ast_source', label: 'AST: Fidelity & Cleanliness (GT)' }
                                        ];

                                        return (
                                            <React.Fragment key={res.model}>
                                                {analyses.map((analysis, aIdx) => (
                                                    <tr key={analysis.key} className={aIdx === analyses.length - 1 && idx !== modelResults.length - 1 ? 'border-b-4 border-gray-100' : ''}>
                                                        {aIdx === 0 && (
                                                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 bg-gray-50/50" rowSpan={4}>
                                                                {res.model}
                                                            </td>
                                                        )}
                                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 italic">
                                                            {analysis.label}
                                                        </td>
                                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-bold">
                                                            <span className={clsx(
                                                                "px-2 inline-flex text-xs leading-5 font-semibold rounded-full",
                                                                res.data[analysis.key]?.winner === 'PR' ? 'bg-green-100 text-green-800' : 
                                                                res.data[analysis.key]?.winner === 'BASE' ? 'bg-yellow-100 text-yellow-800' : 'bg-gray-100 text-gray-800'
                                                            )}>
                                                                {res.data[analysis.key]?.winner || 'N/A'}
                                                            </span>
                                                        </td>
                                                        <td className="px-6 py-4 text-sm text-gray-500 max-w-xl break-words whitespace-pre-wrap">
                                                            {res.data[analysis.key]?.motivation || 'No motivation provided.'}
                                                        </td>
                                                    </tr>
                                                ))}
                                            </React.Fragment>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
