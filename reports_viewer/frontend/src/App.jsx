import { useState, useEffect } from 'react'
import { Tab, Listbox, ListboxButton, ListboxOption, ListboxOptions } from '@headlessui/react'
import clsx from 'clsx'
import DiffViewer from './components/DiffViewer'
import Stats from './components/Stats'

function App() {
  const [reports, setReports] = useState([])
  const [selectedPrIndex, setSelectedPrIndex] = useState(0)
  const [selectedFunction, setSelectedFunction] = useState(null)
  const [showSource, setShowSource] = useState(false)
  const [showCode, setShowCode] = useState(false) // false = AST, true = Code

  useEffect(() => {
    fetch('/api/data')
      .then(res => res.json())
      .then(data => {
        const validData = data.filter(r => r && r.pr);
        setReports(validData)
        if (validData.length > 0) {
            // Select first function of first PR by default
            const firstPr = validData[0];
            const functions = getFunctions(firstPr);
            if (functions.length > 0) setSelectedFunction(functions[0]);
        }
      })
      .catch(err => console.error("Failed to load reports:", err))
  }, [])

  const currentPr = reports[selectedPrIndex]
  
  const getFunctions = (pr) => {
    if (!pr || !pr.results) return []
    // Assuming structure: pr.results = { "model_name": [ { function: "...", ... } ] }
    // We need to aggregate unique functions or just pick from the first model?
    // The requirement says "load every json file... create collections... grouped by PR and function"
    // Since the JSON structure shows `results` -> `model` -> `list of functions`, 
    // we can assume all models have evaluated the same functions.
    // Let's get the list of functions from the first model key found.
    const models = Object.keys(pr.results);
    if (models.length === 0) return [];
    return pr.results[models[0]]; // Returns list of function objects
  }

  const handlePrChange = (index) => {
      setSelectedPrIndex(index);
      const pr = reports[index];
      const funcs = getFunctions(pr);
      if (funcs.length > 0) setSelectedFunction(funcs[0]);
      else setSelectedFunction(null);
  }

  const getOpt = (binary) => binary?.match(/-O[0-3sz]\./)?.[0]?.replace(/[-\.]/g, '') || '';

  return (
    <div className="min-h-screen bg-gray-50 text-gray-900 font-sans">
      {/* Header / Tabs */}
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16 items-center">
            <div className="flex-shrink-0 flex items-center">
              <h1 className="text-xl font-bold text-indigo-600">Ghidra Bench Reports</h1>
            </div>
          </div>
        </div>
        
        {/* PR Tabs */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-4">
            <div className="border-b border-gray-200">
              <nav className="-mb-px flex space-x-8 overflow-x-auto" aria-label="Tabs">
                {reports.map((report, index) => (
                  <button
                    key={report.pr}
                    onClick={() => handlePrChange(index)}
                    className={clsx(
                      selectedPrIndex === index
                        ? 'border-indigo-500 text-indigo-600'
                        : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300',
                      'whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm'
                    )}
                  >
                    PR #{report.pr}
                  </button>
                ))}
              </nav>
            </div>
        </div>
      </div>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {currentPr ? (
            <div className="space-y-6">
                {/* Function Selector & Controls */}
                <div className="bg-white px-4 py-5 shadow sm:rounded-lg sm:px-6 flex flex-col sm:flex-row justify-between items-center gap-4">
                    <div className="w-full sm:w-1/3 relative z-10">
                        <label className="block text-sm font-medium text-gray-700 mb-1">Select Function</label>
                        <Listbox value={selectedFunction} onChange={setSelectedFunction}>
                            <div className="relative mt-1">
                                <ListboxButton className="relative w-full cursor-default rounded-md bg-white py-2 pl-3 pr-10 text-left border border-gray-300 shadow-sm focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                                    <span className="block truncate">{selectedFunction?.function}</span>
                                    <span className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2">
                                        <svg className="h-5 w-5 text-gray-400" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                            <path fillRule="evenodd" d="M10 3a.75.75 0 01.55.24l3.25 3.5a.75.75 0 11-1.1 1.02L10 4.852 7.3 7.76a.75.75 0 01-1.1-1.02l3.25-3.5A.75.75 0 0110 3zm-3.76 9.2a.75.75 0 011.06.04l2.7 2.908 2.7-2.908a.75.75 0 111.1 1.02l-3.25 3.5a.75.75 0 01-1.1 0l-3.25-3.5a.75.75 0 01.04-1.06z" clipRule="evenodd" />
                                        </svg>
                                    </span>
                                </ListboxButton>
                                <ListboxOptions className="absolute z-10 mt-1 max-h-60 w-full overflow-auto rounded-md bg-white py-1 text-base shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none sm:text-sm">
                                    {currentPr && getFunctions(currentPr).map((f, idx) => (
                                        <ListboxOption
                                            key={idx}
                                            value={f}
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
                                                        {f.function}
                                                    </span>
                                                    <span className={clsx(active ? 'text-indigo-200' : 'text-gray-400', 'ml-2 text-xs')}>
                                                        {getOpt(f.binary)}
                                                    </span>
                                                </div>
                                            )}
                                        </ListboxOption>
                                    ))}
                                </ListboxOptions>
                            </div>
                        </Listbox>
                    </div>


                    <div className="flex items-center space-x-4">
                        <div className="flex items-center">
                            <span className="mr-2 text-sm text-gray-700">AST</span>
                            <button
                                onClick={() => setShowCode(!showCode)}
                                className={clsx(
                                    showCode ? 'bg-indigo-600' : 'bg-gray-200',
                                    'relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500'
                                )}
                            >
                                <span
                                    aria-hidden="true"
                                    className={clsx(
                                        showCode ? 'translate-x-5' : 'translate-x-0',
                                        'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200'
                                    )}
                                />
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
                                <span
                                    aria-hidden="true"
                                    className={clsx(
                                        showSource ? 'translate-x-5' : 'translate-x-0',
                                        'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200'
                                    )}
                                />
                            </button>
                        </div>
                    </div>
                </div>

                {/* Info Bar: Binary & Optimization */}
                {selectedFunction && (
                    <div className="flex items-center space-x-4 text-sm text-gray-600 px-1">
                        <span className="bg-gray-100 rounded-md px-2 py-1 border border-gray-200">
                             File: <span className="font-mono text-gray-800">{selectedFunction.binary}</span>
                        </span>
                        <span className="bg-blue-50 rounded-md px-2 py-1 border border-blue-200 text-blue-800">
                             Optimization: <span className="font-bold">{getOpt(selectedFunction.binary) || 'Unknown'}</span>
                        </span>
                    </div>
                )}

                {/* Main Content Area */}
                {selectedFunction && (
                     <div className="space-y-6">
                        {/* Diff Viewer */}
                        <DiffViewer 
                            func={selectedFunction} 
                            prData={currentPr}
                            showCode={showCode}
                            showSource={showSource}
                        />

                        {/* Perplexity Stats & Winner Table */}
                        <Stats 
                            func={selectedFunction} 
                            prData={currentPr} 
                        />
                     </div>
                )}
            </div>
        ) : (
            <div className="text-center py-12">
                <p className="text-gray-500">Loading reports...</p>
            </div>
        )}
      </main>
    </div>
  )
}

export default App
