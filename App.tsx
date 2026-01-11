
import React, { useState, useMemo, useEffect } from 'react';
import { TEST_PAYLOADS } from './constants';
import { TestResult, ReportSummary, TestCategory, TestStatus } from './types';
import { TestCard } from './components/TestCard';
import { ReportView } from './components/ReportView';
import { SecurityAnalysisService } from './services/geminiService';
import { 
  Shield, LayoutDashboard, Database, Activity, FileCheck, 
  ChevronRight, Menu, X, Loader2, Search, BookOpen, 
  Info, CheckCircle2, AlertTriangle, ShieldAlert, Eye, Terminal, Network, Fingerprint, Bug
} from 'lucide-react';

const App: React.FC = () => {
  const [results, setResults] = useState<TestResult[]>([]);
  const [report, setReport] = useState<ReportSummary | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState<'all' | TestCategory>('all');
  const [isSidebarOpen, setIsSidebarOpen] = useState(false); // Closed by default on mobile
  const [isDesktopSidebarOpen, setIsDesktopSidebarOpen] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showGuide, setShowGuide] = useState(false);

  const analysisService = useMemo(() => new SecurityAnalysisService(), []);

  // Close mobile sidebar on navigation or resize
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth >= 1024) {
        setIsSidebarOpen(false);
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const handleTestResult = (result: TestResult) => {
    setResults(prev => {
      const existing = prev.findIndex(r => r.testId === result.testId);
      if (existing > -1) {
        const updated = [...prev];
        updated[existing] = result;
        return updated;
      }
      return [...prev, result];
    });
  };

  const generateReport = async () => {
    if (results.length === 0) return;
    setIsAnalyzing(true);
    try {
      const summary = await analysisService.generateReport(results);
      setReport(summary);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const showPreviewReport = () => {
    const mockReport: ReportSummary = {
      overallHealth: 'Moderate',
      score: 65,
      blockedCount: results.filter(r => r.status === TestStatus.BLOCKED).length || 12,
      passedCount: results.filter(r => r.status === TestStatus.PASSED).length || 4,
      aiAnalysis: "PREVIEW MODE: This is a simulated analysis based on current security trends. In a live environment, this section would contain deep forensics provided by the Gemini Engine, highlighting gaps in SSL inspection and behavioral heuristics."
    };
    setReport(mockReport);
  };

  const filteredPayloads = useMemo(() => {
    return TEST_PAYLOADS.filter(p => {
      const matchesCategory = activeTab === 'all' || p.category === activeTab;
      const matchesSearch = 
        p.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
        p.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.content.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesCategory && matchesSearch;
    });
  }, [activeTab, searchQuery]);

  const categories = ['all', ...Object.values(TestCategory)];

  const NavigationItems = () => (
    <>
      <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-2 mb-4">
        { (isDesktopSidebarOpen || isSidebarOpen) ? 'Threat Categories' : 'TC'}
      </div>
      {categories.map((cat) => (
        <button
          key={cat}
          onClick={() => {
            setActiveTab(cat as any);
            setIsSidebarOpen(false);
          }}
          className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 group ${
            activeTab === cat 
              ? 'bg-blue-600/10 text-blue-400 border border-blue-900/50' 
              : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
          }`}
        >
          <Database size={18} className={activeTab === cat ? 'text-blue-400' : 'text-gray-500'} />
          {(isDesktopSidebarOpen || isSidebarOpen) && <span className="capitalize text-xs truncate">{cat}</span>}
        </button>
      ))}
      
      <div className="pt-8 text-[10px] font-bold text-gray-500 uppercase tracking-widest px-2 mb-4">
        { (isDesktopSidebarOpen || isSidebarOpen) ? 'Support' : 'S'}
      </div>
      <button
        onClick={() => {
          setShowGuide(true);
          setIsSidebarOpen(false);
        }}
        className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-gray-400 hover:bg-gray-800 hover:text-gray-200 transition-all"
      >
        <BookOpen size={18} className="text-gray-500" />
        {(isDesktopSidebarOpen || isSidebarOpen) && <span>Field Manual</span>}
      </button>
    </>
  );

  return (
    <div className="min-h-screen bg-gray-950 flex text-gray-100 font-sans selection:bg-blue-500/30 overflow-x-hidden">
      {/* Mobile Sidebar Overlay */}
      {isSidebarOpen && (
        <div 
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[60] lg:hidden"
          onClick={() => setIsSidebarOpen(false)}
        />
      )}

      {/* Sidebar - Desktop & Mobile Drawer */}
      <aside 
        className={`
          fixed inset-y-0 left-0 z-[70] bg-gray-900 border-r border-gray-800 transition-all duration-300 flex flex-col
          ${isSidebarOpen ? 'translate-x-0 w-64' : '-translate-x-full lg:translate-x-0'}
          ${isDesktopSidebarOpen ? 'lg:w-64' : 'lg:w-20'}
          lg:sticky lg:top-0 lg:h-screen
        `}
      >
        <div className="p-6 flex items-center gap-3">
          <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-900/40 shrink-0">
            <Shield className="text-white" size={24} />
          </div>
          {(isDesktopSidebarOpen || isSidebarOpen) && <span className="font-black text-xl tracking-tight">SENTINELA</span>}
        </div>

        <nav className="flex-1 px-4 mt-8 space-y-1 overflow-y-auto custom-scrollbar">
          <NavigationItems />
        </nav>

        <div className="p-4 border-t border-gray-800 hidden lg:block">
          <button 
            onClick={() => setIsDesktopSidebarOpen(!isDesktopSidebarOpen)}
            className="w-full flex items-center justify-center p-2 text-gray-500 hover:text-gray-300 hover:bg-gray-800 rounded-lg transition-colors"
          >
            {isDesktopSidebarOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0">
        <header className="h-16 lg:h-20 bg-gray-950/80 backdrop-blur-md border-b border-gray-800 flex items-center justify-between px-4 lg:px-8 sticky top-0 z-40">
          <div className="flex items-center gap-2 lg:gap-4 flex-1 min-w-0">
            <button 
              className="lg:hidden p-2 text-gray-400 hover:bg-gray-800 rounded-lg mr-2"
              onClick={() => setIsSidebarOpen(true)}
            >
              <Menu size={20} />
            </button>
            
            <div className="flex items-center gap-2 hidden sm:flex shrink-0">
              <h1 className="text-sm lg:text-lg font-bold text-gray-100 flex items-center gap-2 whitespace-nowrap">
                <LayoutDashboard size={20} className="text-blue-500" />
                Dashboard
              </h1>
              <ChevronRight size={16} className="text-gray-600" />
            </div>
            
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={14} />
              <input 
                type="text" 
                placeholder="Search threats..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-gray-900 border border-gray-800 rounded-lg py-1.5 lg:py-2 pl-9 pr-4 text-xs lg:text-sm focus:outline-none focus:border-blue-500 transition-all"
              />
            </div>
          </div>

          <div className="flex items-center gap-2 lg:gap-3 ml-2 lg:ml-4">
            <button 
              onClick={showPreviewReport}
              className="p-2 lg:px-4 lg:py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-semibold rounded-lg border border-gray-700 transition-all flex items-center gap-2 whitespace-nowrap"
            >
              <Eye size={16} />
              <span className="hidden md:inline">Preview</span>
            </button>
            <button 
              onClick={generateReport}
              disabled={results.length === 0 || isAnalyzing}
              className="px-3 py-2 lg:px-4 lg:py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-500 text-white text-xs lg:text-sm font-semibold rounded-lg shadow-lg shadow-blue-900/20 transition-all flex items-center gap-2 whitespace-nowrap"
            >
              {isAnalyzing ? <Loader2 size={16} className="animate-spin" /> : <FileCheck size={16} />}
              <span className="hidden sm:inline">Report</span>
              <span className="sm:hidden">{results.length > 0 ? results.length : ''}</span>
            </button>
          </div>
        </header>

        <div className="p-4 lg:p-8 max-w-7xl mx-auto w-full flex-1">
          {report ? (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div className="flex flex-col">
                  <h2 className="text-xl lg:text-2xl font-black">Security Posture</h2>
                  <p className="text-[10px] lg:text-xs text-gray-500 italic">Synthetic intelligence evaluation.</p>
                </div>
                <button 
                  onClick={() => setReport(null)}
                  className="w-full sm:w-auto px-3 py-2 text-xs bg-gray-800 hover:bg-gray-700 rounded-lg text-gray-300 transition-all flex items-center justify-center gap-2"
                >
                  <LayoutDashboard size={14} /> Back
                </button>
              </div>
              <ReportView summary={report} results={results} />
            </div>
          ) : (
            <>
              <div className="mb-8 lg:mb-12 flex flex-col md:flex-row md:items-end justify-between gap-6">
                <div>
                  <h2 className="text-2xl lg:text-4xl font-black tracking-tight mb-2 uppercase">Capability Validation</h2>
                  <p className="text-sm lg:text-base text-gray-400 max-w-2xl">
                    Validation for <span className="text-orange-400 font-bold">NGFW</span> & <span className="text-purple-400 font-bold">EDR</span>. 
                    Ensure <span className="text-blue-400">Logging</span> mode is active.
                  </p>
                </div>
                <div className="bg-gray-900/80 border border-gray-800 rounded-xl px-4 py-3 flex items-center gap-3 self-start md:self-auto">
                  <Activity className="text-blue-500" size={20} />
                  <div>
                    <div className="text-[10px] text-gray-500 uppercase font-bold">Execution Log</div>
                    <div className="text-lg lg:text-xl font-bold font-mono">{results.length}</div>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 lg:gap-6">
                {filteredPayloads.map((payload) => (
                  <TestCard 
                    key={payload.id} 
                    payload={payload} 
                    onResult={handleTestResult} 
                  />
                ))}
              </div>

              {filteredPayloads.length === 0 && (
                <div className="text-center py-16 lg:py-20 bg-gray-900/50 rounded-2xl border border-dashed border-gray-800">
                  <ShieldAlert size={48} className="mx-auto text-gray-700 mb-4" />
                  <h3 className="text-lg font-bold text-gray-400">No vectors matched</h3>
                  <button onClick={() => {setSearchQuery(''); setActiveTab('all')}} className="mt-4 text-blue-400 hover:underline text-xs">Clear filters</button>
                </div>
              )}
            </>
          )}
        </div>
        
        <footer className="p-6 lg:p-8 border-t border-gray-900 text-center text-[10px] lg:text-xs text-gray-600">
          <div className="flex flex-wrap justify-center gap-4 lg:gap-6 mb-4">
            <span className="flex items-center gap-1"><Info size={14} /> Docs</span>
            <span className="flex items-center gap-1"><Shield size={14} /> MITRE</span>
          </div>
          <p>© 2026 Sentinela. Professional Defensive Suite.</p>
          <div className="mt-2 font-medium italic">
            By <span className="text-blue-400 font-bold">tegar</span> • <span className="text-orange-500 uppercase font-black tracking-tighter">testing phase</span>
          </div>
        </footer>
      </main>

      {/* Responsive Field Manual Modal */}
      {showGuide && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-2 sm:p-4 md:p-12">
          <div className="absolute inset-0 bg-gray-950/95 backdrop-blur-md" onClick={() => setShowGuide(false)} />
          <div className="relative bg-gray-900 border border-gray-800 w-full max-w-4xl h-full sm:h-auto sm:max-h-[90vh] overflow-hidden sm:rounded-3xl shadow-2xl flex flex-col animate-in fade-in zoom-in duration-300">
            <div className="p-4 lg:p-8 border-b border-gray-800 bg-gray-900/50 flex justify-between items-center">
              <div className="flex items-center gap-3 lg:gap-4">
                <div className="p-2 lg:p-3 bg-blue-600 rounded-lg lg:rounded-xl"><BookOpen size={20} className="text-white lg:w-6 lg:h-6" /></div>
                <div>
                  <h3 className="text-lg lg:text-2xl font-black">Field Manual</h3>
                  <p className="text-[10px] text-gray-500 font-bold uppercase tracking-widest">Methodology v2.6</p>
                </div>
              </div>
              <button onClick={() => setShowGuide(false)} className="p-2 hover:bg-gray-800 rounded-full text-gray-400 hover:text-white transition-all">
                <X size={24} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4 lg:p-8 space-y-8 lg:space-y-12 custom-scrollbar">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 lg:gap-10">
                <section>
                  <h4 className="text-[10px] lg:text-sm font-black text-blue-400 uppercase tracking-[0.2em] mb-3 flex items-center gap-2">
                    <Terminal size={14} /> 01. Setup
                  </h4>
                  <div className="space-y-3 text-xs lg:text-sm text-gray-400 leading-relaxed">
                    <p>Use a <span className="text-white">Hardened Lab VM</span>. Verify egress path via the NGFW.</p>
                    <ul className="space-y-2">
                      <li className="flex gap-2"><CheckCircle2 size={14} className="text-green-500 shrink-0 mt-0.5" /><span>Enable SSL Inspection.</span></li>
                      <li className="flex gap-2"><CheckCircle2 size={14} className="text-green-500 shrink-0 mt-0.5" /><span>EDR in 'Alert and Block'.</span></li>
                    </ul>
                  </div>
                </section>

                <section>
                  <h4 className="text-[10px] lg:text-sm font-black text-orange-400 uppercase tracking-[0.2em] mb-3 flex items-center gap-2">
                    <Network size={14} /> 02. NGFW
                  </h4>
                  <div className="space-y-3 text-xs lg:text-sm text-gray-400 leading-relaxed">
                    <p>Validation targets URI and Header injection. Observe connection resets (RST).</p>
                    <p className="bg-gray-800/50 p-2 rounded border border-gray-700 font-mono text-[10px]">
                      Check: Threat/Security Logs
                    </p>
                  </div>
                </section>
                
                <section>
                  <h4 className="text-[10px] lg:text-sm font-black text-purple-400 uppercase tracking-[0.2em] mb-3 flex items-center gap-2">
                    <Fingerprint size={14} /> 03. EDR
                  </h4>
                  <div className="space-y-3 text-xs lg:text-sm text-gray-400 leading-relaxed">
                    <p>Behavioral detection for Persistence and Lateral Movement simulation.</p>
                  </div>
                </section>

                <section>
                  <h4 className="text-[10px] lg:text-sm font-black text-green-400 uppercase tracking-[0.2em] mb-3 flex items-center gap-2">
                    <Bug size={14} /> 04. Malware
                  </h4>
                  <div className="space-y-3 text-xs lg:text-sm text-gray-400 leading-relaxed">
                    <p>Test Recursive Archive Scanning via 'Compressed EICAR'.</p>
                  </div>
                </section>
              </div>

              <div className="p-4 lg:p-8 bg-gray-800/50 border border-gray-700 rounded-2xl lg:rounded-3xl">
                <h4 className="font-bold text-white mb-4 flex items-center gap-2 text-sm lg:text-base">
                  <FileCheck size={18} className="text-blue-500" /> Operational Cycle
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 lg:gap-6 text-[10px] lg:text-xs text-gray-500">
                  <div className="space-y-1"><span className="font-bold text-gray-300">COLLECT</span><p>Estabish capability baseline.</p></div>
                  <div className="space-y-1"><span className="font-bold text-gray-300">ANALYZE</span><p>Verify data via Preview.</p></div>
                  <div className="space-y-1"><span className="font-bold text-gray-300">APPLY</span><p>Remediate control gaps.</p></div>
                </div>
              </div>
            </div>

            <div className="p-4 lg:p-6 bg-gray-900 border-t border-gray-800 flex items-center justify-between mt-auto">
              <div className="hidden sm:flex items-center gap-2 text-[9px] text-gray-500 font-bold uppercase">
                <div className="w-1 h-1 bg-green-500 rounded-full" /> Updated 2026
              </div>
              <button 
                onClick={() => setShowGuide(false)}
                className="w-full sm:w-auto px-8 py-3 bg-blue-600 hover:bg-blue-500 rounded-xl font-bold transition-all"
              >
                I Understand
              </button>
            </div>
          </div>
        </div>
      )}
      <style>{`
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #374151; border-radius: 10px; }
      `}</style>
    </div>
  );
};

export default App;
