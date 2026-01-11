
import React, { useState, useMemo, useEffect } from 'react';
import { TEST_PAYLOADS } from './constants';
import { TestResult, ReportSummary, TestCategory, TestStatus } from './types';
import { TestCard } from './components/TestCard';
import { ReportView } from './components/ReportView';
import { SecurityAnalysisService } from './services/geminiService';
import { TestRunner } from './services/testRunner';
import { 
  Shield, LayoutDashboard, Database, Activity, FileCheck, 
  Menu, X, Loader2, Search, BookOpen, 
  Info, CheckCircle2, ShieldAlert, Eye, Terminal, Network, Globe, AlertCircle, Wifi, WifiOff
} from 'lucide-react';

const App: React.FC = () => {
  const [results, setResults] = useState<TestResult[]>([]);
  const [report, setReport] = useState<ReportSummary | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState<'all' | TestCategory>('all');
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isDesktopSidebarOpen, setIsDesktopSidebarOpen] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showGuide, setShowGuide] = useState(false);
  
  const [targetUrl, setTargetUrl] = useState('https://httpbin.org/get');
  const [isTargetOnline, setIsTargetOnline] = useState<boolean | null>(null);
  const [isCheckingTarget, setIsCheckingTarget] = useState(false);

  const analysisService = useMemo(() => new SecurityAnalysisService(), []);

  const checkConnectivity = async () => {
    setIsCheckingTarget(true);
    const online = await TestRunner.checkConnectivity(targetUrl);
    setIsTargetOnline(online);
    setIsCheckingTarget(false);
  };

  useEffect(() => {
    checkConnectivity();
  }, [targetUrl]);

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
    // Deterministic local report generation
    const summary = await analysisService.generateReport(results);
    setReport(summary);
    setIsAnalyzing(false);
  };

  const filteredPayloads = useMemo(() => {
    return TEST_PAYLOADS.filter(p => {
      const matchesCategory = activeTab === 'all' || p.category === activeTab;
      const matchesSearch = 
        p.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
        p.description.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesCategory && matchesSearch;
    });
  }, [activeTab, searchQuery]);

  const categories = ['all', ...Object.values(TestCategory)];

  return (
    <div className="min-h-screen bg-gray-950 flex text-gray-100 font-sans selection:bg-blue-500/30 overflow-x-hidden">
      {isSidebarOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[60] lg:hidden" onClick={() => setIsSidebarOpen(false)} />
      )}

      <aside className={`fixed inset-y-0 left-0 z-[70] bg-gray-900 border-r border-gray-800 transition-all duration-300 flex flex-col ${isSidebarOpen ? 'translate-x-0 w-64' : '-translate-x-full lg:translate-x-0'} ${isDesktopSidebarOpen ? 'lg:w-64' : 'lg:w-20'} lg:sticky lg:top-0 lg:h-screen`}>
        <div className="p-6 flex items-center gap-3">
          <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-900/40 shrink-0">
            <Shield className="text-white" size={24} />
          </div>
          {(isDesktopSidebarOpen || isSidebarOpen) && <span className="font-black text-xl tracking-tight uppercase">Sentinela</span>}
        </div>

        <nav className="flex-1 px-4 mt-8 space-y-1 overflow-y-auto custom-scrollbar">
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-2 mb-4">{(isDesktopSidebarOpen || isSidebarOpen) ? 'Threat Categories' : 'TC'}</div>
          {categories.map((cat) => (
            <button key={cat} onClick={() => { setActiveTab(cat as any); setIsSidebarOpen(false); }} className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 group ${activeTab === cat ? 'bg-blue-600/10 text-blue-400 border border-blue-900/50' : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'}`}>
              <Database size={18} className={activeTab === cat ? 'text-blue-400' : 'text-gray-500'} />
              {(isDesktopSidebarOpen || isSidebarOpen) && <span className="capitalize text-xs truncate">{cat}</span>}
            </button>
          ))}
          <div className="pt-8 text-[10px] font-bold text-gray-500 uppercase tracking-widest px-2 mb-4">{(isDesktopSidebarOpen || isSidebarOpen) ? 'Support' : 'S'}</div>
          <button onClick={() => { setShowGuide(true); setIsSidebarOpen(false); }} className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-gray-400 hover:bg-gray-800 hover:text-gray-200 transition-all">
            <BookOpen size={18} className="text-gray-500" />
            {(isDesktopSidebarOpen || isSidebarOpen) && <span>Field Manual</span>}
          </button>
        </nav>

        <div className="p-4 border-t border-gray-800 hidden lg:block">
          <button onClick={() => setIsDesktopSidebarOpen(!isDesktopSidebarOpen)} className="w-full flex items-center justify-center p-2 text-gray-500 hover:text-gray-300 hover:bg-gray-800 rounded-lg transition-colors">
            {isDesktopSidebarOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </aside>

      <main className="flex-1 flex flex-col min-w-0">
        <header className="h-auto min-h-[4rem] lg:min-h-[5rem] bg-gray-950/80 backdrop-blur-md border-b border-gray-800 flex flex-col lg:flex-row items-stretch lg:items-center justify-between px-4 lg:px-8 sticky top-0 z-40 py-2 lg:py-0">
          <div className="flex items-center gap-2 lg:gap-4 flex-1 min-w-0 mb-2 lg:mb-0">
            <button className="lg:hidden p-2 text-gray-400 hover:bg-gray-800 rounded-lg" onClick={() => setIsSidebarOpen(true)}>
              <Menu size={20} />
            </button>
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={14} />
              <input type="text" placeholder="Search threats..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="w-full bg-gray-900 border border-gray-800 rounded-lg py-1.5 lg:py-2 pl-9 pr-4 text-xs lg:text-sm focus:outline-none focus:border-blue-500 transition-all" />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 lg:gap-4">
            <div className="flex items-center gap-3 bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5">
              <div className="flex flex-col">
                <span className="text-[8px] text-gray-500 font-bold uppercase mb-1">Target Connectivity</span>
                <div className="flex items-center gap-2">
                  <input 
                    type="text" 
                    value={targetUrl} 
                    onChange={(e) => setTargetUrl(e.target.value)}
                    className="bg-transparent border-none p-0 text-[10px] lg:text-xs text-blue-400 focus:ring-0 min-w-[150px] font-mono"
                  />
                  {/* Fixed Lucide icon title prop error by wrapping in span with title attribute */}
                  {isCheckingTarget ? (
                    <Loader2 size={14} className="animate-spin text-gray-500" />
                  ) : isTargetOnline ? (
                    <span title="Target Reachable">
                      <Wifi size={14} className="text-green-500" />
                    </span>
                  ) : (
                    <span title="Target Unreachable">
                      <WifiOff size={14} className="text-red-500" />
                    </span>
                  )}
                </div>
              </div>
            </div>

            <button onClick={generateReport} disabled={results.length === 0 || isAnalyzing} className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-500 text-white text-xs lg:text-sm font-semibold rounded-lg shadow-lg shadow-blue-900/20 transition-all flex items-center gap-2">
              {isAnalyzing ? <Loader2 size={16} className="animate-spin" /> : <FileCheck size={16} />}
              <span>Generate Analysis</span>
            </button>
          </div>
        </header>

        <div className="p-4 lg:p-8 max-w-7xl mx-auto w-full flex-1">
          {report ? (
            <div className="space-y-6">
              <div className="flex justify-between items-center">
                <h2 className="text-xl font-black">Security Posture Report</h2>
                <button onClick={() => setReport(null)} className="px-3 py-2 text-xs bg-gray-800 hover:bg-gray-700 rounded-lg text-gray-300">Back to Lab</button>
              </div>
              <ReportView summary={report} results={results} />
            </div>
          ) : (
            <>
              <div className="mb-8 lg:mb-12">
                <h2 className="text-2xl lg:text-4xl font-black tracking-tight mb-2 uppercase flex items-center gap-3">
                  Validation Lab
                  {isTargetOnline === false && (
                    <span className="flex items-center gap-1.5 px-2 py-1 bg-red-950/40 border border-red-900/50 rounded text-[10px] text-red-400 normal-case font-bold">
                      <AlertCircle size={12} /> Target Unreachable
                    </span>
                  )}
                </h2>
                <p className="text-sm lg:text-base text-gray-400 max-w-2xl">
                  Attempting vectors against <span className="text-blue-400 font-mono">{targetUrl}</span>. 
                  If the target is offline, tests will show as 'Blocked' incorrectly.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 lg:gap-6">
                {filteredPayloads.map((payload) => (
                  <TestCard 
                    key={payload.id} 
                    payload={payload} 
                    onResult={handleTestResult} 
                    targetUrl={targetUrl}
                  />
                ))}
              </div>
            </>
          )}
        </div>
        
        <footer className="p-6 lg:p-8 border-t border-gray-900 text-center text-[10px] lg:text-xs text-gray-600">
          <p>© 2026 Sentinela Validation Suite • Manual Testing Mode Enabled</p>
        </footer>
      </main>

      {showGuide && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-gray-950/95 backdrop-blur-md" onClick={() => setShowGuide(false)} />
          <div className="relative bg-gray-900 border border-gray-800 w-full max-w-2xl rounded-3xl p-8 animate-in fade-in zoom-in duration-300">
            <h3 className="text-2xl font-black mb-4 flex items-center gap-3"><Terminal size={24} className="text-blue-500" /> Lab Field Manual</h3>
            <div className="space-y-4 text-sm text-gray-400 leading-relaxed">
              <p>1. <strong className="text-white">Verify Connectivity:</strong> Ensure the icon in the header is green. If it's red, your network or target is down.</p>
              <p>2. <strong className="text-white">Trigger Vectors:</strong> Execute individual attacks. WAF/IPS tests send network packets. Malware tests simulate file drops.</p>
              <p>3. <strong className="text-white">Interpreting Results:</strong></p>
              <ul className="pl-4 border-l border-gray-800 space-y-2">
                <li><span className="text-red-400 font-bold">PASSED:</span> The security control FAILED. The threat reached the target.</li>
                <li><span className="text-green-400 font-bold">BLOCKED:</span> The security control SUCCESS. The connection was terminated or timed out.</li>
              </ul>
            </div>
            <button onClick={() => setShowGuide(false)} className="mt-8 w-full py-3 bg-blue-600 hover:bg-blue-500 rounded-xl font-bold transition-all">Begin Testing</button>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
