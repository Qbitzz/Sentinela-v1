
import React, { useState } from 'react';
import { ReportSummary, TestResult } from '../types';
import { TEST_PAYLOADS } from '../constants';
import { 
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, 
  Legend
} from 'recharts';
import { 
  ShieldCheck, ShieldAlert, FileText, Zap, Activity, Target, 
  Terminal, ArrowRight, Server, Shield, Globe, 
  Cpu, MapPin, Loader2, FileDown, CheckCircle2
} from 'lucide-react';

interface Props {
  summary: ReportSummary;
  results: TestResult[];
}

const AttackPathFlow: React.FC<{ result: TestResult }> = ({ result }) => {
  const reachedPerimeter = result.path?.includes('Perimeter');
  const reachedDestination = result.path?.includes('Destination');
  
  return (
    <div className="flex items-center justify-between w-full py-10 px-6 bg-gray-900/40 rounded-2xl border border-gray-800 mb-6 overflow-hidden relative">
      <div className="flex flex-col items-center gap-3 z-10">
        <div className="w-12 h-12 bg-blue-600 rounded-2xl flex items-center justify-center text-white shadow-lg shadow-blue-900/40 print:shadow-none">
          <Globe size={24} />
        </div>
        <div className="text-center">
          <span className="text-[10px] font-black uppercase text-gray-400 block tracking-normal">Source</span>
          <span className="text-[10px] font-mono text-blue-400 leading-normal">Sentinela Lab</span>
        </div>
      </div>
      
      <div className={`flex-1 h-0.5 mx-4 relative ${reachedPerimeter ? 'bg-blue-500' : 'bg-gray-800'}`}>
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-gray-950 p-1.5 rounded-full border border-gray-800 print:bg-white">
          <ArrowRight size={14} className={reachedPerimeter ? 'text-blue-500' : 'text-gray-800'} />
        </div>
      </div>

      <div className="flex flex-col items-center gap-3 z-10 relative">
        <div className={`w-14 h-14 rounded-2xl border-2 flex items-center justify-center transition-all duration-500 ${result.status === 'blocked' ? 'bg-green-950/30 border-green-500 text-green-500 shadow-lg shadow-green-900/20' : reachedPerimeter ? 'bg-red-950/20 border-red-500 text-red-500' : 'bg-gray-800 border-gray-700 text-gray-600'} print:shadow-none`}>
          <Shield size={28} />
        </div>
        <div className="text-center">
          <span className="text-[10px] font-black uppercase text-gray-400 block tracking-normal">Perimeter</span>
          <span className="text-[10px] font-mono text-gray-500 max-w-[120px] truncate leading-normal">{result.blockingAgent || 'NGFW Gateway'}</span>
        </div>
        {result.status === 'blocked' && (
           <div className="absolute -top-12 bg-green-500 text-black text-[9px] font-black px-3 py-1.5 rounded-full whitespace-nowrap animate-bounce shadow-xl print:animate-none print:shadow-none">
             BLOCKED BY {result.blockingAgent?.split(' ')[0].toUpperCase()}
           </div>
        )}
      </div>

      <div className={`flex-1 h-0.5 mx-4 relative ${reachedDestination ? 'bg-red-500' : 'bg-gray-800'}`}>
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-gray-950 p-1.5 rounded-full border border-gray-800 print:bg-white">
          <ArrowRight size={14} className={reachedDestination ? 'text-red-500' : 'text-gray-800'} />
        </div>
      </div>

      <div className="flex flex-col items-center gap-3 z-10">
        <div className={`w-12 h-12 rounded-2xl border-2 flex items-center justify-center transition-all ${reachedDestination ? 'bg-red-600 border-red-400 text-white shadow-2xl shadow-red-900/60 scale-110' : 'bg-gray-800 border-gray-700 text-gray-600'} print:shadow-none print:scale-100`}>
          <Server size={24} />
        </div>
        <div className="text-center">
          <span className="text-[10px] font-black uppercase text-gray-400 block tracking-normal">Host</span>
          <span className={`text-[10px] font-mono leading-normal ${reachedDestination ? 'text-red-400' : 'text-gray-600'}`}>Target Server</span>
        </div>
        {reachedDestination && (
           <div className="absolute -top-12 bg-red-600 text-white text-[9px] font-black px-3 py-1.5 rounded-full whitespace-nowrap animate-pulse shadow-xl print:animate-none print:shadow-none">
             EXPLOIT SUCCESSFUL
           </div>
        )}
      </div>

      <div className="absolute inset-0 opacity-[0.03] pointer-events-none print:hidden" style={{ backgroundImage: 'radial-gradient(circle, #fff 1px, transparent 1px)', backgroundSize: '20px 20px' }} />
    </div>
  );
};

export const ReportView: React.FC<Props> = ({ summary, results }) => {
  const [isExporting, setIsExporting] = useState(false);

  const handleDownloadPDF = () => {
    setIsExporting(true);
    setTimeout(() => {
      window.print();
      setIsExporting(false);
    }, 500);
  };

  const pieData = [
    { name: 'Blocked', value: summary.blockedCount, color: '#10b981' },
    { name: 'Passed', value: summary.passedCount, color: '#ef4444' }
  ];

  const uniqueAgents = Array.from(new Set(results.map(r => r.blockingAgent).filter(Boolean)));

  return (
    <div className="space-y-6 lg:space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 pb-20 print:p-0 print:pb-0 print:space-y-4 overflow-visible">
      <style>{`
        @media print {
          body { background: white !important; color: black !important; -webkit-print-color-adjust: exact !important; }
          .bg-gray-950, .bg-gray-900, .bg-gray-800, .bg-gray-800\\/50 { background: #f9fafb !important; color: black !important; border-color: #e5e7eb !important; }
          .text-white, .text-gray-100, .text-gray-200, .text-gray-300 { color: black !important; }
          .text-gray-400, .text-gray-500, .text-gray-600 { color: #4b5563 !important; }
          .print\\:hidden { display: none !important; }
          .rounded-2xl, .rounded-xl { border-radius: 8px !important; }
          .border { border: 1px solid #e5e7eb !important; }
          table { border-collapse: collapse !important; width: 100% !important; border: 1px solid #e5e7eb !important; }
          th, td { border: 1px solid #e5e7eb !important; color: black !important; padding: 12px !important; line-height: 1.5 !important; }
          .shadow-lg, .shadow-2xl, .shadow-xl { shadow: none !important; box-shadow: none !important; }
          aside, header, footer, button { display: none !important; }
          .print\\:block { display: block !important; }
          .bg-blue-600 { background-color: #2563eb !important; color: white !important; }
          .bg-green-500 { background-color: #10b981 !important; color: white !important; }
          .bg-red-600 { background-color: #dc2626 !important; color: white !important; }
          @page { margin: 1.5cm; }
        }
      `}</style>

      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 print:mb-8">
        <div>
          <h2 className="text-2xl font-black uppercase tracking-tight flex items-center gap-3">
            <FileText className="text-blue-500" /> Forensic Security Audit
          </h2>
          <p className="text-xs text-gray-500 font-mono mt-1">REPORT_UID: {Math.random().toString(36).substr(2, 9).toUpperCase()}</p>
        </div>
        <button 
          onClick={handleDownloadPDF}
          disabled={isExporting}
          className="print:hidden flex items-center gap-2 px-5 py-2.5 bg-gray-100 text-gray-900 hover:bg-white rounded-xl font-bold text-xs transition-all shadow-lg active:scale-95 disabled:opacity-50"
        >
          {isExporting ? <Loader2 size={16} className="animate-spin" /> : <FileDown size={16} />}
          {isExporting ? 'Preparing Report...' : 'Download PDF Report'}
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-gray-800/50 p-6 rounded-2xl border border-gray-700 hover:border-blue-500/50 transition-all group print:bg-gray-50">
           <div className="flex items-center justify-between mb-4">
             <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest leading-normal">Resilience</span>
             <Activity size={14} className="text-blue-500" />
           </div>
           <div className="text-5xl font-black text-white group-hover:scale-105 transition-transform origin-left leading-tight py-1">{summary.score}%</div>
           <div className="mt-4 h-2 bg-gray-900 rounded-full overflow-hidden print:border print:bg-gray-200">
             <div className="h-full bg-blue-500" style={{ width: `${summary.score}%` }} />
           </div>
        </div>
        
        <div className="bg-gray-800/50 p-6 rounded-2xl border border-gray-700 hover:border-green-500/50 transition-all group print:bg-gray-50">
           <div className="flex items-center justify-between mb-4">
             <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest leading-normal">Interceptions</span>
             <ShieldCheck size={14} className="text-green-500" />
           </div>
           <div className="text-5xl font-black text-green-400 leading-tight py-1">{summary.blockedCount}</div>
           <div className="text-[10px] text-gray-500 mt-2 font-mono uppercase tracking-normal">Verified Blocks</div>
        </div>

        <div className="bg-gray-800/50 p-6 rounded-2xl border border-gray-700 hover:border-red-500/50 transition-all group print:bg-gray-50">
           <div className="flex items-center justify-between mb-4">
             <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest leading-normal">Gaps</span>
             <ShieldAlert size={14} className="text-red-500" />
           </div>
           <div className="text-5xl font-black text-red-500 leading-tight py-1">{summary.passedCount}</div>
           <div className="text-[10px] text-gray-500 mt-2 font-mono uppercase tracking-normal">Weaknesses</div>
        </div>

        <div className="bg-gray-800/50 p-6 rounded-2xl border border-gray-700 hover:border-purple-500/50 transition-all group print:bg-gray-50">
           <div className="flex items-center justify-between mb-4">
             <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest leading-normal">Posture</span>
             <Cpu size={14} className="text-purple-500" />
           </div>
           <div className={`text-3xl font-black leading-tight py-1 ${summary.overallHealth === 'Good' ? 'text-green-400' : 'text-red-400'}`}>{summary.overallHealth}</div>
           <div className="text-[10px] text-gray-500 mt-2 font-mono uppercase tracking-normal">System Status</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
           <div className="bg-gray-800 p-8 rounded-2xl border border-gray-700 print:bg-white print:border-gray-200">
              <h3 className="text-xl font-black mb-8 flex items-center gap-3">
                <Target size={22} className="text-blue-500" /> 
                <span className="tracking-tight uppercase">Attack Topology Analysis</span>
              </h3>
              <div className="space-y-8">
                 {results.slice(0, 5).map((res, i) => (
                    <div key={i} className="animate-in fade-in slide-in-from-left-4 duration-500" style={{ animationDelay: `${i * 150}ms` }}>
                       <div className="flex items-center justify-between mb-4">
                          <div className="flex items-center gap-3">
                             <div className="p-2 bg-gray-900 rounded-md border border-gray-700 print:bg-gray-100">
                                <Terminal size={14} className="text-blue-400" />
                             </div>
                             <span className="text-xs font-black uppercase tracking-normal text-gray-200 leading-relaxed">
                                {TEST_PAYLOADS.find(p => p.id === res.testId)?.name}
                             </span>
                          </div>
                          <span className={`text-[10px] font-black px-2.5 py-1 rounded border ${res.status === 'blocked' ? 'bg-green-950/30 border-green-900/50 text-green-400' : 'bg-red-950/30 border-red-900/50 text-red-400'} print:text-black`}>
                             {res.status.toUpperCase()}
                          </span>
                       </div>
                       <AttackPathFlow result={res} />
                    </div>
                 ))}
                 {results.length > 5 && (
                   <div className="text-center py-4 text-[10px] font-bold text-gray-600 uppercase tracking-widest print:text-gray-400">
                     + {results.length - 5} additional attack traces documented below
                   </div>
                 )}
              </div>
           </div>

           <div className="bg-gray-800 p-8 rounded-2xl border border-gray-700 print:bg-white print:border-gray-200">
             <h3 className="text-xl font-black mb-6 flex items-center gap-3">
               <Zap size={22} className="text-orange-500" /> 
               <span className="tracking-tight uppercase leading-normal">Forensic Intelligence Insights</span>
             </h3>
             <div className="text-[11px] font-mono text-gray-300 bg-gray-950/50 p-8 rounded-2xl border border-gray-800 leading-relaxed whitespace-pre-wrap shadow-inner print:shadow-none print:bg-gray-50 print:text-gray-800 print:border-gray-200">
                {summary.aiAnalysis}
             </div>
           </div>
        </div>

        <div className="space-y-6">
           <div className="bg-gray-800 p-8 rounded-2xl border border-gray-700 print:bg-white print:border-gray-200">
              <h3 className="text-lg font-black uppercase tracking-tight mb-6 leading-normal">Threat Distribution</h3>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={pieData} innerRadius={60} outerRadius={80} paddingAngle={8} dataKey="value" stroke="none">
                      {pieData.map((entry, index) => (<Cell key={`cell-${index}`} fill={entry.color} />))}
                    </Pie>
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#030712', border: '1px solid #374151', borderRadius: '12px', fontSize: '10px', color: '#fff' }} 
                      itemStyle={{ color: '#fff' }}
                      className="print:hidden"
                    />
                    <Legend verticalAlign="bottom" height={36} iconType="circle" wrapperStyle={{ fontSize: '10px', fontWeight: 'bold', textTransform: 'uppercase' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
           </div>

           <div className="bg-gray-800 p-8 rounded-2xl border border-gray-700 print:bg-white print:border-gray-200">
              <h3 className="text-[10px] font-black text-gray-500 uppercase tracking-widest mb-6 leading-normal">Identified Agents</h3>
              <div className="space-y-3">
                 {uniqueAgents.map((agent, i) => (
                   <div key={i} className="flex items-center justify-between p-4 bg-gray-900/50 rounded-xl border border-gray-700 group hover:border-blue-500/30 transition-all cursor-default print:bg-gray-50 print:border-gray-200">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-blue-600/10 flex items-center justify-center text-blue-500 print:bg-blue-600 print:text-white">
                           <CheckCircle2 size={16} />
                        </div>
                        <span className="text-[11px] font-bold text-gray-200 print:text-black leading-normal">{agent}</span>
                      </div>
                      <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse shadow-lg shadow-green-500/50 print:bg-green-600 print:animate-none print:shadow-none" />
                   </div>
                 ))}
                 {uniqueAgents.length === 0 && (
                   <div className="text-center py-6 border-2 border-dashed border-gray-800 rounded-xl text-[10px] text-gray-600 font-bold uppercase tracking-widest print:border-gray-200">
                     No active agents detected
                   </div>
                 )}
              </div>
           </div>
        </div>
      </div>

      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden shadow-2xl print:shadow-none print:bg-white print:border-gray-200">
        <div className="p-8 bg-gray-900/50 border-b border-gray-700 flex items-center justify-between print:bg-gray-50">
           <h3 className="text-xl font-black uppercase tracking-tight leading-normal">Technical Evidence Ledger</h3>
           <FileText size={20} className="text-gray-500" />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[11px]">
            <thead className="bg-gray-950/80 text-gray-500 uppercase tracking-widest text-[9px] font-black print:bg-gray-100">
              <tr>
                <th className="px-8 py-5">Attack Vector</th>
                <th className="px-8 py-5">Forensic Capture</th>
                <th className="px-8 py-5">Interception Point</th>
                <th className="px-8 py-5 text-right">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50 print:divide-gray-200">
              {results.map((res, i) => (
                <tr key={i} className="hover:bg-gray-700/30 transition-all group print:hover:bg-transparent">
                  <td className="px-8 py-5">
                    <div className="font-bold text-gray-100 print:text-black leading-normal">{TEST_PAYLOADS.find(p => p.id === res.testId)?.name}</div>
                    <div className="text-[10px] text-gray-500 font-bold mt-1 uppercase tracking-normal leading-normal">
                      {TEST_PAYLOADS.find(p => p.id === res.testId)?.category}
                    </div>
                  </td>
                  <td className="px-8 py-5 max-w-lg">
                    <div className={`font-mono text-[10px] p-4 rounded-lg border shadow-inner whitespace-pre-wrap break-all leading-relaxed ${res.status === 'blocked' ? 'bg-green-950/10 border-green-900/30 text-green-300 print:bg-green-50 print:text-green-800 print:border-green-200' : 'bg-red-950/10 border-red-900/30 text-red-300 print:bg-red-50 print:text-red-800 print:border-red-200'}`}>
                       {res.proof}
                    </div>
                  </td>
                  <td className="px-8 py-5">
                    <div className="flex items-center gap-2">
                       <Shield size={12} className={res.status === 'blocked' ? 'text-green-500' : 'text-red-500'} />
                       <span className="text-[11px] font-black uppercase tracking-normal text-blue-400 print:text-blue-700 leading-normal">
                         {res.blockingAgent || 'Endpoint Server'}
                       </span>
                    </div>
                  </td>
                  <td className="px-8 py-5 text-right font-mono text-gray-500 group-hover:text-blue-400 transition-colors print:text-black leading-normal">
                    {res.responseTime}ms
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      
      <div className="hidden print:block text-center mt-12 border-t pt-8 text-gray-400 font-mono text-[8px] uppercase tracking-widest">
        Confidential Security Forensic Audit • Generated by Sentinela Lab Intelligence • Page 1
      </div>
    </div>
  );
};
