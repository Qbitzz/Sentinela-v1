
import React from 'react';
import { ReportSummary, TestResult } from '../types';
import { TEST_PAYLOADS } from '../constants';
import { 
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, 
  Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis 
} from 'recharts';
import { ShieldCheck, ShieldAlert, FileText, Zap, Activity, Target, AlertTriangle } from 'lucide-react';

interface Props {
  summary: ReportSummary;
  results: TestResult[];
}

export const ReportView: React.FC<Props> = ({ summary, results }) => {
  const pieData = [
    { name: 'Blocked', value: summary.blockedCount, color: '#10b981' },
    { name: 'Passed', value: summary.passedCount, color: '#ef4444' }
  ];

  const categoryStats = results.reduce((acc: any, curr) => {
    const payload = TEST_PAYLOADS.find(p => p.id === curr.testId);
    const cat = payload?.category || 'Unknown';
    if (!acc[cat]) acc[cat] = { subject: cat, blocked: 0, passed: 0, fullMark: 5 };
    if (curr.status === 'blocked') acc[cat].blocked += 1;
    else if (curr.status === 'passed') acc[cat].passed += 1;
    return acc;
  }, {});

  const barData = Object.values(categoryStats);

  const getHealthColor = () => {
    if (summary.overallHealth === 'Good') return 'text-green-400 bg-green-950/20 border-green-900/30';
    if (summary.overallHealth === 'Moderate') return 'text-yellow-400 bg-yellow-950/20 border-yellow-900/30';
    return 'text-red-400 bg-red-950/20 border-red-900/30';
  };

  return (
    <div className="space-y-6 lg:space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {/* Top Cards Header */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-gray-800 p-5 lg:p-6 rounded-2xl border border-gray-700">
          <div className="flex justify-between items-start mb-4">
            <div className="p-2 bg-blue-900/30 text-blue-400 rounded-lg"><Activity size={20} /></div>
            <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Score</span>
          </div>
          <div className="text-3xl lg:text-4xl font-black text-white">{summary.score}%</div>
          <div className="mt-4 h-1.5 bg-gray-900 rounded-full overflow-hidden">
            <div 
              className={`h-full transition-all duration-1000 ${summary.score > 70 ? 'bg-green-500' : summary.score > 40 ? 'bg-yellow-500' : 'bg-red-500'}`} 
              style={{ width: `${summary.score}%` }} 
            />
          </div>
        </div>

        <div className={`p-5 lg:p-6 rounded-2xl border border-gray-700 shadow-xl ${getHealthColor()}`}>
          <div className="flex justify-between items-start mb-4">
            <div className="p-2 bg-black/20 rounded-lg"><Target size={20} /></div>
            <span className="text-[10px] font-bold opacity-60 uppercase tracking-wider">Assessment</span>
          </div>
          <div className="text-2xl lg:text-3xl font-black">{summary.overallHealth}</div>
          <p className="mt-2 text-[10px] opacity-80">Security control telemetry.</p>
        </div>

        <div className="bg-gray-800 p-5 lg:p-6 rounded-2xl border border-gray-700 flex items-center gap-4">
          <div className="p-3 bg-green-900/30 text-green-400 rounded-xl"><ShieldCheck size={24} /></div>
          <div>
            <div className="text-2xl lg:text-3xl font-black text-white">{summary.blockedCount}</div>
            <div className="text-[9px] text-gray-500 font-bold uppercase tracking-widest leading-tight">Blocked</div>
          </div>
        </div>

        <div className="bg-gray-800 p-5 lg:p-6 rounded-2xl border border-gray-700 flex items-center gap-4">
          <div className="p-3 bg-red-900/30 text-red-400 rounded-xl"><ShieldAlert size={24} /></div>
          <div>
            <div className="text-2xl lg:text-3xl font-black text-white">{summary.passedCount}</div>
            <div className="text-[9px] text-gray-500 font-bold uppercase tracking-widest leading-tight">Gaps</div>
          </div>
        </div>
      </div>

      {/* Main Analysis Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 lg:gap-8">
        <div className="lg:col-span-2 space-y-6 lg:space-y-8">
          <div className="bg-gray-800 p-6 lg:p-8 rounded-2xl border border-gray-700 relative overflow-hidden group">
            <div className="absolute top-0 right-0 p-4 lg:p-8 opacity-5">
               <Zap size={100} className="text-blue-400 lg:w-[160px] lg:h-[160px]" />
            </div>
            <h3 className="text-lg lg:text-xl font-bold mb-6 flex items-center gap-3">
              <Zap size={18} className="text-blue-400" /> AI Insights
            </h3>
            <div className="text-xs lg:text-sm text-gray-300 leading-relaxed whitespace-pre-line z-10 relative">
              {summary.aiAnalysis}
            </div>
          </div>

          <div className="bg-gray-800 p-6 lg:p-8 rounded-2xl border border-gray-700">
            <h3 className="text-base lg:text-lg font-bold mb-6 flex items-center gap-2">
              <Activity size={18} className="text-green-400" /> Capability Matrix
            </h3>
            <div className="h-[250px] lg:h-[350px]">
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart cx="50%" cy="50%" outerRadius="80%" data={barData}>
                  <PolarGrid stroke="#374151" />
                  <PolarAngleAxis dataKey="subject" stroke="#9ca3af" fontSize={8} />
                  <PolarRadiusAxis angle={30} domain={[0, 'auto']} stroke="#4b5563" fontSize={8} />
                  <Radar name="Safe" dataKey="blocked" stroke="#10b981" fill="#10b981" fillOpacity={0.6} />
                  <Radar name="Gap" dataKey="passed" stroke="#ef4444" fill="#ef4444" fillOpacity={0.6} />
                  <Tooltip contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px', fontSize: '10px' }} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="space-y-6 lg:space-y-8">
           <div className="bg-gray-800 p-6 lg:p-8 rounded-2xl border border-gray-700 flex flex-col items-center">
              <h3 className="text-base lg:text-lg font-bold mb-4 w-full">Outcome Distribution</h3>
              <div className="h-48 lg:h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={pieData} innerRadius={40} lg:innerRadius={60} outerRadius={60} lg:outerRadius={80} paddingAngle={5} dataKey="value">
                      {pieData.map((entry, index) => (<Cell key={`cell-${index}`} fill={entry.color} />))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px', fontSize: '10px' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="grid grid-cols-2 gap-3 w-full mt-4">
                 <div className="text-center p-2 rounded-xl bg-gray-900 border border-gray-800">
                    <div className="text-green-400 font-black text-base">{summary.blockedCount}</div>
                    <div className="text-[8px] text-gray-500 uppercase font-bold tracking-tighter">Safe</div>
                 </div>
                 <div className="text-center p-2 rounded-xl bg-gray-900 border border-gray-800">
                    <div className="text-red-400 font-black text-base">{summary.passedCount}</div>
                    <div className="text-[8px] text-gray-500 uppercase font-bold tracking-tighter">Gap</div>
                 </div>
              </div>
           </div>

           <div className="bg-gray-800 p-6 lg:p-8 rounded-2xl border border-gray-700 overflow-hidden relative">
              <div className="absolute top-2 right-2">
                 <AlertTriangle size={14} className="text-red-500 opacity-30" />
              </div>
              <h3 className="text-[10px] font-bold text-gray-400 mb-6 uppercase tracking-widest">Top Risks</h3>
              <div className="space-y-4">
                 {results.filter(r => r.status === 'passed').slice(0, 3).map((r, i) => {
                    const p = TEST_PAYLOADS.find(x => x.id === r.testId);
                    return (
                       <div key={i} className="flex gap-3 items-start border-l-2 border-red-500 pl-3 py-0.5">
                          <div className="min-w-0">
                             <div className="text-xs lg:text-sm font-bold text-gray-200 truncate">{p?.name}</div>
                             <div className="text-[9px] text-gray-500 truncate">{p?.category}</div>
                          </div>
                       </div>
                    );
                 })}
                 {results.filter(r => r.status === 'passed').length === 0 && (
                    <div className="text-[10px] text-gray-500 italic">No evasions detected.</div>
                 )}
              </div>
           </div>
        </div>
      </div>

      {/* Log Table Section */}
      <div className="bg-gray-800 rounded-2xl lg:rounded-3xl border border-gray-700 overflow-hidden">
        <div className="p-5 lg:p-8 border-b border-gray-700 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-gray-900/30">
          <div>
            <h3 className="text-lg lg:text-xl font-bold">Event Ledger</h3>
            <p className="text-[10px] lg:text-xs text-gray-500 mt-1">Telemetry log for all vectors.</p>
          </div>
          <button className="w-full sm:w-auto px-4 py-2 text-[10px] bg-gray-900 hover:bg-black border border-gray-700 rounded-xl text-gray-300 transition-all flex items-center justify-center gap-2">
            <FileText size={14} className="text-blue-500" /> Export JSON
          </button>
        </div>
        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full text-left text-xs min-w-[600px]">
            <thead className="bg-gray-900/50 text-gray-400 font-bold uppercase tracking-wider text-[9px]">
              <tr>
                <th className="px-6 py-4">Test Vector</th>
                <th className="px-6 py-4">Platform</th>
                <th className="px-6 py-4">Outcome</th>
                <th className="px-6 py-4 text-right">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {results.map((res, i) => {
                const p = TEST_PAYLOADS.find(x => x.id === res.testId);
                return (
                  <tr key={i} className="hover:bg-gray-700/30 transition-colors">
                    <td className="px-6 py-3">
                       <div className="font-bold text-gray-100">{p?.name}</div>
                       <div className="text-[9px] text-gray-500 uppercase tracking-tighter">{p?.category}</div>
                    </td>
                    <td className="px-6 py-3">
                       <span className={`text-[8px] font-black px-1.5 py-0.5 border rounded uppercase ${p?.targetDevice === 'NGFW' ? 'text-orange-400 border-orange-900/30' : 'text-purple-400 border-purple-900/30'}`}>
                          {p?.targetDevice}
                       </span>
                    </td>
                    <td className="px-6 py-3">
                      <span className={`px-2 py-0.5 rounded-md text-[9px] font-black ${res.status === 'blocked' ? 'bg-green-500/10 text-green-400 border border-green-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                        {res.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-right text-gray-600 font-mono text-[9px] whitespace-nowrap">
                      {new Date(res.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
