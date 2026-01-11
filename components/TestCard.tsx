
import React, { useState } from 'react';
import { TestPayload, TestResult, TestStatus } from '../types';
import { TestRunner } from '../services/testRunner';
import { StatusBadge } from './ui/Badge';
import { Play, AlertCircle, Monitor, Globe, Check, X, ChevronDown, ChevronUp, Terminal, Shield } from 'lucide-react';

interface Props {
  payload: TestPayload;
  onResult: (result: TestResult) => void;
  targetUrl: string;
}

export const TestCard: React.FC<Props> = ({ payload, onResult, targetUrl }) => {
  const [status, setStatus] = useState<TestStatus>(TestStatus.IDLE);
  const [lastResult, setLastResult] = useState<TestResult | null>(null);
  const [isConfirming, setIsConfirming] = useState(false);
  const [showDetails, setShowDetails] = useState(false);

  const handleRun = async () => {
    setIsConfirming(false);
    setStatus(TestStatus.RUNNING);
    const result = await TestRunner.run(payload, targetUrl);
    setStatus(result.status);
    setLastResult(result);
    onResult(result);
  };

  const getTargetStyles = () => {
    switch(payload.targetDevice) {
      case 'NGFW': return 'bg-orange-950/40 text-orange-400 border-orange-900/50';
      case 'EDR': return 'bg-purple-950/40 text-purple-400 border-purple-900/50';
      default: return 'bg-blue-950/40 text-blue-400 border-blue-900/50';
    }
  };

  return (
    <div className={`bg-gray-800 border ${status === TestStatus.PASSED ? 'border-red-600/50 shadow-lg shadow-red-950/20' : 'border-gray-700'} rounded-xl overflow-hidden hover:border-gray-500 transition-all group flex flex-col h-full`}>
      <div className="p-5 flex-1">
        <div className="flex justify-between items-start mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gray-900 rounded-lg text-blue-400 group-hover:text-blue-300 transition-colors">
              {payload.type === 'network' ? <Globe size={18} /> : <Monitor size={18} />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-gray-100 text-sm">{payload.name}</h3>
                <span className={`text-[8px] font-black px-1.5 py-0.5 border rounded leading-none ${getTargetStyles()}`}>
                  {payload.targetDevice}
                </span>
              </div>
            </div>
          </div>
          <StatusBadge status={status} />
        </div>
        
        <p className="text-xs text-gray-400 mb-6 leading-relaxed line-clamp-2">
          {payload.description}
        </p>

        {lastResult?.proof && (
          <div className="mb-4 space-y-2">
            <div className={`flex items-center gap-1.5 text-[10px] font-black uppercase ${status === TestStatus.PASSED ? 'text-red-400' : 'text-green-400'}`}>
              <Terminal size={12} /> Captured Forensics:
            </div>
            <div className={`border rounded p-2 text-[9px] mono overflow-hidden break-all whitespace-pre-wrap max-h-24 overflow-y-auto custom-scrollbar ${status === TestStatus.PASSED ? 'bg-red-950/30 border-red-900/50 text-red-200' : 'bg-green-950/20 border-green-900/40 text-green-200'}`}>
              {lastResult.proof}
            </div>
          </div>
        )}

        <div className="bg-gray-950 rounded p-2 text-[9px] mono text-gray-500 break-all border border-gray-900/50 mb-4">
          Vector: {payload.content.substring(0, 100)}{payload.content.length > 100 ? '...' : ''}
        </div>

        {lastResult && (
          <div className="mt-2">
            <button 
              onClick={() => setShowDetails(!showDetails)}
              className="flex items-center gap-1 text-[10px] font-bold text-gray-500 hover:text-gray-300 uppercase tracking-tighter"
            >
              {showDetails ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
              Protocol Evidence
            </button>
            {showDetails && (
              <div className="mt-2 p-3 bg-gray-900 rounded text-[10px] text-gray-400 border border-gray-800 animate-in slide-in-from-top-1 duration-200">
                {lastResult.details}
                {lastResult.responseTime && <div className="mt-2 text-blue-500 font-mono">RTT: {lastResult.responseTime}ms</div>}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="bg-gray-900/50 px-5 py-3 border-t border-gray-700 flex items-center justify-between min-h-[52px]">
        {isConfirming ? (
          <div className="flex items-center gap-4 w-full justify-between animate-in fade-in slide-in-from-right-2 duration-200">
            <span className="text-[10px] font-bold text-orange-400 uppercase tracking-wider">Execute Vector?</span>
            <div className="flex gap-2">
              <button onClick={handleRun} className="p-1.5 bg-red-600 hover:bg-red-500 text-white rounded-md transition-colors"><Check size={14} /></button>
              <button onClick={() => setIsConfirming(false)} className="p-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded-md transition-colors"><X size={14} /></button>
            </div>
          </div>
        ) : (
          <>
            <button 
              onClick={() => setIsConfirming(true)}
              disabled={status === TestStatus.RUNNING}
              className="flex items-center gap-2 text-xs font-bold text-blue-400 hover:text-blue-300 disabled:opacity-50 transition-colors uppercase tracking-widest"
            >
              <Play size={12} fill="currentColor" />
              {status === TestStatus.RUNNING ? 'Triggering...' : 'Attack'}
            </button>
            
            {status === TestStatus.BLOCKED && (
              <div className="flex items-center gap-1 text-green-500">
                <Shield size={14} />
                <span className="text-[9px] font-black uppercase tracking-tight">Intercepted</span>
              </div>
            )}
            {status === TestStatus.PASSED && (
              <div className="flex items-center gap-1 text-red-500 animate-pulse">
                <AlertCircle size={14} />
                <span className="text-[9px] font-black uppercase tracking-tight">Exposed</span>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};
