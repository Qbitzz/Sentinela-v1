
import React, { useState } from 'react';
import { TestPayload, TestResult, TestStatus } from '../types';
import { TestRunner } from '../services/testRunner';
import { StatusBadge } from './ui/Badge';
import { Terminal, Shield, Play, Copy, AlertCircle, Monitor, Globe, Check, X, HelpCircle } from 'lucide-react';

interface Props {
  payload: TestPayload;
  onResult: (result: TestResult) => void;
  targetUrl: string;
}

export const TestCard: React.FC<Props> = ({ payload, onResult, targetUrl }) => {
  const [status, setStatus] = useState<TestStatus>(TestStatus.IDLE);
  const [lastResult, setLastResult] = useState<TestResult | null>(null);
  const [isConfirming, setIsConfirming] = useState(false);

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
    <div className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden hover:border-gray-500 transition-all group flex flex-col h-full relative">
      <div className="p-5 flex-1">
        <div className="flex justify-between items-start mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gray-900 rounded-lg text-blue-400 group-hover:text-blue-300 transition-colors">
              {payload.type === 'network' ? <Globe size={18} /> : <Monitor size={18} />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-gray-100">{payload.name}</h3>
                <span className={`text-[9px] font-black px-1.5 py-0.5 border rounded leading-none ${getTargetStyles()}`}>
                  {payload.targetDevice}
                </span>
              </div>
              <p className="text-xs text-gray-400">{payload.category}</p>
            </div>
          </div>
          <StatusBadge status={status} />
        </div>
        
        <p className="text-sm text-gray-300 mb-6 leading-relaxed line-clamp-2">
          {payload.description}
        </p>

        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs text-gray-500">
            <span>Expected:</span>
            <span className="text-gray-400 italic font-medium">{payload.expectedBehavior}</span>
          </div>

          <div className="bg-gray-950 rounded p-2 text-[10px] mono text-gray-500 break-all border border-gray-900">
            {payload.content.substring(0, 80)}{payload.content.length > 80 ? '...' : ''}
          </div>
        </div>

        {status === TestStatus.PASSED && (
          <div className="mt-4 p-3 bg-red-950/20 border border-red-900/50 rounded-lg animate-in fade-in slide-in-from-top-2">
            <div className="flex items-center gap-2 text-red-400 mb-1">
              <AlertCircle size={14} />
              <span className="text-[10px] font-bold uppercase">Security Gap Detected</span>
            </div>
            <p className="text-[10px] text-gray-400 leading-tight">
              The payload was not blocked by your {payload.targetDevice}. Ensure SSL Inspection is active and signatures are up-to-date.
            </p>
          </div>
        )}
      </div>

      <div className="bg-gray-900/50 px-5 py-3 border-t border-gray-700 flex items-center justify-between mt-auto min-h-[52px]">
        {isConfirming ? (
          <div className="flex items-center gap-4 w-full justify-between animate-in fade-in slide-in-from-right-2 duration-200">
            <span className="text-xs font-bold text-orange-400">Trigger Attack?</span>
            <div className="flex gap-2">
              <button onClick={handleRun} className="p-1.5 bg-green-600 hover:bg-green-500 text-white rounded-md transition-colors"><Check size={16} /></button>
              <button onClick={() => setIsConfirming(false)} className="p-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded-md transition-colors"><X size={16} /></button>
            </div>
          </div>
        ) : (
          <>
            <button 
              onClick={() => setIsConfirming(true)}
              disabled={status === TestStatus.RUNNING}
              className="flex items-center gap-2 text-sm font-semibold text-blue-400 hover:text-blue-300 disabled:opacity-50 transition-colors"
            >
              <Play size={14} />
              {status === TestStatus.RUNNING ? 'Testing...' : 'Execute Vector'}
            </button>
            
            <div className="flex gap-2">
              <div className="group/help relative">
                <HelpCircle size={16} className="text-gray-600 hover:text-gray-400 cursor-help" />
                <div className="absolute bottom-full right-0 mb-2 w-64 bg-gray-950 text-[10px] p-3 rounded shadow-2xl invisible group-hover/help:visible z-10 border border-gray-800 text-gray-400">
                  <span className="font-bold text-blue-400 block mb-1">Methodology:</span>
                  This test sends the malicious string to <span className="text-white font-mono">{targetUrl}</span>. If your firewall allows the request to complete, the test shows 'Passed' (Security Failure).
                </div>
              </div>
              {lastResult && (
                 <div className="group/info relative">
                   <AlertCircle size={16} className="text-gray-500 cursor-help" />
                   <div className="absolute bottom-full right-0 mb-2 w-56 bg-gray-950 text-[10px] p-3 rounded shadow-2xl invisible group-hover/info:visible z-10 border border-gray-800">
                      <div className="font-bold text-gray-300 mb-1">Observation Log:</div>
                      {lastResult.details}
                   </div>
                 </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
};
