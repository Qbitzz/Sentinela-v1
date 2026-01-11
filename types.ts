
export enum TestCategory {
  WAF = 'Web Application Firewall',
  IPS = 'Intrusion Prevention',
  VIRUS = 'Virus Simulation',
  RANSOMWARE = 'Ransomware Simulation',
  MALWARE = 'Malware Simulation',
  EXFIL = 'Data Exfiltration',
  POST_EXPLOIT = 'Post-Exploitation',
  EDR = 'EDR Specific',
  API = 'API Security',
  EVASION = 'Encoding Evasion'
}

export enum TestStatus {
  IDLE = 'idle',
  RUNNING = 'running',
  BLOCKED = 'blocked', // Success for the NGFW/EDR
  PASSED = 'passed',   // Failure for the NGFW/EDR (payload got through)
  ERROR = 'error'
}

export interface TestPayload {
  id: string;
  name: string;
  description: string;
  category: TestCategory;
  type: 'network' | 'download' | 'script';
  content: string;
  targetDevice: 'NGFW' | 'EDR' | 'BOTH';
  target?: string;
  expectedBehavior: string;
}

export interface TestResult {
  testId: string;
  status: TestStatus;
  timestamp: string;
  details?: string;
  responseTime?: number;
  proof?: string; // Captured response data as evidence
}

export interface ReportSummary {
  overallHealth: 'Critical' | 'Moderate' | 'Good';
  score: number;
  blockedCount: number;
  passedCount: number;
  aiAnalysis: string;
}
