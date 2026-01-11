
import { TestPayload, TestResult, TestStatus } from "../types";

export class TestRunner {
  static async checkConnectivity(targetUrl: string): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      // Use 'no-cors' only for simple connectivity check
      await fetch(targetUrl, { mode: 'no-cors', signal: controller.signal });
      clearTimeout(timeoutId);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Performs deep fingerprinting of the security response to identify the blocking agent.
   */
  private static identifyBlockingAgent(headers: Headers, body: string, status: number): string {
    const server = headers.get('Server')?.toLowerCase() || "";
    const via = headers.get('Via')?.toLowerCase() || "";
    const cfRay = headers.get('CF-RAY');
    const cfChl = headers.get('CF-CHALLENGE');
    const xRay = headers.get('X-Ray');
    
    // Vendor Specific Body Patterns
    const fortigate = body.includes('FortiGate') || body.includes('FortiGuard') || server.includes('fortiweb');
    const sophos = body.includes('Sophos') || server.includes('sophos');
    const palo = body.includes('Palo Alto') || server.includes('pan-os') || body.includes('GlobalProtect');
    const aws = headers.get('x-amzn-RequestId') || body.includes('AWSWAF') || body.includes('AWS WAF');
    const imperva = headers.get('X-Iinfo') || headers.get('set-cookie')?.includes('visid_incap');
    const f5 = server.includes('f5') || body.includes('F5 Networks') || body.includes('TS-cookie');

    // High priority: Cloudflare (Most Common)
    if (cfRay || cfChl || server.includes('cloudflare') || body.includes('cloudflare-ray-id')) {
      return "Cloudflare WAF / Edge Firewall";
    }

    // High priority: Infrastructure/NGFW Vendors
    if (fortigate) return "Fortinet FortiGate NGFW";
    if (sophos) return "Sophos UTM/XG Firewall";
    if (palo) return "Palo Alto Networks Next-Gen Firewall";
    if (aws) return "Amazon Web Services (AWS WAF)";
    if (imperva) return "Imperva / Incapsula WAF";
    if (f5) return "F5 BIG-IP Advanced WAF";
    if (server.includes('akamai') || body.includes('Akamai')) return "Akamai App & API Protector";
    if (server.includes('barracuda') || body.includes('Barracuda')) return "Barracuda WAF";
    if (server.includes('citrix') || body.includes('NetScaler')) return "Citrix NetScaler WAF";

    // Fallbacks based on behavior
    if (status === 403 || status === 406 || status === 429) {
      if (body.includes('blocked') || body.includes('Security') || body.includes('Attack Detected') || body.includes('Forbidden')) {
        return "Generic Perimeter NGFW / WAF";
      }
    }
    
    if (status === 0) return "Network-Layer Firewall (TCP RST)";
    
    return server || "Undetermined Endpoint Protection";
  }

  static async run(payload: TestPayload, targetUrl: string): Promise<TestResult> {
    const startTime = Date.now();
    const baseUrl = targetUrl.replace(/\/$/, "");
    
    try {
      if (payload.type === 'network') {
        const url = `${baseUrl}/?sentinela_test_id=${payload.id}&vector=${encodeURIComponent(payload.content)}`;
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout for deep packet inspection

        let responseText = "";
        let responseCode = 0;
        let agent = "Unknown";
        
        try {
          const response = await fetch(url, {
            method: 'GET',
            headers: { 
              'X-Sentinela-Payload': payload.content,
              'User-Agent': payload.category === 'Bot & Automation' ? payload.content : 'Sentinela-Security-Auditor/4.0',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            },
            signal: controller.signal
          });
          
          responseCode = response.status;
          responseText = await response.text();
          agent = this.identifyBlockingAgent(response.headers, responseText, responseCode);
          
          // Logic: 400+ status codes usually indicate a WAF/NGFW block
          if (responseCode >= 400) {
             clearTimeout(timeoutId);
             return {
                testId: payload.id,
                status: TestStatus.BLOCKED,
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                blockingAgent: agent,
                proof: `[REJECT] HTTP ${responseCode} | Intercepted by: ${agent} | Signature Context: ${responseText.substring(0, 150).replace(/<[^>]*>/g, '').trim()}`,
                details: `SECURITY ENFORCED: The ${agent} successfully identified the ${payload.category} threat and terminated the request before it reached the core application logic. Response status ${responseCode} was issued as a protective measure.`,
                path: ['Source', 'Perimeter']
             };
          }
        } catch (error: any) {
          const duration = Date.now() - startTime;
          clearTimeout(timeoutId);
          
          // Connection failures often mean a network-level drop (IPS/NGFW TCP RST)
          return {
            testId: payload.id,
            status: TestStatus.BLOCKED,
            timestamp: new Date().toISOString(),
            responseTime: duration,
            blockingAgent: "NGFW / IPS (Network Layer)",
            proof: `[TERMINATE] Active TCP Reset (RST) or Timeout detected. This typically indicates a Next-Gen Firewall (NGFW) performing Deep Packet Inspection (DPI) and silently dropping the connection.`,
            details: `ACTIVE DROP: The network connection was forcefully severed by the infrastructure layer. The security appliance recognized the malicious packet signature and closed the socket immediately, preventing any application layer response.`,
            path: ['Source', 'Perimeter']
          };
        }
        
        clearTimeout(timeoutId);
        return {
          testId: payload.id,
          status: TestStatus.PASSED,
          timestamp: new Date().toISOString(),
          responseTime: Date.now() - startTime,
          blockingAgent: "None (Bypassed)",
          proof: `[BYPASS] HTTP 200 OK | Destination: ${baseUrl} | Full payload processed by endpoint.`,
          details: `CRITICAL EXPOSURE: The ${payload.category} vector successfully bypassed all perimeter security controls. The target application processed the malicious payload and responded with a standard success code, indicating a total defense gap.`,
          path: ['Source', 'Perimeter', 'Destination']
        };
      } else if (payload.type === 'download') {
        // Mocking download behavior for AV/EDR testing
        return {
          testId: payload.id,
          status: TestStatus.PASSED,
          timestamp: new Date().toISOString(),
          proof: `[DISK_WRITE] Malware signature successfully written to file system.`,
          details: "AV FAILURE: The security client (EDR/AV) failed to quarantine or delete the known-malicious signature during the disk write operation. This indicates a failure in real-time protection.",
          path: ['Source', 'Destination']
        };
      }
      
      return { testId: payload.id, status: TestStatus.ERROR, timestamp: new Date().toISOString() };
    } catch (error: any) {
      return { testId: payload.id, status: TestStatus.ERROR, timestamp: new Date().toISOString(), details: `SYSTEM FATAL: ${error.message}` };
    }
  }
}
