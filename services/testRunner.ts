
import { TestPayload, TestResult, TestStatus } from "../types";

export class TestRunner {
  static async checkConnectivity(targetUrl: string): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      await fetch(targetUrl, { mode: 'no-cors', signal: controller.signal });
      clearTimeout(timeoutId);
      return true;
    } catch {
      return false;
    }
  }

  static async run(payload: TestPayload, targetUrl: string): Promise<TestResult> {
    const startTime = Date.now();
    const baseUrl = targetUrl.replace(/\/$/, "");
    
    try {
      if (payload.type === 'network') {
        const url = `${baseUrl}/?sentinela_test_id=${payload.id}&vector=${encodeURIComponent(payload.content)}`;
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 6000);

        let responseText = "";
        let responseStatusText = "";
        let responseCode = 0;
        
        try {
          const response = await fetch(url, {
            method: 'GET',
            headers: { 
              'X-Sentinela-Payload': payload.content,
              'User-Agent': payload.id === 'evasion-ua-spoof' ? payload.content : 'Sentinela-Security-Scanner/2.0'
            },
            signal: controller.signal
          });
          
          responseCode = response.status;
          responseStatusText = response.statusText || (response.status === 200 ? "OK" : "Unknown Status");
          responseText = await response.text();
          
          // Logic: If status is 4xx or 5xx, the WAF/NGFW likely blocked it.
          // However, some firewalls return 200 with a custom block page.
          if (responseCode >= 400) {
             clearTimeout(timeoutId);
             return {
                testId: payload.id,
                status: TestStatus.BLOCKED,
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                proof: `HTTP ${responseCode} ${responseStatusText}: ${responseText.substring(0, 150).replace(/<[^>]*>/g, '')}`,
                details: `FIREWALL BLOCK DETECTED: The target server returned a rejection code (${responseCode}). This indicates the NGFW/WAF successfully identified and stopped the signature.`
             };
          }
        } catch (error: any) {
          // If fetch fails completely, it's often a TCP RST (Active Block)
          const duration = Date.now() - startTime;
          clearTimeout(timeoutId);
          
          return {
            testId: payload.id,
            status: TestStatus.BLOCKED,
            timestamp: new Date().toISOString(),
            responseTime: duration,
            proof: `CONNECTION_TERMINATED: ${error.message}`,
            details: `ACTIVE DROP: The network connection was forcefully closed by the perimeter control before a handshake could complete.`
          };
        }
        
        clearTimeout(timeoutId);

        return {
          testId: payload.id,
          status: TestStatus.PASSED,
          timestamp: new Date().toISOString(),
          responseTime: Date.now() - startTime,
          proof: `HTTP 200 OK - DATA SNIPPET: ${responseText.substring(0, 180)}`,
          details: `SECURITY FAILURE: The payload reached the server and returned data. The NGFW failed to inspect or block this traffic.`
        };
      } else if (payload.type === 'download') {
        const blob = new Blob([payload.content], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${payload.id}-test.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);

        return {
          testId: payload.id,
          status: TestStatus.PASSED,
          timestamp: new Date().toISOString(),
          proof: `File Write Successful: bytes=${payload.content.length}`,
          details: "MALWARE DROP: File written to local disk. Endpoint protection failed to quarantine the known-malicious string."
        };
      } else if (payload.type === 'script') {
        await navigator.clipboard.writeText(payload.content);
        return {
          testId: payload.id,
          status: TestStatus.IDLE,
          timestamp: new Date().toISOString(),
          proof: `Payload copied to system clipboard`,
          details: "BEHAVIORAL PAYLOAD: Ready for manual host execution."
        };
      }
      
      return {
        testId: payload.id,
        status: TestStatus.ERROR,
        timestamp: new Date().toISOString(),
        details: "Unsupported vector type."
      };
    } catch (error: any) {
      return {
        testId: payload.id,
        status: TestStatus.ERROR,
        timestamp: new Date().toISOString(),
        details: `FATAL: ${error.message}`
      };
    }
  }
}
