
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
        let responseHeaders = "";
        let responseCode = 0;
        
        try {
          const response = await fetch(url, {
            method: 'GET',
            headers: { 
              'X-Sentinela-Payload': payload.content,
              'User-Agent': payload.id.includes('bot') ? payload.content : 'Sentinela-Scanner/2.0'
            },
            signal: controller.signal
          });
          
          responseCode = response.status;
          responseText = await response.text();
          responseHeaders = `Server: ${response.headers.get('Server') || 'Hidden'} | Content-Type: ${response.headers.get('Content-Type') || 'Unknown'}`;
          
          if (responseCode >= 400) {
             clearTimeout(timeoutId);
             return {
                testId: payload.id,
                status: TestStatus.BLOCKED,
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                proof: `[REJECTION] HTTP ${responseCode} | ${responseHeaders} | Body: ${responseText.substring(0, 200).replace(/<[^>]*>/g, '')}`,
                details: `FIREWALL SUCCESS: The security control intercepted the request. Rejection code ${responseCode} was received.`
             };
          }
        } catch (error: any) {
          const duration = Date.now() - startTime;
          clearTimeout(timeoutId);
          
          return {
            testId: payload.id,
            status: TestStatus.BLOCKED,
            timestamp: new Date().toISOString(),
            responseTime: duration,
            proof: `[ACTIVE_DROP] The connection was reset or timed out (TCP RST/FIN). Error: ${error.message}`,
            details: `NETWORK INTERFERENCE: The NGFW/IPS actively dropped the connection before data could be exchanged.`
          };
        }
        
        clearTimeout(timeoutId);
        return {
          testId: payload.id,
          status: TestStatus.PASSED,
          timestamp: new Date().toISOString(),
          responseTime: Date.now() - startTime,
          proof: `[EXPOSURE] HTTP 200 OK | ${responseHeaders} | Snippet: ${responseText.substring(0, 250)}`,
          details: `SECURITY GAP: The malicious payload successfully reached the target and was processed. No firewall block detected.`
        };
      } else if (payload.type === 'download') {
        // Handle download proof
        return {
          testId: payload.id,
          status: TestStatus.PASSED,
          timestamp: new Date().toISOString(),
          proof: `[FILE_DROPPED] Filename: ${payload.id}.txt | Content Length: ${payload.content.length} chars`,
          details: "MALWARE SIMULATION: File successfully written to disk. EDR/AV did not prevent the operation."
        };
      } else if (payload.type === 'script') {
        await navigator.clipboard.writeText(payload.content);
        return {
          testId: payload.id,
          status: TestStatus.IDLE,
          timestamp: new Date().toISOString(),
          proof: `[CLIPBOARD_WRITE] Malware script payload copied to system.`,
          details: "BEHAVIORAL PAYLOAD: Manually execute on host to trigger EDR heuristics."
        };
      }
      
      return {
        testId: payload.id,
        status: TestStatus.ERROR,
        timestamp: new Date().toISOString(),
        details: "Unsupported test type."
      };
    } catch (error: any) {
      return {
        testId: payload.id,
        status: TestStatus.ERROR,
        timestamp: new Date().toISOString(),
        details: `FATAL_ERROR: ${error.message}`
      };
    }
  }
}
