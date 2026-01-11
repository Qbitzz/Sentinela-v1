
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
        const timeoutId = setTimeout(() => controller.abort(), 4000);

        // We use 'no-cors' so we don't need the target server to have CORS headers.
        // If the firewall is working, it will kill this connection.
        const response = await fetch(url, {
          method: 'GET',
          mode: 'no-cors',
          headers: { 
            'Cache-Control': 'no-cache',
            'X-Sentinela-Payload': payload.content
          },
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        return {
          testId: payload.id,
          status: TestStatus.PASSED,
          timestamp: new Date().toISOString(),
          responseTime: Date.now() - startTime,
          details: `SUCCESSFUL PENETRATION: The request was fulfilled by the target. The NGFW/WAF allowed this malicious signature to pass through without interference.`
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
          details: "FILE DROPPED: The malicious file was successfully saved to disk. EDR/AV did not prevent the file write operation."
        };
      } else if (payload.type === 'script') {
        await navigator.clipboard.writeText(payload.content);
        return {
          testId: payload.id,
          status: TestStatus.IDLE,
          timestamp: new Date().toISOString(),
          details: "BEHAVIORAL PAYLOAD: Copied to clipboard. Manual execution required to trigger EDR heuristics."
        };
      }
      
      return {
        testId: payload.id,
        status: TestStatus.ERROR,
        timestamp: new Date().toISOString(),
        details: "Unsupported test type."
      };
    } catch (error: any) {
      const duration = Date.now() - startTime;
      
      // If it's an AbortError and took ~4s, it's a timeout (often an IPS silent drop)
      if (error.name === 'AbortError' || duration > 3500) {
        return {
          testId: payload.id,
          status: TestStatus.BLOCKED,
          timestamp: new Date().toISOString(),
          responseTime: duration,
          details: `SILENT DROP (TIMEOUT): The connection timed out. This usually indicates an IPS or Firewall silently dropping the packets containing the exploit signature.`
        };
      }

      // Likely a TCP Reset or Connection Refused
      return {
        testId: payload.id,
        status: TestStatus.BLOCKED,
        timestamp: new Date().toISOString(),
        responseTime: duration,
        details: `ACTIVE BLOCK (TCP RESET): The security control actively terminated the connection (likely a TCP RST packet). Logic: ${error.message}`
      };
    }
  }
}
