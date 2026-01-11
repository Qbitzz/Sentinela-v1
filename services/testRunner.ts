
import { TestPayload, TestResult, TestStatus } from "../types";

export class TestRunner {
  static async run(payload: TestPayload, targetUrl: string): Promise<TestResult> {
    const startTime = Date.now();
    const baseUrl = targetUrl.replace(/\/$/, "");
    
    try {
      if (payload.type === 'network') {
        // We append the payload as a query parameter or header. 
        // Most NGFWs/WAFs inspect these areas for signatures.
        const url = `${baseUrl}/?sentinela_test_id=${payload.id}&vector=${encodeURIComponent(payload.content)}`;
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const response = await fetch(url, {
          method: 'GET',
          mode: 'no-cors', // Essential for cross-origin testing without server-side CORS config
          headers: { 
            'Cache-Control': 'no-cache',
            'X-Sentinela-Payload': payload.content,
            'User-Agent': 'Sentinela-Security-Scanner/1.0'
          },
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        // With mode 'no-cors', type is 'opaque'. 
        // If the firewall resets the connection, the fetch usually fails and goes to 'catch'.
        // If it returns a response (even opaque), it likely got through unless status is 403.
        return {
          testId: payload.id,
          status: TestStatus.PASSED,
          timestamp: new Date().toISOString(),
          responseTime: Date.now() - startTime,
          details: `Request reached destination. Security control failed to intercept this signature.`
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
          details: "File download initiated. Check your EDR/AV for real-time quarantine events."
        };
      } else if (payload.type === 'script') {
        await navigator.clipboard.writeText(payload.content);
        return {
          testId: payload.id,
          status: TestStatus.IDLE,
          timestamp: new Date().toISOString(),
          details: "Behavioral payload copied to clipboard. Execute this in a Terminal on the target machine to test EDR heuristics."
        };
      }
      
      return {
        testId: payload.id,
        status: TestStatus.ERROR,
        timestamp: new Date().toISOString(),
        details: "Unsupported test type."
      };
    } catch (error: any) {
      // In web-based security testing, a 'TypeError: Failed to fetch' or AbortError 
      // is the standard signal that a Network Firewall (NGFW) has dropped the packet or sent a TCP Reset.
      return {
        testId: payload.id,
        status: TestStatus.BLOCKED,
        timestamp: new Date().toISOString(),
        responseTime: Date.now() - startTime,
        details: `CONNECTION TERMINATED: ${error.name}. The payload was likely dropped or rejected by the NGFW/IPS engine.`
      };
    }
  }
}
