
import { TestPayload, TestResult, TestStatus } from "../types";

export class TestRunner {
  static async run(payload: TestPayload): Promise<TestResult> {
    const startTime = Date.now();
    
    try {
      if (payload.type === 'network') {
        // Simulate a real request to the current URL with the payload as a parameter
        // Most WAFs/NGFWs will inspect parameters
        const response = await fetch(`${window.location.origin}/?test=${encodeURIComponent(payload.content)}`, {
          method: 'GET',
          // We don't want caching to interfere
          headers: { 'Cache-Control': 'no-cache' }
        });

        // If the request is blocked, it's a "success" for the firewall
        if (response.status === 403 || response.status === 406 || response.status === 0) {
          return {
            testId: payload.id,
            status: TestStatus.BLOCKED,
            timestamp: new Date().toISOString(),
            responseTime: Date.now() - startTime,
            details: `Server returned status ${response.status}. Payload effectively blocked.`
          };
        } else {
          return {
            testId: payload.id,
            status: TestStatus.PASSED, // Threat got through!
            timestamp: new Date().toISOString(),
            responseTime: Date.now() - startTime,
            details: `Server returned ${response.status}. WAF/NGFW failed to intercept.`
          };
        }
      } else if (payload.type === 'download') {
        // Trigger a download. The user's EDR/AV should flag this if it's scanning downloads.
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
          status: TestStatus.PASSED, // We assume "Passed" until the user confirms detection
          timestamp: new Date().toISOString(),
          details: "Download triggered. Check endpoint logs for quarantine events."
        };
      } else if (payload.type === 'script') {
        // For script-based, we'll "copy to clipboard" and ask the user to run it
        // Or simulate a specific behavior that EDR monitors (e.g., rapid file access)
        await navigator.clipboard.writeText(payload.content);
        return {
          testId: payload.id,
          status: TestStatus.IDLE,
          timestamp: new Date().toISOString(),
          details: "Script payload copied to clipboard. Execute in a safe VM to test EDR."
        };
      }
      
      return {
        testId: payload.id,
        status: TestStatus.ERROR,
        timestamp: new Date().toISOString(),
        details: "Unsupported test type."
      };
    } catch (error: any) {
      // Fetch errors (like CORS or Connection Refused) are often signs of network-level blocking
      return {
        testId: payload.id,
        status: TestStatus.BLOCKED,
        timestamp: new Date().toISOString(),
        responseTime: Date.now() - startTime,
        details: `Connection error: ${error.message}. Likely blocked by network firewall.`
      };
    }
  }
}
