
import { TestResult, ReportSummary, TestStatus, TestCategory } from "../types";
import { TEST_PAYLOADS } from "../constants";

export class SecurityAnalysisService {
  /**
   * Generates a security assessment report locally.
   */
  async generateReport(results: TestResult[]): Promise<ReportSummary> {
    const total = results.length;
    const blockedCount = results.filter(r => r.status === TestStatus.BLOCKED).length;
    const passedCount = results.filter(r => r.status === TestStatus.PASSED).length;
    
    const score = total > 0 ? Math.round((blockedCount / total) * 100) : 0;
    
    let overallHealth: 'Critical' | 'Moderate' | 'Good' = 'Critical';
    if (score >= 80) overallHealth = 'Good';
    else if (score >= 50) overallHealth = 'Moderate';

    let insights = `POSTURE ASSESSMENT REPORT\nGenerated: ${new Date().toLocaleString()}\n\n`;
    
    const gaps = results.filter(r => r.status === TestStatus.PASSED);
    if (gaps.length > 0) {
      insights += "CRITICAL EXPOSURES FOUND:\n";
      gaps.forEach(gap => {
        const p = TEST_PAYLOADS.find(x => x.id === gap.testId);
        insights += `[!] ${p?.category} Bypass: ${p?.name}\n`;
        if (gap.proof) {
          insights += `    - EXPLOIT PROOF: "${gap.proof}"\n`;
        }
        insights += `    - IMPACT: Successful payload delivery to endpoint. Firewall/IPS ignored this signature.\n\n`;
      });
    } else if (results.length > 0) {
      insights += "POSTURE ALERT: All attempted vectors were successfully intercepted by your perimeter security controls.\n";
    } else {
      insights += "No test results available for analysis.\n";
    }

    insights += "TECHNICAL RECOMMENDATIONS:\n";
    insights += "1. Inspect firewall logs for specific vector signatures that bypassed the filter.\n";
    insights += "2. Verify if the target application handles input sanitization to provide 'Defense in Depth'.\n";
    insights += "3. Ensure that your NGFW has SSL/TLS Decryption enabled for the target IP.\n";

    return {
      overallHealth,
      score,
      blockedCount,
      passedCount,
      aiAnalysis: insights
    };
  }
}
