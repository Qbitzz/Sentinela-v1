
import { TestResult, ReportSummary, TestStatus, TestCategory } from "../types";
import { TEST_PAYLOADS } from "../constants";

export class SecurityAnalysisService {
  /**
   * Generates a security assessment report locally without AI.
   */
  async generateReport(results: TestResult[]): Promise<ReportSummary> {
    const total = results.length;
    const blockedCount = results.filter(r => r.status === TestStatus.BLOCKED).length;
    const passedCount = results.filter(r => r.status === TestStatus.PASSED).length;
    
    // Calculate score based on blocked vs total attempted
    const score = total > 0 ? Math.round((blockedCount / total) * 100) : 0;
    
    let overallHealth: 'Critical' | 'Moderate' | 'Good' = 'Critical';
    if (score >= 80) overallHealth = 'Good';
    else if (score >= 50) overallHealth = 'Moderate';

    // Generate technical insights based on results
    let insights = `LOCAL ANALYSIS REPORT\nGenerated: ${new Date().toLocaleString()}\n\n`;
    
    const gaps = results.filter(r => r.status === TestStatus.PASSED);
    if (gaps.length > 0) {
      insights += "VULNERABILITY SUMMARY:\n";
      gaps.forEach(gap => {
        const p = TEST_PAYLOADS.find(x => x.id === gap.testId);
        insights += `- [${p?.targetDevice}] ${p?.name}: The security control failed to inspect and block this payload. `;
        if (p?.category === TestCategory.WAF) insights += "Check WAF signature updates and SSL decryption policies.\n";
        else if (p?.category === TestCategory.EDR) insights += "Verify EDR behavioral heuristics and real-time protection state.\n";
        else insights += "Review firewall IPS signatures for this specific attack vector.\n";
      });
    } else {
      insights += "POSTURE ALERT: No gaps detected in the attempted vectors. Your security controls successfully intercepted all signatures.\n";
    }

    insights += "\nREMEDIATION STEPS:\n";
    insights += "1. Enable Deep Packet Inspection (DPI-SSL) to unmask encrypted threats.\n";
    insights += "2. Transition NGFW from 'Detection Only' to 'Prevention/Block' mode.\n";
    insights += "3. Audit firewall logs for 'TCP Reset' events corresponding to these tests.\n";

    return {
      overallHealth,
      score,
      blockedCount,
      passedCount,
      aiAnalysis: insights
    };
  }
}
