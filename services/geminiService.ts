
import { GoogleGenAI, Type } from "@google/genai";
import { TestResult, ReportSummary } from "../types";
import { TEST_PAYLOADS } from "../constants";

export class SecurityAnalysisService {
  /**
   * Generates a security assessment report using Gemini AI.
   * Following @google/genai guidelines, we instantiate GoogleGenAI immediately before the call.
   */
  async generateReport(results: TestResult[]): Promise<ReportSummary> {
    // Create a new GoogleGenAI instance right before making an API call to ensure it always uses the most up-to-date API key.
    const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
    
    const testDetails = results.map(r => {
      const payload = TEST_PAYLOADS.find(p => p.id === r.testId);
      return {
        name: payload?.name,
        category: payload?.category,
        status: r.status,
        details: r.details
      };
    });

    const prompt = `
      You are a Senior Security Engineer. Analyze the following NGFW/EDR test results and provide a professional assessment.
      
      Results: ${JSON.stringify(testDetails, null, 2)}
      
      Tasks:
      1. Determine overall security health (Good, Moderate, Critical).
      2. Calculate a security score (0-100).
      3. Provide a detailed summary of vulnerabilities if tests passed (indicating security failure).
      4. Suggest remediation steps for the SOC team.
    `;

    try {
      const response = await ai.models.generateContent({
        model: "gemini-3-pro-preview",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              overallHealth: { type: Type.STRING },
              score: { type: Type.NUMBER },
              blockedCount: { type: Type.NUMBER },
              passedCount: { type: Type.NUMBER },
              aiAnalysis: { type: Type.STRING }
            },
            required: ["overallHealth", "score", "blockedCount", "passedCount", "aiAnalysis"]
          }
        }
      });

      // The response.text property directly returns the extracted string output.
      const jsonStr = response.text.trim();
      return JSON.parse(jsonStr || '{}') as ReportSummary;
    } catch (error) {
      console.error("Gemini Analysis Error:", error);
      // Fallback
      return {
        overallHealth: 'Moderate',
        score: 50,
        blockedCount: results.filter(r => r.status === 'blocked').length,
        passedCount: results.filter(r => r.status === 'passed').length,
        aiAnalysis: "Error generating AI analysis. Please check your results manually."
      };
    }
  }
}
