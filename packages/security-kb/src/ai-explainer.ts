/**
 * Phase 7: AI Explanation Assistant
 * 
 * Enhances security findings with AI-generated explanations WITHOUT
 * making vulnerability decisions. The deterministic engine decides;
 * AI only explains.
 * 
 * CRITICAL CONSTRAINTS:
 * - AI MUST NOT decide if code is vulnerable
 * - AI MUST NOT change risk scores or confidence
 * - AI MUST state uncertainty when confidence < 60%
 * - AI MUST add guardrail message when confidence < 40%
 */

import type { SecurityFinding } from './security-review.js';

/**
 * AI-generated explanation for a security finding
 */
export interface AIExplanation {
  /** Human-readable explanation for developers */
  developer_explanation: string;
  
  /** Blue Team / SOC context */
  blue_team_context: {
    /** Business impact of exploitation */
    impact: string;
    /** Attacker's perspective and attack vectors */
    attacker_perspective: string;
    /** Detection indicators */
    detection_indicators: string[];
  };
  
  /** Step-by-step remediation guidance */
  remediation_steps: {
    /** Step number */
    step: number;
    /** Action to take */
    action: string;
    /** Why this step matters */
    rationale: string;
  }[];
  
  /** Secure code example (before/after) */
  code_example: {
    /** Vulnerable code snippet */
    before: string;
    /** Secure code snippet */
    after: string;
    /** Key changes explained */
    changes_explained: string;
  };
  
  /** Confidence disclaimer (required when < 60%) */
  confidence_disclaimer?: string;
  
  /** Guardrail warning (required when < 40%) */
  guardrail_warning?: string;
  
  /** AI model used for generation */
  model_info: {
    name: string;
    version: string;
    timestamp: string;
  };
}

/**
 * Prompt template for AI explanation generation
 * Version: 1.0.0
 * 
 * This template is versioned in code to ensure reproducibility
 * and auditability of AI-generated explanations.
 */
export const AI_EXPLANATION_PROMPT_V1 = {
  version: '1.0.0',
  system_prompt: `You are a security explanation assistant. Your role is to explain existing security findings to developers and security teams.

CRITICAL RULES:
1. You MUST NOT decide if code is vulnerable - that decision has already been made by a deterministic engine
2. You MUST NOT change the risk score or confidence level
3. You MUST explain the finding in clear, actionable terms
4. You MUST provide Blue Team / SOC context for detection and response
5. When confidence < 60%, you MUST state: "Note: This finding has moderate confidence and may benefit from manual review."
6. When confidence < 40%, you MUST add: "⚠️ GUARDRAIL: This finding is heuristic and may require manual review."

Your explanations should be:
- Clear and jargon-free for developers
- Actionable with specific remediation steps
- Include secure code examples
- Provide attacker perspective for Blue Team`,

  user_prompt_template: `Explain the following security finding:

**Finding Metadata:**
- CWE ID: {{cwe_id}}
- CWE Name: {{cwe_name}}
- OWASP Category: {{owasp_category}}
- Risk Score: {{risk_score}}/10
- Confidence: {{confidence}}% ({{confidence_level}})
- Urgency: {{urgency}}

**Code Context:**
Language: {{language}}
{{#if code_snippet}}
Vulnerable Code:
\`\`\`{{language}}
{{code_snippet}}
\`\`\`
{{/if}}

**Pattern Detected:**
{{pattern_explanation}}

**CVE Evidence:**
{{#if cve_references}}
{{cve_references}}
{{else}}
No specific CVE references available. This is a general vulnerability pattern.
{{/if}}

**OWASP Context:**
{{owasp_description}}

Generate a comprehensive explanation with:
1. Developer-friendly explanation (why this matters, what could go wrong)
2. Blue Team context (impact, attacker perspective, detection indicators)
3. Step-by-step remediation (3-5 concrete steps)
4. Secure code example (before/after with changes explained)

Remember: The vulnerability decision is final. Your job is to explain and guide, not to re-assess.`
};

/**
 * Generate AI explanation for a security finding
 * 
 * @param finding - Security finding from deterministic engine
 * @param aiClient - AI client (optional, for testing can be mocked)
 * @returns AI-enhanced explanation
 * 
 * @example
 * ```typescript
 * const finding = {
 *   cwe: { id: 'CWE-79', name: 'XSS' },
 *   pattern: 'innerHTML assignment',
 *   snippet: 'div.innerHTML = userInput'
 * };
 * 
 * const explanation = await explainFindingWithAI(finding);
 * console.log(explanation.developer_explanation);
 * ```
 */
export async function explainFindingWithAI(
  finding: SecurityFinding,
  options?: {
    aiClient?: AIExplainerClient;
    includeCodeExample?: boolean;
  }
): Promise<AIExplanation> {
  // Extract confidence level
  const confidence = finding.confidence;
  const confidencePercent = Math.round(confidence * 100);
  
  // Build prompt with finding metadata
  const prompt = buildPromptFromFinding(finding);
  
  // If no AI client provided, return structured mock (for testing)
  if (!options?.aiClient) {
    return buildMockExplanation(finding, confidencePercent);
  }
  
  // Call AI client
  const rawResponse = await options.aiClient.generateExplanation(prompt);
  
  // Parse and validate AI response
  const explanation = parseAIResponse(rawResponse);
  
  // Apply guardrails based on confidence
  applyConfidenceGuardrails(explanation, confidencePercent);
  
  // Add model metadata
  explanation.model_info = {
    name: options.aiClient.modelName || 'unknown',
    version: AI_EXPLANATION_PROMPT_V1.version,
    timestamp: new Date().toISOString()
  };
  
  return explanation;
}

/**
 * AI client interface for explanation generation
 * Abstracts the actual LLM provider (OpenAI, Anthropic, etc.)
 */
export interface AIExplainerClient {
  modelName: string;
  generateExplanation(prompt: string): Promise<string>;
}

/**
 * Build prompt from finding metadata
 */
function buildPromptFromFinding(finding: SecurityFinding): string {
  const confidenceLevel = getConfidenceLevel(finding.confidence);
  
  // Replace template variables
  let prompt = AI_EXPLANATION_PROMPT_V1.user_prompt_template;
  
  const replacements: Record<string, string> = {
    '{{cwe_id}}': finding.cwe.id,
    '{{cwe_name}}': finding.cwe.name || 'Unknown',
    '{{owasp_category}}': finding.owasp.join(', ') || 'Unknown',
    '{{risk_score}}': finding.risk_score.toString(),
    '{{confidence}}': Math.round(finding.confidence * 100).toString(),
    '{{confidence_level}}': confidenceLevel,
    '{{urgency}}': finding.threat_context.urgency,
    '{{language}}': 'code', // Will be inferred from context
    '{{pattern_explanation}}': finding.explanation,
    '{{owasp_description}}': finding.owasp.join(', ')
  };
  
  // Handle optional fields
  if (finding.snippet) {
    prompt = prompt.replace('{{#if code_snippet}}', '');
    prompt = prompt.replace('{{/if}}', '');
    replacements['{{code_snippet}}'] = finding.snippet;
  } else {
    // Remove code snippet block
    prompt = prompt.replace(/{{#if code_snippet}}[\s\S]*?{{\/if}}/g, 'No code snippet available.');
  }
  
  // Handle CVE references
  if (finding.cvss_context.top_cves && finding.cvss_context.top_cves.length > 0) {
    prompt = prompt.replace('{{#if cve_references}}', '');
    prompt = prompt.replace('{{else}}', '<!-- REMOVED -->');
    prompt = prompt.replace(/<!-- REMOVED -->[\s\S]*?{{\/if}}/g, '');
    const cveList = finding.cvss_context.top_cves
      .map((cve: any) => `- ${cve.cve_id}: ${cve.description} (CVSS: ${cve.cvss_score})`)
      .join('\n');
    replacements['{{cve_references}}'] = cveList;
  } else {
    prompt = prompt.replace(/{{#if cve_references}}[\s\S]*?{{else}}/g, '');
    prompt = prompt.replace('{{/if}}', '');
  }
  
  // Apply all replacements
  for (const [key, value] of Object.entries(replacements)) {
    prompt = prompt.replace(new RegExp(key, 'g'), value);
  }
  
  return AI_EXPLANATION_PROMPT_V1.system_prompt + '\n\n' + prompt;
}

/**
 * Get confidence level label
 */
function getConfidenceLevel(confidence: number): string {
  if (confidence >= 0.90) return 'Very High';
  if (confidence >= 0.75) return 'High';
  if (confidence >= 0.60) return 'Moderate';
  if (confidence >= 0.40) return 'Low';
  return 'Very Low';
}

/**
 * Apply confidence-based guardrails
 */
function applyConfidenceGuardrails(explanation: AIExplanation, confidencePercent: number): void {
  if (confidencePercent < 60) {
    explanation.confidence_disclaimer = 
      `📋 Note: This finding has ${confidencePercent}% confidence and may benefit from manual review to confirm accuracy.`;
  }
  
  if (confidencePercent < 40) {
    explanation.guardrail_warning = 
      `⚠️ GUARDRAIL: This finding is heuristic (${confidencePercent}% confidence) and may require manual review. ` +
      `Pattern-based detection may produce false positives in this confidence range.`;
  }
}

/**
 * Parse AI response into structured format
 * (In real implementation, this would use LLM structured output or JSON parsing)
 */
function parseAIResponse(response: string): AIExplanation {
  // This is a placeholder - real implementation would parse LLM JSON output
  // For now, return structured format
  return {
    developer_explanation: response,
    blue_team_context: {
      impact: 'Extracted from AI response',
      attacker_perspective: 'Extracted from AI response',
      detection_indicators: ['Log analysis', 'WAF alerts']
    },
    remediation_steps: [
      { step: 1, action: 'Extracted from AI', rationale: 'Extracted from AI' }
    ],
    code_example: {
      before: '// Vulnerable code',
      after: '// Secure code',
      changes_explained: 'Extracted from AI'
    },
    model_info: {
      name: 'mock',
      version: '1.0.0',
      timestamp: new Date().toISOString()
    }
  };
}

/**
 * Build mock explanation (for testing without AI client)
 */
function buildMockExplanation(finding: SecurityFinding, confidencePercent: number): AIExplanation {
  const explanation: AIExplanation = {
    developer_explanation: `This code contains a ${finding.cwe.id} vulnerability. ${finding.explanation}`,
    
    blue_team_context: {
      impact: `Risk Score: ${finding.risk_score}/10 - ${finding.threat_context.urgency} priority`,
      attacker_perspective: `Attackers can exploit ${finding.cwe.id} patterns to compromise application security. ${finding.threat_context.attack_vector}`,
      detection_indicators: [
        `Pattern: ${finding.pattern}`,
        `CWE: ${finding.cwe.id} - ${finding.cwe.name}`,
        `OWASP: ${finding.owasp.join(', ')}`
      ]
    },
    
    remediation_steps: finding.remediation ? [
      {
        step: 1,
        action: 'Review the vulnerable code pattern',
        rationale: 'Understand how the vulnerability manifests in your code'
      },
      {
        step: 2,
        action: 'Apply secure coding pattern from remediation guidance',
        rationale: finding.remediation.explanation
      },
      {
        step: 3,
        action: 'Test with security scanning tools',
        rationale: 'Verify the vulnerability is fully mitigated'
      }
    ] : [
      {
        step: 1,
        action: 'Review the flagged code pattern',
        rationale: 'Understand how the vulnerability manifests'
      },
      {
        step: 2,
        action: 'Apply secure coding practices',
        rationale: 'Replace vulnerable pattern with secure alternative'
      },
      {
        step: 3,
        action: 'Test and verify',
        rationale: 'Ensure the vulnerability is fully addressed'
      }
    ],
    
    code_example: {
      before: finding.snippet || '// Vulnerable code pattern',
      after: finding.remediation?.secure_example || '// Apply secure coding practices (see remediation guidance)',
      changes_explained: finding.remediation?.explanation || 'Replace insecure pattern with validated, sanitized, or parameterized approach'
    },
    
    model_info: {
      name: 'mock-explainer',
      version: AI_EXPLANATION_PROMPT_V1.version,
      timestamp: new Date().toISOString()
    }
  };
  
  // Apply guardrails
  applyConfidenceGuardrails(explanation, confidencePercent);
  
  return explanation;
}

/**
 * Format AI explanation for display
 */
export function formatAIExplanation(explanation: AIExplanation): string {
  let output = '\n';
  output += '═'.repeat(80) + '\n';
  output += '🤖 AI EXPLANATION ASSISTANT\n';
  output += '═'.repeat(80) + '\n\n';
  
  // Guardrail warnings (if present)
  if (explanation.guardrail_warning) {
    output += explanation.guardrail_warning + '\n\n';
  }
  if (explanation.confidence_disclaimer) {
    output += explanation.confidence_disclaimer + '\n\n';
  }
  
  // Developer explanation
  output += '📖 Developer Explanation:\n';
  output += '─'.repeat(80) + '\n';
  output += explanation.developer_explanation + '\n\n';
  
  // Blue Team context
  output += '🛡️  Blue Team / SOC Context:\n';
  output += '─'.repeat(80) + '\n';
  output += `Impact: ${explanation.blue_team_context.impact}\n`;
  output += `Attacker Perspective: ${explanation.blue_team_context.attacker_perspective}\n`;
  output += `Detection Indicators:\n`;
  explanation.blue_team_context.detection_indicators.forEach(indicator => {
    output += `  • ${indicator}\n`;
  });
  output += '\n';
  
  // Remediation steps
  output += '🔧 Remediation Steps:\n';
  output += '─'.repeat(80) + '\n';
  explanation.remediation_steps.forEach(step => {
    output += `${step.step}. ${step.action}\n`;
    output += `   → ${step.rationale}\n`;
  });
  output += '\n';
  
  // Code example
  output += '💻 Secure Code Example:\n';
  output += '─'.repeat(80) + '\n';
  output += 'Before (Vulnerable):\n';
  output += explanation.code_example.before + '\n\n';
  output += 'After (Secure):\n';
  output += explanation.code_example.after + '\n\n';
  output += 'Changes Explained:\n';
  output += explanation.code_example.changes_explained + '\n\n';
  
  // Model info
  output += '─'.repeat(80) + '\n';
  output += `Generated by: ${explanation.model_info.name} `;
  output += `(Template v${explanation.model_info.version})\n`;
  output += `Timestamp: ${explanation.model_info.timestamp}\n`;
  output += '═'.repeat(80) + '\n';
  
  return output;
}
