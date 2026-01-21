/**
 * Security Code Review Tool
 * 
 * Performs automated security analysis of pseudocode and implementation plans.
 * Identifies common security vulnerabilities, insecure patterns, and provides remediation guidance.
 */

import type { MCPToolResult } from '@mcp-ssdlc/core';
import { createSecurityKB } from '@mcp-ssdlc/security-kb';

export interface CodeReviewInput {
  code_snippet: string;
  language: string;
  context?: string; // What this code does
  severity_threshold?: 'low' | 'medium' | 'high' | 'critical';
}

export interface SecurityFinding {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  cwe_id?: string;
  owasp_category?: string;
  title: string;
  description: string;
  line_number?: number;
  code_snippet: string;
  remediation: string;
  references: string[];
}

export interface CodeReviewOutput {
  summary: {
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  findings: SecurityFinding[];
  secure_patterns_recommended: Array<{
    pattern_name: string;
    description: string;
    example_code: string;
  }>;
  compliance_notes: string[];
  overall_risk_score: number; // 0-100
  recommendations: string[];
}

export async function securityReviewCode(args: CodeReviewInput): Promise<MCPToolResult> {
  try {
    const findings: SecurityFinding[] = [];
    let findingIdCounter = 1;

    // Initialize security KB for pattern matching
    const securityKB = await createSecurityKB();

    // Security analysis rules
    const securityRules = getSecurityRules(args.language);

    // Analyze code against security rules
    for (const rule of securityRules) {
      const matches = rule.pattern.test(args.code_snippet);
      if (matches) {
        // Get CWE information if available
        let cweDetails = null;
        if (rule.cwe_id) {
          try {
            cweDetails = await securityKB.getCWE(rule.cwe_id);
          } catch (err) {
            // CWE not found in DB
          }
        }

        findings.push({
          id: `SEC-${findingIdCounter++}`,
          severity: rule.severity,
          category: rule.category,
          cwe_id: rule.cwe_id,
          owasp_category: rule.owasp_category,
          title: rule.title,
          description: cweDetails?.description || rule.description,
          code_snippet: extractCodeSnippet(args.code_snippet, rule.pattern),
          remediation: rule.remediation,
          references: [
            ...(cweDetails ? [`CWE-${rule.cwe_id}: https://cwe.mitre.org/data/definitions/${rule.cwe_id}.html`] : []),
            ...rule.references
          ]
        });
      }
    }

    // Sort findings by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    // Filter by severity threshold if specified
    const filteredFindings = args.severity_threshold
      ? findings.filter(f => severityOrder[f.severity] <= severityOrder[args.severity_threshold!])
      : findings;

    // Count by severity
    const summary = {
      total_findings: filteredFindings.length,
      critical: filteredFindings.filter(f => f.severity === 'critical').length,
      high: filteredFindings.filter(f => f.severity === 'high').length,
      medium: filteredFindings.filter(f => f.severity === 'medium').length,
      low: filteredFindings.filter(f => f.severity === 'low').length
    };

    // Get recommended secure patterns from KB
    // TODO: Implement getSecurePatterns in SecurityKnowledgeBase
    const securePatterns: Array<{ name: string; description: string; code_example: string }> = [];
    const recommendedPatterns = securePatterns.map((p: { name: string; description: string; code_example: string }) => ({
      pattern_name: p.name,
      description: p.description,
      example_code: p.code_example
    }));

    // Calculate overall risk score
    const riskScore = calculateRiskScore(summary);

    // Generate recommendations
    const recommendations = generateRecommendations(filteredFindings, args.language);

    // Compliance notes
    const complianceNotes = [
      'Review findings for OWASP Top 10 compliance',
      'Ensure all critical/high findings are addressed before production',
      'Consider penetration testing for complex security scenarios',
      'Document security decisions and accepted risks',
      'Implement security logging and monitoring'
    ];

    await securityKB.close();

    const output: CodeReviewOutput = {
      summary,
      findings: filteredFindings,
      secure_patterns_recommended: recommendedPatterns.slice(0, 3), // Top 3
      compliance_notes: complianceNotes,
      overall_risk_score: riskScore,
      recommendations
    };

    // Generate markdown report
    const report = generateSecurityReviewReport(output, args.code_snippet);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(output, null, 2)
        },
        {
          type: 'text',
          text: report
        }
      ]
    };

  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ error: String(error) }, null, 2)
        }
      ],
      isError: true
    };
  }
}

// Security analysis rules by language
function getSecurityRules(language: string): Array<{
  pattern: RegExp;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  cwe_id?: string;
  owasp_category?: string;
  title: string;
  description: string;
  remediation: string;
  references: string[];
}> {
  const commonRules = [
    {
      pattern: /(password|secret|api[_-]?key|token|credential).*=.*["'].*["']/i,
      severity: 'critical' as const,
      category: 'Hardcoded Secrets',
      cwe_id: 'CWE-798',
      owasp_category: 'A02:2021 – Cryptographic Failures',
      title: 'Hardcoded Secrets Detected',
      description: 'Sensitive credentials are hardcoded in the source code',
      remediation: 'Use environment variables or secure vault services (HashiCorp Vault, AWS Secrets Manager)',
      references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/']
    },
    {
      pattern: /eval\s*\(|exec\s*\(/i,
      severity: 'critical' as const,
      category: 'Code Injection',
      cwe_id: 'CWE-94',
      owasp_category: 'A03:2021 – Injection',
      title: 'Dangerous Code Execution Function',
      description: 'Use of eval() or exec() can lead to arbitrary code execution',
      remediation: 'Avoid eval/exec. Use safe alternatives like JSON.parse() for data parsing',
      references: ['https://owasp.org/www-community/attacks/Code_Injection']
    },
    {
      pattern: /SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\+|QUERY.*\+|query.*\+/i,
      severity: 'critical' as const,
      category: 'SQL Injection',
      cwe_id: 'CWE-89',
      owasp_category: 'A03:2021 – Injection',
      title: 'Potential SQL Injection Vulnerability',
      description: 'SQL query appears to use string concatenation instead of parameterized queries',
      remediation: 'Use parameterized queries (prepared statements) or ORM frameworks',
      references: ['https://owasp.org/www-community/attacks/SQL_Injection']
    },
    {
      pattern: /md5\s*\(|sha1\s*\(/i,
      severity: 'high' as const,
      category: 'Weak Cryptography',
      cwe_id: 'CWE-327',
      owasp_category: 'A02:2021 – Cryptographic Failures',
      title: 'Weak Cryptographic Hash Function',
      description: 'MD5 and SHA1 are cryptographically broken',
      remediation: 'Use SHA-256, SHA-3, or bcrypt/argon2 for password hashing',
      references: ['https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure']
    },
    {
      pattern: /random\s*\(|Math\.random\s*\(/i,
      severity: 'medium' as const,
      category: 'Weak Random Number Generator',
      cwe_id: 'CWE-338',
      owasp_category: 'A02:2021 – Cryptographic Failures',
      title: 'Insecure Random Number Generation',
      description: 'Standard random() is not cryptographically secure',
      remediation: 'Use cryptographically secure random generators (secrets module in Python, crypto.randomBytes in Node.js)',
      references: ['https://cwe.mitre.org/data/definitions/338.html']
    },
    {
      pattern: /innerHTML|outerHTML|document\.write/i,
      severity: 'high' as const,
      category: 'Cross-Site Scripting (XSS)',
      cwe_id: 'CWE-79',
      owasp_category: 'A03:2021 – Injection',
      title: 'Potential XSS Vulnerability',
      description: 'Direct DOM manipulation without sanitization can lead to XSS',
      remediation: 'Use textContent, innerText, or proper sanitization libraries (DOMPurify)',
      references: ['https://owasp.org/www-community/attacks/xss/']
    },
    {
      pattern: /cors.*\*|Access-Control-Allow-Origin.*\*/i,
      severity: 'medium' as const,
      category: 'Insecure CORS Configuration',
      cwe_id: 'CWE-942',
      owasp_category: 'A05:2021 – Security Misconfiguration',
      title: 'Overly Permissive CORS Policy',
      description: 'Allowing all origins (*) in CORS can expose APIs to unauthorized access',
      remediation: 'Specify explicit allowed origins or use a whitelist',
      references: ['https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny']
    },
    {
      pattern: /try\s*\{[^}]*\}\s*catch\s*\([^)]*\)\s*\{\s*\}/i,
      severity: 'low' as const,
      category: 'Error Handling',
      cwe_id: 'CWE-390',
      owasp_category: 'A09:2021 – Security Logging and Monitoring Failures',
      title: 'Empty Catch Block',
      description: 'Silently catching exceptions can hide errors and security issues',
      remediation: 'Log errors appropriately and handle them gracefully',
      references: ['https://cwe.mitre.org/data/definitions/390.html']
    }
  ];

  // Language-specific rules
  if (language.toLowerCase() === 'python') {
    commonRules.push({
      pattern: /pickle\.loads?\s*\(/i,
      severity: 'critical' as const,
      category: 'Deserialization',
      cwe_id: 'CWE-502',
      owasp_category: 'A08:2021 – Software and Data Integrity Failures',
      title: 'Insecure Deserialization',
      description: 'pickle.loads() can execute arbitrary code from untrusted data',
      remediation: 'Use JSON or other safe serialization formats for untrusted data',
      references: ['https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data']
    });
  }

  if (language.toLowerCase() === 'javascript' || language.toLowerCase() === 'typescript') {
    commonRules.push({
      pattern: /dangerouslySetInnerHTML/i,
      severity: 'high' as const,
      category: 'XSS',
      cwe_id: 'CWE-79',
      owasp_category: 'A03:2021 – Injection',
      title: 'Dangerous React Property',
      description: 'dangerouslySetInnerHTML can introduce XSS if not properly sanitized',
      remediation: 'Sanitize HTML with DOMPurify before using dangerouslySetInnerHTML',
      references: ['https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html']
    });
  }

  return commonRules;
}

function extractCodeSnippet(code: string, pattern: RegExp): string {
  const match = code.match(pattern);
  if (match) {
    const lines = code.split('\n');
    const matchLine = lines.find(line => pattern.test(line));
    return matchLine?.trim() || match[0];
  }
  return '';
}

function calculateRiskScore(summary: CodeReviewOutput['summary']): number {
  // Weighted risk calculation
  const weights = {
    critical: 40,
    high: 20,
    medium: 5,
    low: 1
  };

  const score = 
    summary.critical * weights.critical +
    summary.high * weights.high +
    summary.medium * weights.medium +
    summary.low * weights.low;

  // Normalize to 0-100
  return Math.min(100, score);
}

function generateRecommendations(findings: SecurityFinding[], language: string): string[] {
  const recommendations: string[] = [];

  if (findings.some(f => f.category === 'Hardcoded Secrets')) {
    recommendations.push('Implement secret management using environment variables or vault services');
  }

  if (findings.some(f => f.category.includes('Injection'))) {
    recommendations.push('Use parameterized queries and input validation for all user inputs');
  }

  if (findings.some(f => f.category === 'Weak Cryptography')) {
    recommendations.push('Upgrade to modern cryptographic algorithms (SHA-256+, bcrypt/argon2)');
  }

  if (findings.some(f => f.category === 'XSS')) {
    recommendations.push('Implement Content Security Policy (CSP) headers');
    recommendations.push('Sanitize all user-generated content before rendering');
  }

  if (findings.some(f => f.owasp_category?.includes('A02:2021'))) {
    recommendations.push('Enable TLS 1.3 for all data in transit');
    recommendations.push('Encrypt sensitive data at rest');
  }

  // General recommendations
  recommendations.push('Conduct regular security code reviews');
  recommendations.push('Integrate SAST/DAST tools in CI/CD pipeline');
  recommendations.push('Implement security logging and monitoring');

  return [...new Set(recommendations)]; // Remove duplicates
}

function generateSecurityReviewReport(output: CodeReviewOutput, codeSnippet: string): string {
  const severityEmoji = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🟢'
  };

  return `
# Security Code Review Report

## Summary

| Severity | Count |
|----------|-------|
| ${severityEmoji.critical} Critical | ${output.summary.critical} |
| ${severityEmoji.high} High | ${output.summary.high} |
| ${severityEmoji.medium} Medium | ${output.summary.medium} |
| ${severityEmoji.low} Low | ${output.summary.low} |
| **Total** | **${output.summary.total_findings}** |

**Overall Risk Score**: ${output.overall_risk_score}/100 ${output.overall_risk_score > 70 ? '🔴 HIGH RISK' : output.overall_risk_score > 40 ? '🟡 MEDIUM RISK' : '🟢 LOW RISK'}

## Findings

${output.findings.map((finding, idx) => `
### ${idx + 1}. ${severityEmoji[finding.severity]} ${finding.title} (${finding.severity.toUpperCase()})

**ID**: ${finding.id}
**Category**: ${finding.category}
${finding.cwe_id ? `**CWE**: ${finding.cwe_id}` : ''}
${finding.owasp_category ? `**OWASP**: ${finding.owasp_category}` : ''}

**Description**: ${finding.description}

**Affected Code**:
\`\`\`
${finding.code_snippet}
\`\`\`

**Remediation**: ${finding.remediation}

**References**:
${finding.references.map(ref => `- ${ref}`).join('\n')}
`).join('\n---\n')}

${output.findings.length === 0 ? '✅ No security issues detected!' : ''}

## Recommended Secure Patterns

${output.secure_patterns_recommended.map(pattern => `
### ${pattern.pattern_name}
${pattern.description}

\`\`\`
${pattern.example_code}
\`\`\`
`).join('\n')}

## Recommendations

${output.recommendations.map((rec, idx) => `${idx + 1}. ${rec}`).join('\n')}

## Compliance Notes

${output.compliance_notes.map(note => `- ${note}`).join('\n')}

---
*Generated by MCP SSDLC Security Toolkit - Security Code Review Tool*
`;
}
