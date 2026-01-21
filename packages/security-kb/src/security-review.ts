/**
 * Security Review Tool - Phase 6A
 * AI Security Review Engine with Blue Team context and explainability
 */

import { Database } from 'sql.js';
import { canonicalizeCWEId } from './utils/normalize.js';

// ============================================================================
// Type Definitions
// ============================================================================

export interface SecurityFinding {
  pattern: string;
  line_number?: number;
  snippet: string;
  cwe: {
    id: string;
    name: string;
    severity: string;
  };
  owasp: string[];
  cvss_context: {
    top_cves: Array<{
      cve_id: string;
      cvss_score: number;
      description: string;
      cisa_kev: boolean;
    }>;
    max_cvss: number;
  };
  threat_context: {
    exploited_in_wild: boolean;
    attack_vector: string;
    impact: string;
    urgency: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  };
  risk_score: number;
  confidence: number;
  confidence_breakdown: {
    pattern: number;
    cwe: number;
    owasp: number;
    cve: number;
  };
  explanation: string;
  remediation?: {
    insecure_example: string;
    secure_example: string;
    explanation: string;
  };
  false_positive_notes?: string;
}

export interface SecurityReviewResult {
  language: string;
  total_lines: number;
  findings: SecurityFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total_risk_score: number;
    average_confidence: number;
  };
  scan_metadata: {
    patterns_checked: number;
    kb_version: string;
    timestamp: string;
  };
}

// ============================================================================
// Security Review Engine
// ============================================================================

export class SecurityReviewEngine {
  constructor(private db: Database) {}

  /**
   * Review code for security vulnerabilities.
   * 
   * This is a deterministic, knowledge-base driven scanner that:
   * 1. Matches code patterns against threat_patterns table
   * 2. Looks up CWE, OWASP, CVE evidence
   * 3. Calculates confidence based on evidence quality
   * 4. Provides Blue Team context (CISA KEV, urgency)
   * 5. Includes remediation guidance
   * 
   * Does NOT use LLM reasoning or invent vulnerabilities.
   */
  async reviewCode(language: string, code: string): Promise<SecurityReviewResult> {
    const lines = code.split('\n');
    const findings: SecurityFinding[] = [];

    // Get all patterns for this language
    const patterns = this.getThreatPatterns(language);

    for (const pattern of patterns) {
      const matches = this.findPatternInCode(pattern.pattern, code, lines);
      
      for (const match of matches) {
        // Check for false positives
        const fpNote = this.checkFalsePositive(match.snippet, pattern.pattern);
        if (fpNote && fpNote.includes('SKIP')) {
          continue; // Don't report obvious false positives
        }

        // Build finding with full intelligence
        const finding = await this.buildFinding(
          pattern,
          match.line_number,
          match.snippet,
          language,
          fpNote
        );

        if (finding) {
          findings.push(finding);
        }
      }
    }

    // Sort by urgency and risk score
    findings.sort((a, b) => {
      const urgencyOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      const urgencyDiff = urgencyOrder[b.threat_context.urgency] - urgencyOrder[a.threat_context.urgency];
      if (urgencyDiff !== 0) return urgencyDiff;
      return b.risk_score - a.risk_score;
    });

    return {
      language,
      total_lines: lines.length,
      findings,
      summary: this.calculateSummary(findings),
      scan_metadata: {
        patterns_checked: patterns.length,
        kb_version: this.getKBVersion(),
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Get threat patterns for a specific language.
   */
  private getThreatPatterns(language: string): Array<{
    pattern: string;
    cwe_id: string;
    risk_score: number;
    confidence: number;
    explanation: string;
  }> {
    const stmt = this.db.prepare(`
      SELECT pattern, cwe_id, risk_score, confidence, explanation
      FROM threat_patterns
      WHERE language = ? OR language = 'any'
      ORDER BY risk_score DESC
    `);
    stmt.bind([language.toLowerCase()]);

    const results: any[] = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      results.push({
        pattern: row.pattern as string,
        cwe_id: row.cwe_id as string,
        risk_score: row.risk_score as number,
        confidence: row.confidence as number,
        explanation: row.explanation as string
      });
    }
    stmt.free();
    return results;
  }

  /**
   * Find pattern occurrences in code.
   * Returns line numbers and snippets.
   * 
   * Patterns from threat_patterns table are already regex-ready.
   */
  private findPatternInCode(
    pattern: string,
    code: string,
    lines: string[]
  ): Array<{ line_number: number; snippet: string }> {
    const matches: Array<{ line_number: number; snippet: string }> = [];

    try {
      // Create new RegExp per line to avoid state issues with 'g' flag
      lines.forEach((line, index) => {
        const regex = new RegExp(pattern, 'i'); // No 'g' flag - fresh regex each time
        if (regex.test(line)) {
          matches.push({
            line_number: index + 1,
            snippet: line.trim()
          });
        }
      });
    } catch (error) {
      // Invalid regex - skip this pattern
      console.warn(`Invalid regex pattern: ${pattern}`, error);
    }

    return matches;
  }

  /**
   * Check for false positive indicators.
   * 
   * Guards against:
   * - Constant strings (no user input)
   * - Comments
   * - Test code patterns
   */
  private checkFalsePositive(snippet: string, pattern: string): string | null {
    // Skip comments
    if (snippet.trim().startsWith('//') || snippet.trim().startsWith('#')) {
      return 'SKIP: Code in comment';
    }

    // Check for constant strings (no variables)
    const hasVariable = /\w+Input|\w+Data|\w+Path|req\.|params\.|query\.|body\.|\$\{|\%\(/i.test(snippet);
    if (!hasVariable && pattern.includes('user')) {
      return 'Context-dependent: No obvious user input detected. Verify data source manually.';
    }

    // Test file indicators
    if (snippet.includes('.test.') || snippet.includes('.spec.')) {
      return 'Context-dependent: Detected in test file. May be intentional for testing.';
    }

    return null;
  }

  /**
   * Build complete finding with KB intelligence.
   */
  private async buildFinding(
    pattern: any,
    lineNumber: number,
    snippet: string,
    language: string,
    fpNote: string | null
  ): Promise<SecurityFinding | null> {
    // Step 1: Get CWE details
    const cweId = canonicalizeCWEId(pattern.cwe_id);
    if (!cweId) return null;

    const cwe = this.getCWE(cweId);
    if (!cwe) return null;

    // Step 2: Get OWASP mappings
    const owasp = this.getOWASP(cweId);

    // Step 3: Get top CVEs
    const cves = this.getCVEs(cweId);

    // Step 4: Get remediation
    const remediation = this.getRemediation(cweId, language);

    // Step 5: Calculate confidence breakdown
    const patternConfidence = pattern.confidence;
    const cweConfidence = 1.0; // CWE exists in KB
    const owaspConfidence = owasp.length > 0 ? 0.9 : 0.5;
    const cveConfidence = cves.length > 0 ? 0.8 : 0.3;

    // Calculate confidence - weighted average (Bayesian-lite approach)
    // Pattern is most important (direct match), then CWE/CVE evidence, then OWASP
    const finalConfidence = (
      patternConfidence * 0.40 +    // Direct pattern match (highest weight)
      cweConfidence * 0.25 +        // CWE weakness existence
      cveConfidence * 0.20 +        // CVE real-world evidence
      owaspConfidence * 0.15        // OWASP Top 10 classification
    );

    // Step 6: Build threat context (Blue Team perspective)
    const threatContext = this.buildThreatContext(cwe, cves);

    // Step 7: Build explanation
    const explanation = this.buildExplanation(pattern, cwe, owasp, cves);

    return {
      pattern: pattern.pattern,
      line_number: lineNumber,
      snippet,
      cwe: {
        id: cweId,
        name: cwe.name,
        severity: cwe.severity
      },
      owasp: owasp.map(o => o.category),
      cvss_context: {
        top_cves: cves.slice(0, 3).map(c => ({
          cve_id: c.cve_id,
          cvss_score: c.cvss_score,
          description: c.description.substring(0, 150) + '...',
          cisa_kev: c.cisa_known_exploited
        })),
        max_cvss: cves.length > 0 ? Math.max(...cves.map(c => c.cvss_score)) : 0
      },
      threat_context: threatContext,
      risk_score: this.calculateRiskScore(pattern, cves),
      confidence: finalConfidence,
      confidence_breakdown: {
        pattern: patternConfidence,
        cwe: cweConfidence,
        owasp: owaspConfidence,
        cve: cveConfidence
      },
      explanation,
      remediation,
      false_positive_notes: fpNote || undefined
    };
  }

  /**
   * Build threat context from Blue Team perspective.
   */
  private buildThreatContext(cwe: any, cves: any[]): SecurityFinding['threat_context'] {
    const hasKEV = cves.some(c => c.cisa_known_exploited);
    const maxCVSS = cves.length > 0 ? Math.max(...cves.map(c => c.cvss_score)) : 0;

    // Determine urgency
    let urgency: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'MEDIUM';
    if (hasKEV) {
      urgency = 'CRITICAL'; // CISA KEV = actively exploited
    } else if (maxCVSS >= 9.0) {
      urgency = 'CRITICAL';
    } else if (maxCVSS >= 7.0) {
      urgency = 'HIGH';
    } else if (maxCVSS >= 4.0) {
      urgency = 'MEDIUM';
    } else {
      urgency = 'LOW';
    }

    // Determine attack vector and impact from CWE severity
    const attackVector = this.inferAttackVector(cwe);
    const impact = this.inferImpact(cwe);

    return {
      exploited_in_wild: hasKEV,
      attack_vector: attackVector,
      impact,
      urgency
    };
  }

  /**
   * Calculate risk score combining pattern risk + CVSS + KEV.
   */
  private calculateRiskScore(pattern: any, cves: any[]): number {
    const patternRisk = pattern.risk_score;
    const maxCVSS = cves.length > 0 
      ? Math.max(...cves.map((c: any) => c.cvss_score))
      : 0;
    const hasKEV = cves.some((c: any) => c.cisa_known_exploited);
    const kevBoost = hasKEV ? 2.0 : 0;
    
    // Weighted combination: pattern (50%) + CVSS (40%) + KEV boost
    const riskScore = Math.min(10, 
      patternRisk * 0.5 + 
      maxCVSS * 0.4 + 
      kevBoost
    );
    
    return Number(riskScore.toFixed(1));
  }

  private inferAttackVector(cwe: any): string {
    const cweId = cwe.cwe_id.toLowerCase();
    if (cweId.includes('79')) return 'Network: Remote attacker via malicious payload in HTTP request';
    if (cweId.includes('89')) return 'Network: Remote attacker via SQL injection in input fields';
    if (cweId.includes('95')) return 'Network: Remote attacker via code injection payload';
    if (cweId.includes('78')) return 'Network/Local: Command injection via crafted input';
    if (cweId.includes('22')) return 'Network/Local: Path traversal via manipulated file paths';
    return 'Network: Remote attacker via malicious input';
  }

  private inferImpact(cwe: any): string {
    const severity = cwe.severity.toLowerCase();
    if (severity === 'critical' || severity === 'high') {
      return 'Code execution, data breach, system compromise';
    } else if (severity === 'medium') {
      return 'Information disclosure, privilege escalation';
    }
    return 'Limited information disclosure';
  }

  /**
   * Build comprehensive explanation.
   */
  private buildExplanation(pattern: any, cwe: any, owasp: any[], cves: any[]): string {
    let explanation = `**Pattern**: ${pattern.pattern}\n\n`;
    explanation += `**Why This Is Risky**: ${pattern.explanation}\n\n`;
    explanation += `**CWE Context**: ${cwe.description}\n\n`;

    if (owasp.length > 0) {
      explanation += `**OWASP Classification**: ${owasp.map(o => `${o.category} - ${o.name}`).join(', ')}\n\n`;
    }

    if (cves.length > 0) {
      const kevCves = cves.filter(c => c.cisa_known_exploited);
      explanation += `**Real-World Evidence**: ${cves.length} documented CVEs with CVSS 4.0+`;
      if (kevCves.length > 0) {
        explanation += ` (${kevCves.length} actively exploited per CISA KEV catalog)`;
      }
      explanation += '\n\n';
    } else {
      explanation += `**Evidence Note**: No documented CVEs found with CVSS 4.0+. This reduces confidence but the pattern is still high-risk based on CWE classification.\n\n`;
    }

    return explanation;
  }

  // ============================================================================
  // KB Query Helpers
  // ============================================================================

  private getCWE(cweId: string): any {
    const stmt = this.db.prepare('SELECT * FROM cwes WHERE cwe_id = ?');
    stmt.bind([cweId]);
    
    let result = null;
    if (stmt.step()) {
      const row = stmt.getAsObject();
      result = {
        cwe_id: row.cwe_id,
        name: row.name,
        description: row.description,
        severity: row.severity
      };
    }
    stmt.free();
    return result;
  }

  private getOWASP(cweId: string): any[] {
    // Fix OWASP Top 10 2021 mapping - XSS (CWE-79) is A03:Injection, not A05
    const owaspOverrides: Record<string, { category: string; name: string }> = {
      'CWE-79': { category: 'A03', name: 'Injection' }, // XSS
      'CWE-89': { category: 'A03', name: 'Injection' }, // SQL Injection
      'CWE-78': { category: 'A03', name: 'Injection' }, // OS Command Injection
      'CWE-77': { category: 'A03', name: 'Injection' }, // Command Injection
      'CWE-94': { category: 'A03', name: 'Injection' }, // Code Injection
    };
    
    if (owaspOverrides[cweId]) {
      return [owaspOverrides[cweId]];
    }
    
    const stmt = this.db.prepare(`
      SELECT DISTINCT o.category, o.name
      FROM owasp_top10 o
      INNER JOIN cwe_owasp_mapping m ON o.category = m.owasp_category
      WHERE m.cwe_id = ?
    `);
    stmt.bind([cweId]);

    const results: any[] = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      results.push({
        category: row.category,
        name: row.name
      });
    }
    stmt.free();
    return results;
  }

  private getCVEs(cweId: string): any[] {
    const stmt = this.db.prepare(`
      SELECT c.cve_id, c.cvss_score, c.description, c.cisa_known_exploited
      FROM cves c
      INNER JOIN cve_cwe_mapping m ON c.cve_id = m.cve_id
      WHERE m.cwe_id = ? AND c.cvss_score >= 4.0
      ORDER BY c.cisa_known_exploited DESC, c.cvss_score DESC
      LIMIT 5
    `);
    stmt.bind([cweId]);

    const results: any[] = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      results.push({
        cve_id: row.cve_id,
        cvss_score: row.cvss_score,
        description: row.description,
        cisa_known_exploited: row.cisa_known_exploited === 1
      });
    }
    stmt.free();
    return results;
  }

  private getRemediation(cweId: string, language: string): SecurityFinding['remediation'] | undefined {
    try {
      const stmt = this.db.prepare(`
        SELECT insecure_example, secure_example, explanation
        FROM cwe_remediation
        WHERE cwe_id = ? AND language = ?
      `);
      stmt.bind([cweId, language.toLowerCase()]);

      let result = undefined;
      if (stmt.step()) {
        const row = stmt.getAsObject();
        result = {
          insecure_example: row.insecure_example as string,
          secure_example: row.secure_example as string,
          explanation: row.explanation as string
        };
      }
      stmt.free();
      return result;
    } catch (error) {
      // Table may not exist - return undefined
      return undefined;
    }
  }

  private getKBVersion(): string {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM cwes');
    stmt.step();
    const cweCount = stmt.getAsObject().count;
    stmt.free();
    return `CWE:${cweCount}/CVE:NVD-2024`;
  }

  // ============================================================================
  // Summary Calculations
  // ============================================================================

  private calculateSummary(findings: SecurityFinding[]) {
    const urgencyCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };

    findings.forEach(f => {
      const urgency = f.threat_context.urgency.toLowerCase();
      urgencyCounts[urgency as keyof typeof urgencyCounts]++;
    });

    const totalRisk = findings.reduce((sum, f) => sum + f.risk_score, 0);
    const avgConfidence = findings.length > 0
      ? findings.reduce((sum, f) => sum + f.confidence, 0) / findings.length
      : 0;

    return {
      ...urgencyCounts,
      total_risk_score: Math.round(totalRisk * 10) / 10,
      average_confidence: Math.round(avgConfidence * 100) / 100
    };
  }
}
