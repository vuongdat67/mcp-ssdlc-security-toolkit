/**
 * Security Intelligence Layer - Query API with Reasoning
 * Phase 5: Intelligent queries with confidence propagation
 */

import { Database } from 'sql.js';
import { canonicalizeCWEId, canonicalizeCVEId } from './utils/normalize.js';

// ============================================================================
// Type Definitions
// ============================================================================

export interface CWEDetail {
  cwe_id: string;
  name: string;
  description: string;
  extended_description?: string;
  severity: string;
  likelihood: string;
  mitigations: Array<{
    phase: string;
    description: string;
    effectiveness?: string;
  }>;
  related_cwes: string[];
}

export interface CVEDetail {
  cve_id: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  cvss_score: number;
  cvss_vector?: string;
  published_date: string;
  last_modified: string;
  affected_technologies: string[];
  references: string[];
  cisa_known_exploited: boolean;
}

export interface OWASPCategory {
  category: string;
  name: string;
  description: string;
  related_cwes: string[];
  prevention_strategies: string[];
}

export interface ThreatExplanation {
  pattern: string;
  language: string;
  category: string;
  cwe: CWEDetail[];
  owasp: OWASPCategory[];
  top_cves: CVEDetail[];
  risk_score: number;
  confidence: number;
  explanation: string;
  reasoning_chain: ReasoningStep[];
}

export interface ReasoningStep {
  level: 'pattern' | 'cwe' | 'owasp' | 'cve';
  item: string;
  confidence: number;
  description: string;
}

export interface QueryOptions {
  limit?: number;
  minSeverity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  minCVSS?: number;
  cisaKEVOnly?: boolean;
}

// ============================================================================
// Security Intelligence API
// ============================================================================

export class SecurityIntelligence {
  constructor(private db: Database) {}

  // -------------------------------------------------------------------------
  // Core Queries
  // -------------------------------------------------------------------------

  /**
   * Get detailed CWE information.
   * Canonicalizes input ID to ensure consistent lookups (e.g., "79" → "CWE-79").
   */
  getCWE(cweId: string): CWEDetail | null {
    // Canonicalize CWE ID to ensure consistent format
    const normalizedId = canonicalizeCWEId(cweId);
    if (!normalizedId) {
      console.warn(`[Intelligence] Invalid CWE ID: ${cweId}`);
      return null;
    }

    const stmt = this.db.prepare(`
      SELECT cwe_id, name, description, extended_description, severity, likelihood, 
             mitigation_json, related_cwes_json
      FROM cwes
      WHERE cwe_id = ?
    `);
    stmt.bind([normalizedId]);

    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();

      return {
        cwe_id: row.cwe_id as string,
        name: row.name as string,
        description: row.description as string,
        extended_description: row.extended_description as string | undefined,
        severity: row.severity as string,
        likelihood: row.likelihood as string,
        mitigations: row.mitigation_json ? JSON.parse(row.mitigation_json as string) : [],
        related_cwes: row.related_cwes_json ? JSON.parse(row.related_cwes_json as string) : []
      };
    }

    stmt.free();
    return null;
  }

  /**
   * Query CVEs by CWE ID with filters.
   * Canonicalizes CWE ID for consistent queries.
   */
  queryCVEsByCWE(cweId: string, options: QueryOptions = {}): CVEDetail[] {
    // Canonicalize CWE ID
    const normalizedCweId = canonicalizeCWEId(cweId);
    if (!normalizedCweId) {
      console.warn(`[Intelligence] Invalid CWE ID: ${cweId}`);
      return [];
    }

    const {
      limit = 10,
      minSeverity,
      minCVSS = 0,
      cisaKEVOnly = false
    } = options;

    // Build WHERE clause
    const conditions = ['m.cwe_id = ?'];
    const params: any[] = [normalizedCweId];

    if (minSeverity) {
      const severityMap = { 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4 };
      const severityLevel = severityMap[minSeverity];
      conditions.push(`(
        CASE c.severity
          WHEN 'CRITICAL' THEN 4
          WHEN 'HIGH' THEN 3
          WHEN 'MEDIUM' THEN 2
          WHEN 'LOW' THEN 1
          ELSE 0
        END
      ) >= ?`);
      params.push(severityLevel);
    }

    if (minCVSS > 0) {
      conditions.push('c.cvss_score >= ?');
      params.push(minCVSS);
    }

    if (cisaKEVOnly) {
      conditions.push('c.cisa_known_exploited = 1');
    }

    const sql = `
      SELECT DISTINCT c.cve_id, c.description, c.severity, c.cvss_score, c.cvss_vector,
             c.published_date, c.last_modified, c.affected_technologies_json,
             c.references_json, c.cisa_known_exploited
      FROM cves c
      INNER JOIN cve_cwe_mapping m ON c.cve_id = m.cve_id
      WHERE ${conditions.join(' AND ')}
      ORDER BY c.cvss_score DESC, c.cisa_known_exploited DESC
      LIMIT ?
    `;
    params.push(limit);

    const stmt = this.db.prepare(sql);
    stmt.bind(params);

    const results: CVEDetail[] = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      results.push({
        cve_id: row.cve_id as string,
        description: row.description as string,
        severity: row.severity as any,
        cvss_score: row.cvss_score as number,
        cvss_vector: row.cvss_vector as string | undefined,
        published_date: row.published_date as string,
        last_modified: row.last_modified as string,
        affected_technologies: row.affected_technologies_json ? JSON.parse(row.affected_technologies_json as string) : [],
        references: row.references_json ? JSON.parse(row.references_json as string) : [],
        cisa_known_exploited: (row.cisa_known_exploited as number) === 1
      });
    }

    stmt.free();
    return results;
  }

  /**
   * Get OWASP category by CWE ID.
   * Canonicalizes CWE ID for consistent queries.
   */
  getOWASPByCWE(cweId: string): OWASPCategory[] {
    // Canonicalize CWE ID
    const normalizedCweId = canonicalizeCWEId(cweId);
    if (!normalizedCweId) {
      console.warn(`[Intelligence] Invalid CWE ID: ${cweId}`);
      return [];
    }

    const stmt = this.db.prepare(`
      SELECT DISTINCT o.category, o.name, o.description, o.related_cwes_json, o.prevention_strategies_json
      FROM owasp_top10 o
      INNER JOIN cwe_owasp_mapping m ON o.category = m.owasp_category
      WHERE m.cwe_id = ?
      ORDER BY o.category
    `);
    stmt.bind([normalizedCweId]);

    const results: OWASPCategory[] = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      results.push({
        category: row.category as string,
        name: row.name as string,
        description: row.description as string,
        related_cwes: row.related_cwes_json ? JSON.parse(row.related_cwes_json as string) : [],
        prevention_strategies: row.prevention_strategies_json ? JSON.parse(row.prevention_strategies_json as string) : []
      });
    }

    stmt.free();
    return results;
  }

  // -------------------------------------------------------------------------
  // Threat Intelligence (Pattern → Risk Explanation)
  // -------------------------------------------------------------------------

  /**
   * Explain threat from code pattern with full reasoning chain.
   * This is the core intelligence feature.
   */
  explainThreat(pattern: string, language: string): ThreatExplanation | null {
    // Step 1: Find matching threat pattern
    const patternStmt = this.db.prepare(`
      SELECT pattern, language, category, cwe_id, risk_score, confidence, explanation
      FROM threat_patterns
      WHERE pattern = ? AND language = ?
      LIMIT 1
    `);
    patternStmt.bind([pattern, language]);

    if (!patternStmt.step()) {
      patternStmt.free();
      return null;
    }

    const patternRow = patternStmt.getAsObject();
    const patternConfidence = patternRow.confidence as number;
    patternStmt.free();

    // Step 2: Get CWE details
    const cweId = patternRow.cwe_id as string;
    const cwe = this.getCWE(cweId);
    if (!cwe) return null;

    const cweConfidence = 1.0; // CWE mapping is definitive

    // Step 3: Get OWASP mappings
    const owasp = this.getOWASPByCWE(cweId);
    // Confidence: High if mapped (0.9), Medium if not mapped but CWE exists (0.5)
    const owaspConfidence = owasp.length > 0 ? 0.9 : 0.5;

    // Step 4: Get top CVEs
    const cves = this.queryCVEsByCWE(cweId, { limit: 5, minCVSS: 4.0 });
    // CRITICAL: Do not artificially inflate confidence when CVE evidence is missing
    // If no CVEs found, this significantly lowers final confidence (realistic)
    const cveConfidence = cves.length > 0 ? 0.8 : 0.3;

    // Step 5: Calculate final confidence (minimum along chain - conservative approach)
    // This ensures we don't overstate certainty when evidence is weak
    const finalConfidence = Math.min(
      patternConfidence,
      cweConfidence,
      owaspConfidence,
      cveConfidence  // Low CVE confidence propagates through chain
    );

    // Step 6: Build reasoning chain with per-step confidence
    // This provides explainability: users can see where confidence drops
    const reasoningChain: ReasoningStep[] = [
      {
        level: 'pattern',
        item: pattern,
        confidence: patternConfidence,
        description: `Code pattern detected: ${pattern} in ${language}`
      },
      {
        level: 'cwe',
        item: cweId,
        confidence: cweConfidence,
        description: `Maps to ${cweId}: ${cwe.name} (${cwe.severity} severity)`
      }
    ];

    if (owasp.length > 0) {
      reasoningChain.push({
        level: 'owasp',
        item: owasp[0].category,
        confidence: owaspConfidence,
        description: `Related to OWASP ${owasp[0].category}: ${owasp[0].name}`
      });
    } else {
      // Explicitly note when OWASP mapping is missing
      reasoningChain.push({
        level: 'owasp',
        item: 'No OWASP mapping',
        confidence: owaspConfidence,
        description: `CWE not mapped to OWASP Top 10 2025 (reduces confidence)`
      });
    }

    if (cves.length > 0) {
      const cisaCount = cves.filter(c => c.cisa_known_exploited).length;
      reasoningChain.push({
        level: 'cve',
        item: `${cves.length} CVEs`,
        confidence: cveConfidence,
        description: `Found ${cves.length} related CVEs${cisaCount > 0 ? ` (${cisaCount} CISA Known Exploited)` : ''}`
      });
    } else {
      // Explicitly note when CVE evidence is missing
      reasoningChain.push({
        level: 'cve',
        item: 'No CVEs found',
        confidence: cveConfidence,
        description: `No real-world CVEs found with CVSS 4.0+ (significantly reduces confidence)`
      });
    }

    // Step 7: Generate comprehensive explanation
    const explanation = this.generateExplanation(
      pattern,
      language,
      cwe,
      owasp,
      cves,
      patternRow.explanation as string
    );

    return {
      pattern,
      language,
      category: patternRow.category as string,
      cwe: [cwe],
      owasp,
      top_cves: cves,
      risk_score: patternRow.risk_score as number,
      confidence: finalConfidence,
      explanation,
      reasoning_chain: reasoningChain
    };
  }

  /**
   * Generate comprehensive threat explanation.
   */
  private generateExplanation(
    pattern: string,
    language: string,
    cwe: CWEDetail,
    owasp: OWASPCategory[],
    cves: CVEDetail[],
    baseExplanation: string
  ): string {
    let explanation = `${baseExplanation}\n\n`;

    explanation += `**CWE Context**: This pattern relates to ${cwe.cwe_id} (${cwe.name}), `;
    explanation += `a ${cwe.severity.toLowerCase()} severity weakness. ${cwe.description}\n\n`;

    if (owasp.length > 0) {
      explanation += `**OWASP Context**: This weakness is part of OWASP ${owasp[0].category} (${owasp[0].name}), `;
      explanation += `one of the top web application security risks.\n\n`;
    }

    if (cves.length > 0) {
      const cisaCount = cves.filter(c => c.cisa_known_exploited).length;
      explanation += `**Real-World Impact**: There are ${cves.length} documented CVEs related to this weakness. `;
      
      if (cisaCount > 0) {
        explanation += `${cisaCount} of these are CISA Known Exploited Vulnerabilities, `;
        explanation += `meaning they are actively exploited in the wild. `;
      }

      const highSeverityCVEs = cves.filter(c => c.severity === 'CRITICAL' || c.severity === 'HIGH');
      if (highSeverityCVEs.length > 0) {
        explanation += `${highSeverityCVEs.length} have HIGH or CRITICAL severity (CVSS ${highSeverityCVEs[0].cvss_score}+).`;
      }
    }

    return explanation;
  }

  // -------------------------------------------------------------------------
  // Risk Scoring
  // -------------------------------------------------------------------------

  /**
   * Calculate risk score for a CWE based on CVEs and OWASP mapping.
   */
  calculateRiskScore(cweId: string): number {
    const cve = this.queryCVEsByCWE(cweId, { limit: 10 });
    if (cve.length === 0) return 5.0; // Base score if no CVEs

    // Calculate average CVSS
    const avgCVSS = cve.reduce((sum, c) => sum + c.cvss_score, 0) / cve.length;

    // CISA KEV multiplier
    const cisaCount = cve.filter(c => c.cisa_known_exploited).length;
    const cisaMultiplier = cisaCount > 0 ? 1.2 : 1.0;

    // Recent vulnerability multiplier (last 2 years)
    const recentDate = new Date();
    recentDate.setFullYear(recentDate.getFullYear() - 2);
    const recentCount = cve.filter(c => new Date(c.published_date) > recentDate).length;
    const recencyMultiplier = recentCount > 0 ? 1.1 : 1.0;

    const riskScore = Math.min(10.0, avgCVSS * cisaMultiplier * recencyMultiplier);
    return Math.round(riskScore * 10) / 10;
  }

  // -------------------------------------------------------------------------
  // Statistics
  // -------------------------------------------------------------------------

  /**
   * Get knowledge base statistics.
   */
  getStatistics(): Record<string, number> {
    const stats: Record<string, number> = {};

    stats.total_cwes = this.db.exec('SELECT COUNT(*) FROM cwes')[0].values[0][0] as number;
    stats.total_cves = this.db.exec('SELECT COUNT(*) FROM cves')[0].values[0][0] as number;
    stats.total_owasp = this.db.exec('SELECT COUNT(*) FROM owasp_top10')[0].values[0][0] as number;
    stats.cve_cwe_mappings = this.db.exec('SELECT COUNT(*) FROM cve_cwe_mapping')[0].values[0][0] as number;
    stats.cwe_owasp_mappings = this.db.exec('SELECT COUNT(*) FROM cwe_owasp_mapping')[0].values[0][0] as number;
    stats.threat_patterns = this.db.exec('SELECT COUNT(*) FROM threat_patterns')[0].values[0][0] as number;
    stats.cisa_kev_count = this.db.exec('SELECT COUNT(*) FROM cves WHERE cisa_known_exploited = 1')[0].values[0][0] as number;

    return stats;
  }
}
