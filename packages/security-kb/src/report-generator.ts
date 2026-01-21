/**
 * Phase 8: Report Generator
 * 
 * Generates professional security reports in Markdown format
 * for executives, security teams, and developers.
 */

import type { SecurityFinding, SecurityReviewResult } from './security-review.js';
import { 
  normalizeSeverity, 
  formatDeveloperSeverity, 
  formatSecuritySeverity,
  formatBusinessImpact,
  getSLADescription,
  type SeverityAssessment 
} from './severity-normalizer.js';

export interface ReportOptions {
  /** Project name */
  projectName?: string;
  
  /** Include AI explanations */
  includeExplanations?: boolean;
  
  /** Include remediation examples */
  includeRemediation?: boolean;
  
  /** Minimum severity to report */
  minSeverity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  
  /** Report format */
  format?: 'full' | 'executive' | 'developer';
}

export interface EnrichedFinding extends SecurityFinding {
  severity: SeverityAssessment;
}

/**
 * Generate comprehensive security report
 */
export function generateSecurityReport(
  result: SecurityReviewResult,
  options: ReportOptions = {}
): string {
  const {
    projectName = 'Security Review',
    format = 'full',
    minSeverity = 'LOW'
  } = options;
  
  // Enrich findings with severity normalization
  const enrichedFindings: EnrichedFinding[] = result.findings.map(f => ({
    ...f,
    severity: normalizeSeverity(f)
  }));
  
  // Filter by minimum severity
  const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const minLevel = severityOrder[minSeverity];
  const filteredFindings = enrichedFindings.filter(
    f => severityOrder[f.severity.security] >= minLevel
  );
  
  let report = '';
  
  // Header
  report += generateHeader(projectName, result);
  
  // Executive Summary
  if (format === 'full' || format === 'executive') {
    report += generateExecutiveSummary(filteredFindings, result);
  }
  
  // High-Risk Findings
  report += generateHighRiskFindings(filteredFindings);
  
  // CWE/OWASP Mapping
  if (format === 'full') {
    report += generateCWEOWASPMapping(filteredFindings);
  }
  
  // Exploited in Wild Highlights
  report += generateExploitedInWildSection(filteredFindings);
  
  // Remediation Checklist
  if (format === 'full' || format === 'developer') {
    report += generateRemediationChecklist(filteredFindings);
  }
  
  // All Findings Detail
  if (format === 'full') {
    report += generateDetailedFindings(filteredFindings, options);
  }
  
  // Footer
  report += generateFooter(result);
  
  return report;
}

function generateHeader(projectName: string, result: SecurityReviewResult): string {
  const timestamp = new Date(result.scan_metadata.timestamp).toLocaleString();
  
  return `# 🔒 Security Review Report

**Project**: ${projectName}  
**Language**: ${result.language}  
**Scan Date**: ${timestamp}  
**Lines Analyzed**: ${result.total_lines.toLocaleString()}  
**Patterns Checked**: ${result.scan_metadata.patterns_checked}

---

`;
}

function generateExecutiveSummary(findings: EnrichedFinding[], result: SecurityReviewResult): string {
  const critical = findings.filter(f => f.severity.security === 'CRITICAL').length;
  const high = findings.filter(f => f.severity.security === 'HIGH').length;
  const medium = findings.filter(f => f.severity.security === 'MEDIUM').length;
  const low = findings.filter(f => f.severity.security === 'LOW').length;
  
  const exploited = findings.filter(f => f.threat_context.exploited_in_wild).length;
  const cisaKev = findings.filter(f => 
    f.cvss_context.top_cves.some(cve => cve.cisa_kev)
  ).length;
  
  const fixNow = findings.filter(f => f.severity.developer === 'FIX_NOW').length;
  
  const highImpact = findings.filter(f => f.severity.business === 'HIGH').length;
  
  let summary = `## 📊 Executive Summary

### Overall Risk Assessment

`;
  
  // Overall project risk
  const totalRisk = result.summary.total_risk_score;
  
  // Risk management rule: ANY Critical/High finding elevates overall risk
  const hasCritical = findings.some(f => f.severity.security === 'CRITICAL');
  const hasHigh = findings.some(f => f.severity.security === 'HIGH');
  
  let riskLevel: string;
  if (hasCritical || totalRisk >= 70) {
    riskLevel = '🔴 HIGH RISK';
  } else if (hasHigh || totalRisk >= 20) {
    riskLevel = '🟠 MEDIUM RISK';
  } else {
    riskLevel = '🟢 LOW RISK';
  }
  
  summary += `**Project Risk Score**: ${riskLevel} (${totalRisk.toFixed(1)}/100)\n\n`;
  
  summary += `### Key Findings

- **Total Issues**: ${findings.length}
  - 🔴 Critical: ${critical}
  - 🟠 High: ${high}
  - 🟡 Medium: ${medium}
  - 🟢 Low: ${low}

`;
  
  if (exploited > 0 || cisaKev > 0 || fixNow > 0) {
    summary += `### ⚠️ Immediate Action Required

`;
    if (fixNow > 0) {
      summary += `- **${fixNow} findings require immediate attention** (Fix within 24 hours)\n`;
    }
    if (exploited > 0) {
      summary += `- **${exploited} vulnerabilities actively exploited in the wild**\n`;
    }
    if (cisaKev > 0) {
      summary += `- **${cisaKev} vulnerabilities in CISA Known Exploited Vulnerabilities catalog**\n`;
    }
    summary += '\n';
  }
  
  summary += `### 💼 Business Impact

- **High Impact Issues**: ${highImpact}
- **Average Confidence**: ${(result.summary.average_confidence * 100).toFixed(0)}%
- **Recommended Actions**: See remediation checklist below

---

`;
  
  return summary;
}

function generateHighRiskFindings(findings: EnrichedFinding[]): string {
  const highRisk = findings
    .filter(f => f.severity.security === 'CRITICAL' || f.severity.security === 'HIGH')
    .sort((a, b) => b.risk_score - a.risk_score);
  
  if (highRisk.length === 0) {
    return `## ✅ High-Risk Findings

No critical or high-severity findings detected.

---

`;
  }
  
  let section = `## 🚨 High-Risk Findings

${highRisk.length} critical or high-severity issues require attention:

`;
  
  highRisk.forEach((finding, index) => {
    section += `### ${index + 1}. ${finding.cwe.id}: ${finding.cwe.name}

**Severity**: ${formatSecuritySeverity(finding.severity.security)} | **Action**: ${formatDeveloperSeverity(finding.severity.developer)}  
**Risk Score**: ${finding.risk_score.toFixed(1)}/10 | **Confidence**: ${(finding.confidence * 100).toFixed(0)}%  
**SLA**: Fix within ${getSLADescription(finding.severity.recommended_sla_hours)}

`;
    
    if (finding.threat_context.exploited_in_wild) {
      section += `⚠️ **ACTIVELY EXPLOITED IN THE WILD**\n\n`;
    }
    
    if (finding.cvss_context.top_cves.some(cve => cve.cisa_kev)) {
      section += `⚠️ **CISA KEV LISTED - KNOWN EXPLOITED VULNERABILITY**\n\n`;
    }
    
    section += `**Attack Vector**: ${finding.threat_context.attack_vector}\n`;
    section += `**Impact**: ${finding.threat_context.impact}\n\n`;
    
    if (finding.line_number) {
      section += `**Location**: Line ${finding.line_number}\n`;
    }
    
    section += `\`\`\`${finding.snippet ? '' : 'text'}\n${finding.snippet || 'Pattern: ' + finding.pattern}\n\`\`\`\n\n`;
    
    section += `**Explanation**: ${finding.explanation}\n\n`;
    
    if (finding.remediation) {
      section += `**Quick Fix**:\n`;
      section += `\`\`\`\n${finding.remediation.secure_example}\n\`\`\`\n\n`;
    }
    
    section += `---\n\n`;
  });
  
  return section;
}

function generateCWEOWASPMapping(findings: EnrichedFinding[]): string {
  // Group by CWE
  const cweMap = new Map<string, EnrichedFinding[]>();
  findings.forEach(f => {
    const key = f.cwe.id;
    if (!cweMap.has(key)) cweMap.set(key, []);
    cweMap.get(key)!.push(f);
  });
  
  // Group by OWASP
  const owaspMap = new Map<string, EnrichedFinding[]>();
  findings.forEach(f => {
    f.owasp.forEach(category => {
      if (!owaspMap.has(category)) owaspMap.set(category, []);
      owaspMap.get(category)!.push(f);
    });
  });
  
  let section = `## 📚 CWE & OWASP Mapping

### CWE Coverage

| CWE ID | Name | Count | Max Risk |
|--------|------|-------|----------|
`;
  
  Array.from(cweMap.entries())
    .sort((a, b) => b[1].length - a[1].length)
    .forEach(([cweId, cweFindings]) => {
      const maxRisk = Math.max(...cweFindings.map(f => f.risk_score));
      const name = cweFindings[0].cwe.name;
      section += `| ${cweId} | ${name} | ${cweFindings.length} | ${maxRisk.toFixed(1)} |\n`;
    });
  
  section += `\n### OWASP Top 10 Mapping

| OWASP Category | Count | Avg Risk |
|----------------|-------|----------|
`;
  
  Array.from(owaspMap.entries())
    .sort((a, b) => b[1].length - a[1].length)
    .forEach(([category, owaspFindings]) => {
      const avgRisk = owaspFindings.reduce((sum, f) => sum + f.risk_score, 0) / owaspFindings.length;
      section += `| ${category} | ${owaspFindings.length} | ${avgRisk.toFixed(1)} |\n`;
    });
  
  section += `\n---\n\n`;
  
  return section;
}

function generateExploitedInWildSection(findings: EnrichedFinding[]): string {
  const exploited = findings.filter(f => f.threat_context.exploited_in_wild);
  const cisaKev = findings.filter(f => 
    f.cvss_context.top_cves.some(cve => cve.cisa_kev)
  );
  
  if (exploited.length === 0 && cisaKev.length === 0) {
    return `## ✅ Exploited Vulnerabilities

No vulnerabilities with known active exploitation detected.

---

`;
  }
  
  let section = `## ⚠️ Exploited Vulnerabilities - Priority Action Required

### Actively Exploited

`;
  
  if (exploited.length > 0) {
    section += `**${exploited.length} vulnerabilities are actively exploited in the wild:**

`;
    exploited.forEach((finding, index) => {
      section += `${index + 1}. **${finding.cwe.id}**: ${finding.cwe.name}\n`;
      section += `   - Risk: ${finding.risk_score.toFixed(1)}/10\n`;
      section += `   - Attack: ${finding.threat_context.attack_vector}\n`;
      if (finding.line_number) {
        section += `   - Location: Line ${finding.line_number}\n`;
      }
      section += `\n`;
    });
  }
  
  if (cisaKev.length > 0) {
    section += `### CISA Known Exploited Vulnerabilities (KEV)

**${cisaKev.length} vulnerabilities in CISA KEV catalog:**

`;
    cisaKev.forEach((finding, index) => {
      const kevCVEs = finding.cvss_context.top_cves.filter(cve => cve.cisa_kev);
      section += `${index + 1}. **${finding.cwe.id}**: ${finding.cwe.name}\n`;
      kevCVEs.forEach(cve => {
        section += `   - ${cve.cve_id} (CVSS ${cve.cvss_score})\n`;
      });
      section += `\n`;
    });
  }
  
  section += `> **Action**: These findings must be remediated immediately. Actively exploited vulnerabilities pose imminent risk to production systems.

---

`;
  
  return section;
}

function generateRemediationChecklist(findings: EnrichedFinding[]): string {
  const fixNow = findings.filter(f => f.severity.developer === 'FIX_NOW');
  const reviewSoon = findings.filter(f => f.severity.developer === 'REVIEW_SOON');
  const review = findings.filter(f => f.severity.developer === 'REVIEW');
  
  let section = `## ✅ Remediation Checklist

### Immediate Actions (24 hours)

`;
  
  if (fixNow.length === 0) {
    section += `No immediate actions required.\n\n`;
  } else {
    fixNow.forEach((finding, index) => {
      section += `- [ ] **${finding.cwe.id}**: ${finding.cwe.name}`;
      if (finding.line_number) section += ` (Line ${finding.line_number})`;
      section += `\n`;
      if (finding.remediation) {
        section += `      → ${finding.remediation.explanation}\n`;
      }
    });
    section += `\n`;
  }
  
  section += `### Short-Term Actions (1 week)

`;
  
  if (reviewSoon.length === 0) {
    section += `No short-term actions required.\n\n`;
  } else {
    reviewSoon.forEach((finding, index) => {
      section += `- [ ] **${finding.cwe.id}**: ${finding.cwe.name}`;
      if (finding.line_number) section += ` (Line ${finding.line_number})`;
      section += `\n`;
    });
    section += `\n`;
  }
  
  section += `### Medium-Term Actions (1 month)

`;
  
  if (review.length === 0) {
    section += `No medium-term actions required.\n\n`;
  } else {
    section += `${review.length} findings require review and remediation planning.\n\n`;
  }
  
  section += `---\n\n`;
  
  return section;
}

function generateDetailedFindings(
  findings: EnrichedFinding[], 
  options: ReportOptions
): string {
  let section = `## 📋 Detailed Findings

All ${findings.length} findings with complete context:

`;
  
  findings.forEach((finding, index) => {
    section += `### Finding ${index + 1}: ${finding.cwe.id}

`;
    
    section += `| Property | Value |\n`;
    section += `|----------|-------|\n`;
    section += `| **CWE** | ${finding.cwe.id} - ${finding.cwe.name} |\n`;
    section += `| **OWASP** | ${finding.owasp.join(', ')} |\n`;
    section += `| **Security Severity** | ${formatSecuritySeverity(finding.severity.security)} |\n`;
    section += `| **Developer Action** | ${formatDeveloperSeverity(finding.severity.developer)} |\n`;
    section += `| **Business Impact** | ${formatBusinessImpact(finding.severity.business)} |\n`;
    section += `| **Risk Score** | ${finding.risk_score.toFixed(1)}/10 |\n`;
    section += `| **Confidence** | ${(finding.confidence * 100).toFixed(0)}% |\n`;
    section += `| **SLA** | ${getSLADescription(finding.severity.recommended_sla_hours)} |\n`;
    if (finding.line_number) {
      section += `| **Location** | Line ${finding.line_number} |\n`;
    }
    section += `\n`;
    
    section += `**Explanation**: ${finding.explanation}\n\n`;
    
    if (finding.snippet) {
      section += `**Code**:\n\`\`\`\n${finding.snippet}\n\`\`\`\n\n`;
    }
    
    if (finding.remediation && options.includeRemediation !== false) {
      section += `**Remediation**:\n\n`;
      section += `${finding.remediation.explanation}\n\n`;
      section += `Secure Example:\n\`\`\`\n${finding.remediation.secure_example}\n\`\`\`\n\n`;
    }
    
    if (finding.cvss_context.top_cves.length > 0) {
      section += `**Related CVEs**:\n`;
      finding.cvss_context.top_cves.slice(0, 3).forEach(cve => {
        section += `- ${cve.cve_id} (CVSS ${cve.cvss_score})`;
        if (cve.cisa_kev) section += ` ⚠️ CISA KEV`;
        section += `\n`;
      });
      section += `\n`;
    }
    
    if (finding.false_positive_notes) {
      section += `> ⚠️ **Note**: ${finding.false_positive_notes}\n\n`;
    }
    
    section += `---\n\n`;
  });
  
  return section;
}

function generateFooter(result: SecurityReviewResult): string {
  return `## 📝 Report Metadata

**Knowledge Base Version**: ${result.scan_metadata.kb_version}  
**Scan Timestamp**: ${result.scan_metadata.timestamp}  
**Average Detection Confidence**: ${(result.summary.average_confidence * 100).toFixed(0)}%

---

*This report was generated by the MCP SSDLC Security Toolkit - Deterministic security analysis with AI-enhanced explanations.*
`;
}

/**
 * Generate quick summary (for CLI/API responses)
 */
export function generateQuickSummary(result: SecurityReviewResult): string {
  const findings = result.findings.map(f => ({ ...f, severity: normalizeSeverity(f) }));
  
  const critical = findings.filter(f => f.severity.security === 'CRITICAL').length;
  const high = findings.filter(f => f.severity.security === 'HIGH').length;
  const exploited = findings.filter(f => f.threat_context.exploited_in_wild).length;
  
  let summary = `Security Review Summary:\n`;
  summary += `  Total Findings: ${findings.length}\n`;
  summary += `  Critical: ${critical} | High: ${high}\n`;
  if (exploited > 0) {
    summary += `  ⚠️ ${exploited} actively exploited vulnerabilities\n`;
  }
  summary += `  Overall Risk: ${result.summary.total_risk_score.toFixed(1)}/100\n`;
  
  return summary;
}
