/**
 * Phase 8: Severity Normalization
 * 
 * Normalizes security findings across different audiences:
 * - Developer Severity: Clear actionability for engineers
 * - Security Severity: Standard vulnerability classification
 * - Business Impact: Executive-level risk assessment
 */

import type { SecurityFinding } from './security-review.js';

/**
 * Developer-facing severity levels
 */
export type DeveloperSeverity = 
  | 'FIX_NOW'       // Critical, exploited in wild, must fix immediately
  | 'REVIEW_SOON'   // High severity, should fix in current sprint
  | 'REVIEW'        // Medium severity, plan remediation
  | 'WARNING';      // Low severity or informational

/**
 * Standard security severity (CVSS-aligned)
 */
export type SecuritySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

/**
 * Business impact classification
 */
export type BusinessImpact = 'HIGH' | 'MEDIUM' | 'LOW';

/**
 * Normalized severity assessment
 */
export interface SeverityAssessment {
  /** Developer-actionable severity */
  developer: DeveloperSeverity;
  
  /** Security team classification */
  security: SecuritySeverity;
  
  /** Business impact level */
  business: BusinessImpact;
  
  /** Justification for severity assignment */
  rationale: string;
  
  /** Recommended SLA (hours) */
  recommended_sla_hours: number;
}

/**
 * Normalize finding severity across different audiences
 */
export function normalizeSeverity(finding: SecurityFinding): SeverityAssessment {
  const riskScore = finding.risk_score;
  const confidence = finding.confidence;
  const exploitedInWild = finding.threat_context.exploited_in_wild;
  const cisaKev = finding.cvss_context.top_cves.some(cve => cve.cisa_kev);
  const urgency = finding.threat_context.urgency;
  
  // Determine Security Severity (CVSS-aligned)
  let security: SecuritySeverity;
  if (riskScore >= 9.0) security = 'CRITICAL';
  else if (riskScore >= 7.0) security = 'HIGH';
  else if (riskScore >= 4.0) security = 'MEDIUM';
  else security = 'LOW';
  
  // Determine Developer Severity (actionability-focused)
  let developer: DeveloperSeverity;
  let sla: number;
  
  if (exploitedInWild || cisaKev || (riskScore >= 9.0 && confidence >= 0.80)) {
    developer = 'FIX_NOW';
    sla = 24; // Fix within 24 hours
  } else if (riskScore >= 7.0 && confidence >= 0.70) {
    developer = 'REVIEW_SOON';
    sla = 168; // Fix within 1 week (7 days)
  } else if (riskScore >= 4.0) {
    developer = 'REVIEW';
    sla = 720; // Fix within 1 month (30 days)
  } else {
    developer = 'WARNING';
    sla = 2160; // Fix within 3 months (90 days)
  }
  
  // Low confidence findings require review regardless of risk score
  if (confidence < 0.60 && developer === 'FIX_NOW') {
    developer = 'REVIEW_SOON'; // Downgrade due to uncertainty
    sla = 168;
  }
  
  // Determine Business Impact
  let business: BusinessImpact;
  
  if (exploitedInWild || cisaKev || riskScore >= 8.5) {
    business = 'HIGH';
  } else if (riskScore >= 6.0) {
    business = 'MEDIUM';
  } else {
    business = 'LOW';
  }
  
  // Build rationale
  const reasons: string[] = [];
  
  if (exploitedInWild) reasons.push('exploited in the wild');
  if (cisaKev) reasons.push('CISA KEV listed');
  if (riskScore >= 9.0) reasons.push('critical CVSS score');
  if (confidence < 0.60) reasons.push('moderate confidence - needs review');
  if (urgency === 'CRITICAL') reasons.push('critical attack vector');
  
  const rationale = reasons.length > 0
    ? `${security} severity: ${reasons.join(', ')}`
    : `${security} severity based on risk score ${riskScore}/10`;
  
  return {
    developer,
    security,
    business,
    rationale,
    recommended_sla_hours: sla
  };
}

/**
 * Format developer severity with emoji indicator
 */
export function formatDeveloperSeverity(severity: DeveloperSeverity): string {
  switch (severity) {
    case 'FIX_NOW': return '🚨 FIX NOW';
    case 'REVIEW_SOON': return '⚠️ REVIEW SOON';
    case 'REVIEW': return '📋 REVIEW';
    case 'WARNING': return '💡 WARNING';
  }
}

/**
 * Format security severity with color indicator
 */
export function formatSecuritySeverity(severity: SecuritySeverity): string {
  switch (severity) {
    case 'CRITICAL': return '🔴 CRITICAL';
    case 'HIGH': return '🟠 HIGH';
    case 'MEDIUM': return '🟡 MEDIUM';
    case 'LOW': return '🟢 LOW';
  }
}

/**
 * Format business impact
 */
export function formatBusinessImpact(impact: BusinessImpact): string {
  switch (impact) {
    case 'HIGH': return '💼 HIGH IMPACT';
    case 'MEDIUM': return '💼 MEDIUM IMPACT';
    case 'LOW': return '💼 LOW IMPACT';
  }
}

/**
 * Get SLA description
 */
export function getSLADescription(hours: number): string {
  if (hours <= 24) return '24 hours';
  if (hours <= 168) return '1 week';
  if (hours <= 720) return '1 month';
  return '3 months';
}
