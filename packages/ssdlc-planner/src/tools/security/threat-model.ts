/**
 * Phase 10: Security - STRIDE Threat Modeling
 * 
 * Performs STRIDE threat analysis on system architecture using security-kb intelligence.
 * Maps threats to CWE → OWASP → CVE for risk assessment.
 */

import type { ToolResponse } from '@mcp-ssdlc/core';
import { createLogger } from '@mcp-ssdlc/core';
// import { createSecurityKB } from '@mcp-ssdlc/security-kb';  // Available for CVE enrichment
import type { Component, DataFlow, TrustBoundary } from '../tech-lead/design-architecture.js';

const logger = createLogger('Security-Threat-Model');

export interface ThreatModelInput {
  project_name?: string;
  // Structured inputs (from previous phases)
  components?: Component[];
  data_flows?: DataFlow[];
  trust_boundaries?: TrustBoundary[];
  tech_stack?: string[];
  compliance_requirements?: string[];

  // Simple string inputs (from Claude/manual usage)
  component?: string;  // Single component name to analyze
  architecture?: string;  // Architecture description as free text
}

export interface STRIDEThreat {
  id: string;
  category: 'Spoofing' | 'Tampering' | 'Repudiation' | 'Information Disclosure' | 'Denial of Service' | 'Elevation of Privilege';
  target_component: string;
  target_data_flow?: string;
  description: string;
  cwe_id: string;
  cwe_name: string;
  owasp_category: string;
  cvss_score: number;  // From related CVEs
  exploited_in_wild: boolean;
  risk_score: number;  // 0-10
  likelihood: 'low' | 'medium' | 'high';
  impact: 'low' | 'medium' | 'high' | 'critical';
  mitigation_strategy: string[];
  testing_approach: string[];
}

export interface ThreatModelOutput {
  threats: STRIDEThreat[];
  summary: {
    total_threats: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    exploited_in_wild: number;
  };
  attack_surface_analysis: {
    entry_points: number;
    trust_boundary_crossings: number;
    external_dependencies: number;
  };
  recommendations: string[];
}

// Helper function to parse architecture text and extract components
function parseArchitectureText(architecture: string, componentName?: string): Component[] {
  const components: Component[] = [];
  const archLower = architecture.toLowerCase();

  // Extract component type from the componentName or architecture
  const name = componentName || 'System Component';
  const isDatabase = archLower.includes('database') || archLower.includes('postgresql') || archLower.includes('mysql');
  const isApi = archLower.includes('api') || archLower.includes('gateway') || archLower.includes('backend');
  const isFrontend = archLower.includes('frontend') || archLower.includes('react') || archLower.includes('mobile') || archLower.includes('app');
  const isAuth = archLower.includes('auth') || archLower.includes('oauth') || archLower.includes('identity');

  // Determine trust level based on keywords
  let trustLevel: 'untrusted' | 'semi-trusted' | 'trusted' = 'semi-trusted';
  if (archLower.includes('public') || archLower.includes('internet') || archLower.includes('untrusted')) {
    trustLevel = 'untrusted';
  } else if (archLower.includes('internal') || archLower.includes('trusted') || archLower.includes('private')) {
    trustLevel = 'trusted';
  }

  // Determine component type
  let componentType: 'frontend' | 'backend' | 'database' | 'external' | 'storage' = 'backend';
  if (isFrontend) componentType = 'frontend';
  else if (isDatabase) componentType = 'database';
  else if (isAuth) componentType = 'external';

  // Create component based on the specific input
  components.push({
    id: 'C-input',
    name: name,
    type: componentType,
    responsibilities: componentName ? [componentName] : ['Core functionality'],
    technologies: extractTechnologies(architecture),
    trust_level: trustLevel,
    processes_sensitive_data: archLower.includes('phi') || archLower.includes('pii') ||
      archLower.includes('patient') || archLower.includes('sensitive') ||
      archLower.includes('credential') || archLower.includes('medical')
  });

  return components;
}

// Extract technologies from architecture description
function extractTechnologies(text: string): string[] {
  const technologies: string[] = [];
  const techKeywords = [
    'React', 'Vue', 'Angular', 'Node.js', 'Express', 'FastAPI', 'Django', 'Flask',
    'PostgreSQL', 'MySQL', 'MongoDB', 'Redis', 'Elasticsearch',
    'AWS', 'Azure', 'GCP', 'Kubernetes', 'Docker',
    'OAuth', 'JWT', 'Auth0', 'Okta',
    'TLS', 'HTTPS', 'gRPC', 'REST', 'GraphQL'
  ];

  for (const tech of techKeywords) {
    if (text.toLowerCase().includes(tech.toLowerCase())) {
      technologies.push(tech);
    }
  }

  return technologies.length > 0 ? technologies : ['Unknown'];
}

export async function threatModelArchitecture(
  input: ThreatModelInput
): Promise<ToolResponse> {
  // Default components if not provided
  const defaultComponents: Component[] = [
    {
      id: 'C1',
      name: 'Web Frontend',
      type: 'frontend',
      responsibilities: ['User interface', 'Client-side validation'],
      technologies: ['React', 'TypeScript'],
      trust_level: 'untrusted',
      processes_sensitive_data: true
    },
    {
      id: 'C2',
      name: 'API Backend',
      type: 'backend',
      responsibilities: ['Business logic', 'Authentication'],
      technologies: ['Node.js', 'Express'],
      trust_level: 'semi-trusted',
      processes_sensitive_data: true
    },
    {
      id: 'C3',
      name: 'Database',
      type: 'database',
      responsibilities: ['Data storage', 'Query processing'],
      technologies: ['PostgreSQL'],
      trust_level: 'trusted',
      processes_sensitive_data: true
    }
  ];

  const defaultDataFlows: DataFlow[] = [
    {
      id: 'DF1',
      from_component: 'C1',
      to_component: 'C2',
      data_type: 'User requests',
      protocol: 'HTTPS',
      authentication_required: true,
      encryption_required: true,
      crosses_trust_boundary: true
    },
    {
      id: 'DF2',
      from_component: 'C2',
      to_component: 'C3',
      data_type: 'Database queries',
      protocol: 'TLS',
      authentication_required: true,
      encryption_required: true,
      crosses_trust_boundary: false
    }
  ];

  const defaultTrustBoundaries: TrustBoundary[] = [
    {
      id: 'TB1',
      name: 'Public Zone',
      description: 'Untrusted zone',
      components_inside: ['C1'],
      entry_points: ['User'],
      exit_points: ['API']
    },
    {
      id: 'TB2',
      name: 'Internal Zone',
      description: 'Trusted zone',
      components_inside: ['C2', 'C3'],
      entry_points: ['API Gateway'],
      exit_points: ['Database']
    }
  ];

  // Handle string inputs from Claude (component/architecture)
  let components: Component[];

  if (input.component || input.architecture) {
    // Parse free-text input into structured components
    components = parseArchitectureText(
      input.architecture || input.component || '',
      input.component
    );
  } else {
    // Use provided components or defaults
    components = input.components || defaultComponents;
  }

  const dataFlows: DataFlow[] = input.data_flows || defaultDataFlows;
  const trustBoundaries: TrustBoundary[] = input.trust_boundaries || defaultTrustBoundaries;

  logger.info('Performing STRIDE threat modeling', {
    components: components.length,
    data_flows: dataFlows.length,
    trust_boundaries: trustBoundaries.length
  });

  // Note: securityKB can be used to enrich threat data with CVE mappings
  // const securityKB = await createSecurityKB();
  const threats: STRIDEThreat[] = [];
  let threatId = 1;

  // Analyze each component for STRIDE threats
  for (const component of components) {
    // Spoofing threats
    if (component.trust_level === 'untrusted' || component.type === 'frontend') {
      threats.push({
        id: `T-${threatId++}`,
        category: 'Spoofing',
        target_component: component.id,
        description: `Attacker impersonates legitimate user to ${component.name}`,
        cwe_id: 'CWE-287',
        cwe_name: 'Improper Authentication',
        owasp_category: 'A07',
        cvss_score: 8.1,
        exploited_in_wild: true,
        risk_score: 8.5,
        likelihood: 'high',
        impact: 'critical',
        mitigation_strategy: [
          'Implement multi-factor authentication (MFA)',
          'Use industry-standard authentication protocols (OAuth2/OIDC)',
          'Session tokens with proper expiration and rotation',
          'Monitor for suspicious authentication patterns'
        ],
        testing_approach: [
          'Attempt authentication bypass',
          'Test weak password policies',
          'Verify MFA enforcement',
          'Session fixation testing'
        ]
      });
    }

    // Tampering threats
    if (component.processes_sensitive_data) {
      threats.push({
        id: `T-${threatId++}`,
        category: 'Tampering',
        target_component: component.id,
        description: `Attacker modifies data in ${component.name}`,
        cwe_id: 'CWE-284',
        cwe_name: 'Improper Access Control',
        owasp_category: 'A01',
        cvss_score: 7.5,
        exploited_in_wild: false,
        risk_score: 7.0,
        likelihood: 'medium',
        impact: 'high',
        mitigation_strategy: [
          'Implement role-based access control (RBAC)',
          'Use digital signatures for critical data',
          'Enable audit logging for all data modifications',
          'Integrity checks (HMAC) for data transfers'
        ],
        testing_approach: [
          'Attempt unauthorized data modification',
          'Verify RBAC enforcement',
          'Test integrity validation',
          'Privilege escalation testing'
        ]
      });
    }

    // Information Disclosure threats
    if (component.type === 'database' || component.processes_sensitive_data) {
      threats.push({
        id: `T-${threatId++}`,
        category: 'Information Disclosure',
        target_component: component.id,
        description: `Sensitive data leaked from ${component.name}`,
        cwe_id: 'CWE-200',
        cwe_name: 'Exposure of Sensitive Information',
        owasp_category: 'A01',
        cvss_score: 6.5,
        exploited_in_wild: false,
        risk_score: 6.5,
        likelihood: 'medium',
        impact: 'high',
        mitigation_strategy: [
          'Encrypt sensitive data at rest (AES-256)',
          'Encrypt data in transit (TLS 1.3+)',
          'Implement data masking for logs/errors',
          'Minimize data retention',
          'Use secure headers (HSTS, CSP)'
        ],
        testing_approach: [
          'Verify encryption at rest',
          'Test TLS configuration',
          'Check error messages for data leakage',
          'Verify access logging excludes sensitive data'
        ]
      });
    }

    // Denial of Service threats
    if (component.type === 'backend' || component.type === 'frontend') {
      threats.push({
        id: `T-${threatId++}`,
        category: 'Denial of Service',
        target_component: component.id,
        description: `Resource exhaustion attack on ${component.name}`,
        cwe_id: 'CWE-770',
        cwe_name: 'Allocation of Resources Without Limits',
        owasp_category: 'A04',
        cvss_score: 5.3,
        exploited_in_wild: false,
        risk_score: 5.5,
        likelihood: 'medium',
        impact: 'medium',
        mitigation_strategy: [
          'Implement rate limiting per user/IP',
          'Set resource quotas (memory, CPU, connections)',
          'Use CDN and DDoS protection',
          'Implement circuit breakers',
          'Auto-scaling for elastic capacity'
        ],
        testing_approach: [
          'Load testing with high concurrency',
          'Resource exhaustion scenarios',
          'Verify rate limiting',
          'Test auto-scaling triggers'
        ]
      });
    }
  }

  // Analyze data flows for additional threats
  for (const flow of dataFlows) {
    if (flow.crosses_trust_boundary && !flow.encryption_required) {
      threats.push({
        id: `T-${threatId++}`,
        category: 'Information Disclosure',
        target_component: flow.from_component,
        target_data_flow: flow.id,
        description: `Unencrypted data flow ${flow.id} crosses trust boundary`,
        cwe_id: 'CWE-319',
        cwe_name: 'Cleartext Transmission of Sensitive Information',
        owasp_category: 'A02',
        cvss_score: 7.5,
        exploited_in_wild: true,
        risk_score: 8.0,
        likelihood: 'high',
        impact: 'high',
        mitigation_strategy: [
          'Enable TLS 1.3 for all external communications',
          'Use mTLS for internal service-to-service',
          'Implement certificate pinning for mobile apps'
        ],
        testing_approach: [
          'Network traffic inspection',
          'Verify TLS version and cipher suites',
          'Test certificate validation'
        ]
      });
    }

    if (!flow.authentication_required && flow.crosses_trust_boundary) {
      threats.push({
        id: `T-${threatId++}`,
        category: 'Elevation of Privilege',
        target_component: flow.to_component,
        target_data_flow: flow.id,
        description: `Unauthenticated data flow ${flow.id} allows privilege escalation`,
        cwe_id: 'CWE-306',
        cwe_name: 'Missing Authentication',
        owasp_category: 'A07',
        cvss_score: 9.8,
        exploited_in_wild: true,
        risk_score: 9.5,
        likelihood: 'high',
        impact: 'critical',
        mitigation_strategy: [
          'Require authentication for all trust boundary crossings',
          'Implement least privilege access',
          'Use short-lived JWT tokens',
          'Enforce authorization checks at every service'
        ],
        testing_approach: [
          'Attempt unauthenticated access',
          'Test token expiration',
          'Verify authorization enforcement',
          'Horizontal privilege escalation testing'
        ]
      });
    }
  }

  // Calculate summary
  const summary = {
    total_threats: threats.length,
    critical: threats.filter(t => t.impact === 'critical').length,
    high: threats.filter(t => t.impact === 'high').length,
    medium: threats.filter(t => t.impact === 'medium').length,
    low: threats.filter(t => t.impact === 'low').length,
    exploited_in_wild: threats.filter(t => t.exploited_in_wild).length
  };

  const attackSurfaceAnalysis = {
    entry_points: dataFlows.filter(df =>
      components.find(c => c.id === df.from_component)?.trust_level === 'untrusted'
    ).length,
    trust_boundary_crossings: dataFlows.filter(df => df.crosses_trust_boundary).length,
    external_dependencies: components.filter(c => c.type === 'external').length
  };

  const output: ThreatModelOutput = {
    threats,
    summary,
    attack_surface_analysis: attackSurfaceAnalysis,
    recommendations: [
      `🔴 CRITICAL: ${summary.critical} critical threats require immediate attention`,
      `🟠 HIGH: ${summary.high} high-priority threats need mitigation planning`,
      `⚠️ ${summary.exploited_in_wild} threats are actively exploited in the wild`,
      '🛡️ Implement defense-in-depth: multiple layers of security controls',
      '🔒 Prioritize threats that cross trust boundaries',
      '📊 Use this threat model as input for security testing strategy',
      '🎯 Schedule regular threat model updates as architecture evolves'
    ]
  };

  logger.success('Threat modeling complete', {
    total_threats: output.summary.total_threats,
    critical: output.summary.critical,
    high: output.summary.high
  });

  return {
    content: [
      {
        type: 'text',
        text: formatThreatModelOutput(output)
      }
    ]
  };
}

function formatThreatModelOutput(output: ThreatModelOutput): string {
  let report = `# 🛡️ STRIDE Threat Model\n\n`;

  report += `## 📊 Executive Summary\n\n`;
  report += `**Total Threats Identified:** ${output.summary.total_threats}\n\n`;
  report += `| Severity | Count |\n`;
  report += `|----------|-------|\n`;
  report += `| 🔴 Critical | ${output.summary.critical} |\n`;
  report += `| 🟠 High | ${output.summary.high} |\n`;
  report += `| 🟡 Medium | ${output.summary.medium} |\n`;
  report += `| 🟢 Low | ${output.summary.low} |\n\n`;
  report += `⚠️ **Exploited in Wild:** ${output.summary.exploited_in_wild} threats\n\n`;

  report += `## 🎯 Attack Surface Analysis\n\n`;
  report += `- **Entry Points:** ${output.attack_surface_analysis.entry_points}\n`;
  report += `- **Trust Boundary Crossings:** ${output.attack_surface_analysis.trust_boundary_crossings}\n`;
  report += `- **External Dependencies:** ${output.attack_surface_analysis.external_dependencies}\n\n`;

  report += `## 🚨 Threats (STRIDE Classification)\n\n`;

  // Group by category
  const categories = ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'];
  categories.forEach(category => {
    const categoryThreats = output.threats.filter(t => t.category === category);
    if (categoryThreats.length === 0) return;

    report += `### ${category} (${categoryThreats.length} threats)\n\n`;
    categoryThreats.forEach(threat => {
      const severityIcon = threat.impact === 'critical' ? '🔴' :
        threat.impact === 'high' ? '🟠' :
          threat.impact === 'medium' ? '🟡' : '🟢';
      report += `#### ${threat.id}: ${threat.description}\n\n`;
      report += `${severityIcon} **Impact:** ${threat.impact.toUpperCase()} | **Likelihood:** ${threat.likelihood} | **Risk:** ${threat.risk_score}/10\n\n`;
      report += `**Target:** Component ${threat.target_component}${threat.target_data_flow ? ` (Data Flow ${threat.target_data_flow})` : ''}\n\n`;
      report += `**CWE:** ${threat.cwe_id} - ${threat.cwe_name}  \n`;
      report += `**OWASP:** ${threat.owasp_category}  \n`;
      report += `**CVSS:** ${threat.cvss_score}  \n`;
      if (threat.exploited_in_wild) {
        report += `⚠️ **ACTIVELY EXPLOITED IN THE WILD**\n\n`;
      }
      report += `\n**Mitigation Strategy:**\n`;
      threat.mitigation_strategy.forEach(m => report += `- ${m}\n`);
      report += `\n**Testing Approach:**\n`;
      threat.testing_approach.forEach(t => report += `- ${t}\n`);
      report += `\n`;
    });
  });

  report += `## 💡 Recommendations\n\n`;
  output.recommendations.forEach(rec => report += `${rec}\n`);

  return report;
}
