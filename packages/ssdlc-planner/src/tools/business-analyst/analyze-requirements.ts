/**
 * Phase 9: Business Analyst - Analyze Requirements
 * 
 * Analyzes business requirements and generates:
 * - User stories with acceptance criteria
 * - Abuse cases (security-relevant)
 * - Non-functional requirements (NFRs)
 * - Input for architecture design
 */

import type { MCPToolResult } from '@mcp-ssdlc/core';
import { createLogger } from '@mcp-ssdlc/core';

const logger = createLogger('BA-Analyze-Requirements');

export interface BAAnalyzeRequirementsInput {
  project_description: string;
  users: string[];  // Target user personas
  business_goals: string[];
  compliance_requirements?: string[];  // GDPR, PCI-DSS, etc.
  security_concerns?: string[];
}

export interface UserStory {
  id: string;
  title: string;
  user_role: string;
  action: string;
  benefit: string;
  acceptance_criteria: string[];
  security_notes: string[];
  priority: 'critical' | 'high' | 'medium' | 'low';
}

export interface AbuseCase {
  id: string;
  title: string;
  attacker_goal: string;
  attack_vector: string;
  assets_at_risk: string[];
  likelihood: 'high' | 'medium' | 'low';
  impact: 'critical' | 'high' | 'medium' | 'low';
  mitigations: string[];
}

export interface BAAnalyzeRequirementsOutput {
  user_stories: UserStory[];
  abuse_cases: AbuseCase[];
  non_functional_requirements: {
    category: string;
    requirement: string;
    rationale: string;
    security_relevant: boolean;
  }[];
  data_classification: {
    data_type: string;
    sensitivity: 'public' | 'internal' | 'confidential' | 'restricted';
    regulations: string[];
  }[];
  recommendations: string[];
}

export async function analyzeBusinessRequirements(
  input: BAAnalyzeRequirementsInput
): Promise<MCPToolResult> {
  logger.info('Analyzing business requirements', { 
    users: input.users.length,
    goals: input.business_goals.length 
  });

  // Generate user stories from business goals
  const userStories: UserStory[] = [];
  let storyId = 1;

  for (const goal of input.business_goals) {
    for (const user of input.users) {
      userStories.push({
        id: `US-${storyId++}`,
        title: `${user} achieves ${goal}`,
        user_role: user,
        action: goal,
        benefit: `Value delivery for ${goal}`,
        acceptance_criteria: [
          `Given ${user} has access`,
          `When they perform ${goal}`,
          `Then the system responds appropriately`,
          'And security controls are enforced'
        ],
        security_notes: [
          'Requires authentication',
          'Input validation needed',
          'Audit logging required'
        ],
        priority: 'high'
      });
    }
  }

  // Generate abuse cases (security-relevant)
  const abuseCases: AbuseCase[] = [
    {
      id: 'AB-1',
      title: 'Unauthorized Access to Sensitive Data',
      attacker_goal: 'Access confidential data without authorization',
      attack_vector: 'Authentication bypass, privilege escalation',
      assets_at_risk: ['User data', 'Business logic', 'Credentials'],
      likelihood: 'medium',
      impact: 'critical',
      mitigations: [
        'Implement strong authentication (MFA)',
        'Role-based access control (RBAC)',
        'Audit all access attempts',
        'Encrypt sensitive data at rest'
      ]
    },
    {
      id: 'AB-2',
      title: 'Data Injection Attack',
      attacker_goal: 'Inject malicious data to compromise system',
      attack_vector: 'SQL injection, XSS, command injection',
      assets_at_risk: ['Database', 'User sessions', 'Server integrity'],
      likelihood: 'high',
      impact: 'high',
      mitigations: [
        'Parameterized queries for all DB operations',
        'Input validation and sanitization',
        'Output encoding for web content',
        'Content Security Policy (CSP)'
      ]
    }
  ];

  // Non-functional requirements
  const nfrs = [
    {
      category: 'Security',
      requirement: 'All user authentication must use industry-standard protocols (OAuth2/OIDC)',
      rationale: 'Prevent credential theft and session hijacking',
      security_relevant: true
    },
    {
      category: 'Security',
      requirement: 'All sensitive data must be encrypted in transit (TLS 1.3+) and at rest (AES-256)',
      rationale: input.compliance_requirements?.includes('GDPR') 
        ? 'GDPR Article 32: Security of processing'
        : 'Protect confidentiality of user data',
      security_relevant: true
    },
    {
      category: 'Performance',
      requirement: 'System must handle 1000 concurrent users',
      rationale: 'Support business scale',
      security_relevant: false
    },
    {
      category: 'Auditability',
      requirement: 'All security-relevant events must be logged with timestamp, user, and action',
      rationale: 'Incident response and compliance',
      security_relevant: true
    }
  ];

  // Data classification
  const dataClassification = [
    {
      data_type: 'User credentials',
      sensitivity: 'restricted' as const,
      regulations: ['GDPR', 'PCI-DSS']
    },
    {
      data_type: 'Personal information (PII)',
      sensitivity: 'confidential' as const,
      regulations: input.compliance_requirements || ['GDPR']
    },
    {
      data_type: 'Application logs',
      sensitivity: 'internal' as const,
      regulations: []
    }
  ];

  const output: BAAnalyzeRequirementsOutput = {
    user_stories: userStories,
    abuse_cases: abuseCases,
    non_functional_requirements: nfrs,
    data_classification: dataClassification,
    recommendations: [
      'Prioritize abuse cases AB-1 and AB-2 in threat modeling',
      'Ensure architecture includes defense-in-depth for identified attack vectors',
      'Plan security testing for all critical user stories',
      `Compliance focus: ${input.compliance_requirements?.join(', ') || 'General security best practices'}`
    ]
  };

  logger.success('Business analysis complete', {
    user_stories: output.user_stories.length,
    abuse_cases: output.abuse_cases.length,
    nfrs: output.non_functional_requirements.length
  });

  return {
    content: [
      {
        type: 'text',
        text: formatBAOutput(output)
      }
    ]
  };
}

function formatBAOutput(output: BAAnalyzeRequirementsOutput): string {
  let report = `# 📋 Business Requirements Analysis\n\n`;
  
  report += `## 👤 User Stories (${output.user_stories.length})\n\n`;
  for (const story of output.user_stories) {
    report += `### ${story.id}: ${story.title}\n`;
    report += `**As a** ${story.user_role}  \n`;
    report += `**I want to** ${story.action}  \n`;
    report += `**So that** ${story.benefit}\n\n`;
    report += `**Acceptance Criteria:**\n`;
    story.acceptance_criteria.forEach(ac => report += `- ${ac}\n`);
    report += `\n**Security Notes:**\n`;
    story.security_notes.forEach(note => report += `- 🔒 ${note}\n`);
    report += `\n`;
  }

  report += `## 🚨 Abuse Cases (${output.abuse_cases.length})\n\n`;
  for (const abuse of output.abuse_cases) {
    report += `### ${abuse.id}: ${abuse.title}\n`;
    report += `**Attacker Goal:** ${abuse.attacker_goal}  \n`;
    report += `**Attack Vector:** ${abuse.attack_vector}  \n`;
    report += `**Likelihood:** ${abuse.likelihood} | **Impact:** ${abuse.impact}\n\n`;
    report += `**Assets at Risk:**\n`;
    abuse.assets_at_risk.forEach(asset => report += `- ${asset}\n`);
    report += `\n**Mitigations:**\n`;
    abuse.mitigations.forEach(mit => report += `- ✅ ${mit}\n`);
    report += `\n`;
  }

  report += `## 📊 Non-Functional Requirements\n\n`;
  output.non_functional_requirements
    .filter(nfr => nfr.security_relevant)
    .forEach(nfr => {
      report += `### ${nfr.category}: ${nfr.requirement}\n`;
      report += `**Rationale:** ${nfr.rationale}\n\n`;
    });

  report += `## 🔐 Data Classification\n\n`;
  report += `| Data Type | Sensitivity | Regulations |\n`;
  report += `|-----------|-------------|-------------|\n`;
  output.data_classification.forEach(dc => {
    report += `| ${dc.data_type} | ${dc.sensitivity.toUpperCase()} | ${dc.regulations.join(', ') || 'None'} |\n`;
  });

  report += `\n## 💡 Recommendations\n\n`;
  output.recommendations.forEach(rec => report += `- ${rec}\n`);

  return report;
}
