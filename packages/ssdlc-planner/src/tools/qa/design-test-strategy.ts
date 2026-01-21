/**
 * Phase 11: QA - Design Security Test Strategy
 * 
 * Creates comprehensive security testing approach from threat model and requirements.
 */

import type { ToolResponse } from '@mcp-ssdlc/core';
import { createLogger } from '@mcp-ssdlc/core';
import type { STRIDEThreat } from '../security/threat-model.js';
import type { AbuseCase } from '../business-analyst/analyze-requirements.js';

const logger = createLogger('QA-Test-Strategy');

// Flexible input - accepts either detailed threat data or simple project info
export interface TestStrategyInput {
  // Optional detailed inputs from previous phases
  threats?: STRIDEThreat[];
  abuse_cases?: AbuseCase[];
  compliance_requirements?: string[];
  risk_tolerance?: 'low' | 'medium' | 'high';

  // Alternative simple inputs for standalone use
  project_name?: string;
  test_levels?: string[];
  tech_stack?: string[];
  risk_level?: 'low' | 'medium' | 'high' | 'critical';
}

export interface SecurityTestCase {
  id: string;
  category: 'Authentication' | 'Authorization' | 'Data Validation' | 'Cryptography' | 'Session Management' | 'Error Handling' | 'Configuration' | 'Network Security';
  title: string;
  threat_id?: string;  // Links to threat model
  abuse_case_id?: string;  // Links to abuse case
  owasp_testing_guide: string;  // WSTG reference
  priority: 'critical' | 'high' | 'medium' | 'low';
  test_steps: string[];
  expected_result: string;
  automated: boolean;
  tools_required: string[];
}

export interface PenetrationTestChecklist {
  phase: string;
  tasks: string[];
}

export interface TestStrategyOutput {
  test_cases: SecurityTestCase[];
  penetration_test_plan: PenetrationTestChecklist[];
  automation_coverage: {
    total_tests: number;
    automated: number;
    manual: number;
    automation_percentage: number;
  };
  testing_timeline: {
    unit_security_tests: string;
    integration_security_tests: string;
    penetration_testing: string;
    compliance_audit: string;
  };
  recommendations: string[];
}

export async function designTestStrategy(
  input: TestStrategyInput
): Promise<ToolResponse> {
  // Use provided threats or generate default test cases based on risk level
  const threats = input.threats || [];
  const riskTolerance = input.risk_tolerance || input.risk_level || 'medium';

  logger.info('Designing security test strategy', {
    threats: threats.length,
    abuse_cases: input.abuse_cases?.length || 0,
    compliance: input.compliance_requirements?.length || 0,
    risk_tolerance: riskTolerance,
    project_name: input.project_name || 'Unnamed Project'
  });

  const testCases: SecurityTestCase[] = [];
  let testId = 1;

  // If no threats provided, generate default security test cases based on project/risk
  if (threats.length === 0) {
    // Add default OWASP-based test cases
    const defaultTests: SecurityTestCase[] = [
      {
        id: `TC-${testId++}`,
        category: 'Authentication',
        title: 'Verify authentication security controls',
        owasp_testing_guide: 'WSTG-ATHN-01 to WSTG-ATHN-10',
        priority: riskTolerance === 'high' || riskTolerance === 'critical' ? 'critical' : 'high',
        test_steps: [
          'Test for weak password policies',
          'Verify MFA enforcement',
          'Test session management',
          'Verify account lockout after failed attempts',
          'Test password reset functionality'
        ],
        expected_result: 'Strong authentication controls in place',
        automated: true,
        tools_required: ['Burp Suite', 'OWASP ZAP']
      },
      {
        id: `TC-${testId++}`,
        category: 'Authorization',
        title: 'Verify access control enforcement',
        owasp_testing_guide: 'WSTG-ATHZ-01 to WSTG-ATHZ-04',
        priority: 'high',
        test_steps: [
          'Test RBAC enforcement',
          'Verify horizontal privilege escalation prevention',
          'Test vertical privilege escalation prevention',
          'Verify IDOR (Insecure Direct Object Reference) prevention'
        ],
        expected_result: 'Access control properly enforced',
        automated: true,
        tools_required: ['Burp Suite', 'Postman']
      },
      {
        id: `TC-${testId++}`,
        category: 'Data Validation',
        title: 'Verify input validation and output encoding',
        owasp_testing_guide: 'WSTG-INPV-01 to WSTG-INPV-19',
        priority: 'high',
        test_steps: [
          'Test SQL injection vectors',
          'Test XSS (reflected, stored, DOM)',
          'Test command injection',
          'Verify output encoding',
          'Test file upload security'
        ],
        expected_result: 'All inputs validated, outputs properly encoded',
        automated: true,
        tools_required: ['SQLMap', 'XSStrike', 'OWASP ZAP']
      },
      {
        id: `TC-${testId++}`,
        category: 'Cryptography',
        title: 'Verify encryption implementation',
        owasp_testing_guide: 'WSTG-CRYP-01 to WSTG-CRYP-04',
        priority: 'high',
        test_steps: [
          'Verify TLS 1.2+ configuration',
          'Test certificate validation',
          'Verify encryption at rest',
          'Check for sensitive data exposure'
        ],
        expected_result: 'Strong encryption in transit and at rest',
        automated: true,
        tools_required: ['testssl.sh', 'SSLyze', 'Nmap']
      },
      {
        id: `TC-${testId++}`,
        category: 'Configuration',
        title: 'Verify security configuration',
        owasp_testing_guide: 'WSTG-CONF-01 to WSTG-CONF-11',
        priority: 'medium',
        test_steps: [
          'Check for default credentials',
          'Verify security headers (CSP, HSTS, X-Frame-Options)',
          'Test error handling',
          'Verify rate limiting',
          'Check for information disclosure'
        ],
        expected_result: 'Secure configuration with no unnecessary exposure',
        automated: true,
        tools_required: ['Nikto', 'OWASP ZAP', 'SecurityHeaders.com']
      }
    ];
    testCases.push(...defaultTests);
  }

  // Generate test cases from threat model
  for (const threat of threats) {
    // Handle flexible threat input formats (support both structured and manual input)
    const threatDescription = (threat as any).description || (threat as any).threat || 'security threat';
    const targetComponent = (threat as any).target_component || (threat as any).component || 'system';
    const threatImpact = (threat as any).impact?.toLowerCase() ||
      ((threat as any).severity?.toLowerCase() === 'critical' ? 'critical' :
        (threat as any).severity?.toLowerCase() === 'high' ? 'high' : 'medium');

    if (threat.category === 'Spoofing') {
      testCases.push({
        id: `TC-${testId++}`,
        category: 'Authentication',
        title: `Verify protection against ${threatDescription}`,
        threat_id: threat.id,
        owasp_testing_guide: 'WSTG-ATHN-01 to WSTG-ATHN-10',
        priority: threatImpact === 'critical' ? 'critical' : threatImpact === 'high' ? 'high' : 'medium',
        test_steps: [
          'Attempt authentication with invalid credentials',
          'Test for default/weak credentials',
          'Verify MFA enforcement',
          'Test session timeout behavior',
          'Attempt session fixation attack'
        ],
        expected_result: 'Authentication failures are properly handled, MFA enforced, sessions properly managed',
        automated: true,
        tools_required: ['Burp Suite', 'OWASP ZAP', 'Selenium']
      });
    }

    if (threat.category === 'Tampering' || threat.category === 'Elevation of Privilege') {
      testCases.push({
        id: `TC-${testId++}`,
        category: 'Authorization',
        title: `Verify access control for ${targetComponent}`,
        threat_id: threat.id,
        owasp_testing_guide: 'WSTG-ATHZ-01 to WSTG-ATHZ-04',
        priority: threatImpact === 'critical' ? 'critical' : 'high',
        test_steps: [
          'Verify RBAC enforcement',
          'Test horizontal privilege escalation',
          'Test vertical privilege escalation',
          'Verify resource-level permissions',
          'Test direct object reference vulnerabilities'
        ],
        expected_result: 'Access control enforced at all levels, privilege escalation prevented',
        automated: true,
        tools_required: ['Burp Suite', 'Postman', 'Custom scripts']
      });
    }

    if (threat.category === 'Information Disclosure') {
      testCases.push({
        id: `TC-${testId++}`,
        category: 'Cryptography',
        title: `Verify encryption for ${targetComponent}`,
        threat_id: threat.id,
        owasp_testing_guide: 'WSTG-CRYP-01 to WSTG-CRYP-04',
        priority: threatImpact === 'critical' ? 'critical' : 'high',
        test_steps: [
          'Verify TLS configuration (version, cipher suites)',
          'Test certificate validation',
          'Verify encryption at rest (database, files)',
          'Check for sensitive data in logs/errors',
          'Test data masking in UI'
        ],
        expected_result: 'All sensitive data encrypted in transit and at rest, no data leakage',
        automated: true,
        tools_required: ['SSLyze', 'testssl.sh', 'Nmap', 'Wireshark']
      });
    }

    if (threat.category === 'Denial of Service') {
      testCases.push({
        id: `TC-${testId++}`,
        category: 'Configuration',
        title: `Test DoS protections for ${targetComponent}`,
        threat_id: threat.id,
        owasp_testing_guide: 'WSTG-CONF-10',
        priority: threatImpact === 'high' ? 'high' : 'medium',
        test_steps: [
          'Load testing with high concurrency',
          'Test rate limiting per user/IP',
          'Verify resource quotas',
          'Test application-layer DoS (slowloris)',
          'Verify auto-scaling triggers'
        ],
        expected_result: 'Rate limiting active, resource quotas enforced, auto-scaling functional',
        automated: true,
        tools_required: ['JMeter', 'Locust', 'Artillery', 'Custom scripts']
      });
    }
  }

  // Generate test cases from abuse cases
  if (input.abuse_cases) {
    for (const abuseCase of input.abuse_cases) {
      testCases.push({
        id: `TC-${testId++}`,
        category: 'Data Validation',
        title: `Verify protection against ${abuseCase.attacker_goal}`,
        abuse_case_id: abuseCase.id,
        owasp_testing_guide: 'WSTG-INPV-01 to WSTG-INPV-19',
        priority: abuseCase.impact === 'critical' ? 'critical' : abuseCase.impact === 'high' ? 'high' : 'medium',
        test_steps: [
          'Test input validation for all user inputs',
          'Attempt SQL injection attacks',
          'Attempt XSS attacks (reflected, stored, DOM)',
          'Test command injection vectors',
          'Verify output encoding'
        ],
        expected_result: 'All inputs validated, injection attacks prevented, output properly encoded',
        automated: true,
        tools_required: ['Burp Suite', 'SQLMap', 'XSStrike', 'OWASP ZAP']
      });
    }
  }

  // Add compliance-specific tests
  if (input.compliance_requirements?.includes('GDPR')) {
    testCases.push({
      id: `TC-${testId++}`,
      category: 'Data Validation',
      title: 'Verify GDPR compliance (data protection)',
      owasp_testing_guide: 'WSTG-PRIV-01 to WSTG-PRIV-03',
      priority: 'critical',
      test_steps: [
        'Verify data minimization practices',
        'Test data deletion/anonymization features',
        'Verify consent management',
        'Test data export functionality',
        'Verify audit logging of data access'
      ],
      expected_result: 'GDPR requirements met: right to erasure, data portability, consent management',
      automated: false,
      tools_required: ['Manual testing', 'Database queries']
    });
  }

  if (input.compliance_requirements?.includes('PCI-DSS')) {
    testCases.push({
      id: `TC-${testId++}`,
      category: 'Cryptography',
      title: 'Verify PCI-DSS compliance (payment data security)',
      owasp_testing_guide: 'WSTG-CRYP-01, WSTG-CRYP-02',
      priority: 'critical',
      test_steps: [
        'Verify cardholder data encryption',
        'Test for PAN storage/logging',
        'Verify network segmentation',
        'Test access controls for payment systems',
        'Verify audit logging'
      ],
      expected_result: 'PCI-DSS requirements met: encryption, no PAN storage, segmentation',
      automated: false,
      tools_required: ['PCI scanning tool', 'Manual audit']
    });
  }

  // Penetration test plan
  const penetrationTestPlan: PenetrationTestChecklist[] = [
    {
      phase: 'Reconnaissance',
      tasks: [
        'Information gathering (OSINT)',
        'Subdomain enumeration',
        'Technology stack identification',
        'Network mapping'
      ]
    },
    {
      phase: 'Scanning & Enumeration',
      tasks: [
        'Port scanning',
        'Vulnerability scanning (Nessus, OpenVAS)',
        'Web application scanning (OWASP ZAP)',
        'Directory/file enumeration'
      ]
    },
    {
      phase: 'Exploitation',
      tasks: [
        'Attempt identified vulnerabilities',
        'Test for OWASP Top 10',
        'Business logic testing',
        'API security testing'
      ]
    },
    {
      phase: 'Post-Exploitation',
      tasks: [
        'Privilege escalation attempts',
        'Lateral movement testing',
        'Data exfiltration simulation',
        'Persistence mechanism testing'
      ]
    },
    {
      phase: 'Reporting',
      tasks: [
        'Document all findings',
        'Risk assessment and prioritization',
        'Remediation recommendations',
        'Executive summary'
      ]
    }
  ];

  // Calculate automation coverage
  const automatedTests = testCases.filter(tc => tc.automated).length;
  const automationCoverage = {
    total_tests: testCases.length,
    automated: automatedTests,
    manual: testCases.length - automatedTests,
    automation_percentage: Math.round((automatedTests / testCases.length) * 100)
  };

  // Testing timeline
  const testingTimeline = {
    unit_security_tests: 'Sprint 1-2 (Continuous)',
    integration_security_tests: 'Sprint 2-3',
    penetration_testing: 'Sprint 3 (External)',
    compliance_audit: 'Sprint 4 (Pre-production)'
  };

  const output: TestStrategyOutput = {
    test_cases: testCases,
    penetration_test_plan: penetrationTestPlan,
    automation_coverage: automationCoverage,
    testing_timeline: testingTimeline,
    recommendations: [
      `✅ ${automationCoverage.automation_percentage}% test automation coverage achieved`,
      '🔄 Integrate security tests into CI/CD pipeline',
      '🎯 Prioritize testing based on threat model risk scores',
      '📊 Track security testing metrics (vulnerabilities found, time to fix)',
      '🔒 Conduct penetration testing by external firm before production',
      '📝 Document all security test results for compliance evidence',
      '🔁 Re-test after each security fix implementation'
    ]
  };

  logger.success('Test strategy complete', {
    test_cases: output.test_cases.length,
    automation_coverage: `${output.automation_coverage.automation_percentage}%`,
    critical_tests: output.test_cases.filter(tc => tc.priority === 'critical').length
  });

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(output, null, 2)
      }
    ]
  };
}

function formatTestStrategyOutput(output: TestStrategyOutput): string {
  let report = `# 🧪 Security Test Strategy\n\n`;

  report += `## 📊 Automation Coverage\n\n`;
  report += `**Total Test Cases:** ${output.automation_coverage.total_tests}  \n`;
  report += `**Automated:** ${output.automation_coverage.automated} (${output.automation_coverage.automation_percentage}%)  \n`;
  report += `**Manual:** ${output.automation_coverage.manual}  \n\n`;

  report += `## 🎯 Security Test Cases\n\n`;

  // Group by category
  const categories = ['Authentication', 'Authorization', 'Data Validation', 'Cryptography', 'Session Management', 'Error Handling', 'Configuration', 'Network Security'];
  categories.forEach(category => {
    const categoryTests = output.test_cases.filter(tc => tc.category === category);
    if (categoryTests.length === 0) return;

    report += `### ${category} (${categoryTests.length} tests)\n\n`;
    categoryTests.forEach(test => {
      const priorityIcon = test.priority === 'critical' ? '🔴' :
        test.priority === 'high' ? '🟠' :
          test.priority === 'medium' ? '🟡' : '🟢';
      report += `#### ${test.id}: ${test.title}\n\n`;
      report += `${priorityIcon} **Priority:** ${test.priority.toUpperCase()} | **Automated:** ${test.automated ? '✅ Yes' : '❌ No'}\n\n`;
      if (test.threat_id) report += `**Linked Threat:** ${test.threat_id}  \n`;
      if (test.abuse_case_id) report += `**Linked Abuse Case:** ${test.abuse_case_id}  \n`;
      report += `**OWASP Testing Guide:** ${test.owasp_testing_guide}  \n\n`;
      report += `**Test Steps:**\n`;
      test.test_steps.forEach(step => report += `1. ${step}\n`);
      report += `\n**Expected Result:** ${test.expected_result}\n\n`;
      report += `**Tools Required:** ${test.tools_required.join(', ')}\n\n`;
    });
  });

  report += `## 🎯 Penetration Test Plan\n\n`;
  output.penetration_test_plan.forEach(phase => {
    report += `### ${phase.phase}\n\n`;
    phase.tasks.forEach(task => report += `- ${task}\n`);
    report += `\n`;
  });

  report += `## 📅 Testing Timeline\n\n`;
  report += `| Testing Phase | Timeline |\n`;
  report += `|--------------|----------|\n`;
  report += `| Unit Security Tests | ${output.testing_timeline.unit_security_tests} |\n`;
  report += `| Integration Security Tests | ${output.testing_timeline.integration_security_tests} |\n`;
  report += `| Penetration Testing | ${output.testing_timeline.penetration_testing} |\n`;
  report += `| Compliance Audit | ${output.testing_timeline.compliance_audit} |\n\n`;

  report += `## 💡 Recommendations\n\n`;
  output.recommendations.forEach(rec => report += `${rec}\n`);

  return report;
}
