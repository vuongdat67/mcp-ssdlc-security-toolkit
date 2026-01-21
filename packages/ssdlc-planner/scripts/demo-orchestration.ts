/**
 * Demo: Full SSDLC Orchestration
 * 
 * Demonstrates Phase 9-11 workflow:
 * BA → Tech Lead → Security → QA
 */

import { analyzeBusinessRequirements } from "../src/tools/business-analyst/analyze-requirements.js";
import { designSystemArchitecture } from "../src/tools/tech-lead/design-architecture.js";
import { threatModelArchitecture } from "../src/tools/security/threat-model.js";
import { designTestStrategy } from "../src/tools/qa/design-test-strategy.js";

console.log("🚀 MCP SSDLC Orchestration Demo\n");
console.log("=" .repeat(60));
console.log("Project: E-commerce Platform with Payment Processing");
console.log("=" .repeat(60) + "\n");

// Phase 9A: Business Analyst - Requirements Analysis
console.log("📋 Phase 9A: Business Analyst - Requirements Analysis\n");

const baInput = {
  project_description: "Build an e-commerce platform with user authentication, product catalog, shopping cart, and payment processing. Must support 10K concurrent users and comply with PCI-DSS.",
  users: ["Customer", "Admin", "Payment Processor"],
  business_goals: [
    "Enable secure online purchases",
    "Protect customer payment data",
    "Provide admin dashboard for inventory",
    "Ensure 99.9% uptime"
  ],
  compliance_requirements: ["PCI-DSS", "GDPR"],
  security_concerns: [
    "Payment card data theft",
    "Unauthorized access to admin functions",
    "SQL injection in product search"
  ]
};

const baOutput = await analyzeBusinessRequirements(baInput);
console.log(baOutput.content[0].text);
console.log("\n" + "=".repeat(60) + "\n");

// Extract user stories from BA output
const baText = baOutput.content[0].text;
const userStoriesMatch = baText.match(/## 📖 User Stories([\s\S]*?)(?=##|$)/);
const userStoriesText = userStoriesMatch ? userStoriesMatch[1] : '';

// Parse user stories (simplified)
const mockUserStories = [
  {
    id: 'US-1',
    title: 'User authentication',
    description: 'As a Customer, I want to login securely',
    acceptance_criteria: ['MFA required', 'Session timeout'],
    security_notes: ['Spoofing threats', 'Session management']
  },
  {
    id: 'US-2',
    title: 'Payment processing',
    description: 'As a Customer, I want to pay securely',
    acceptance_criteria: ['PCI-DSS compliant', 'Encrypted transmission'],
    security_notes: ['Data encryption', 'Payment validation']
  }
];

// Phase 9B: Tech Lead - Architecture Design
console.log("🏗️ Phase 9B: Tech Lead - Architecture Design\n");

const techLeadInput = {
  user_stories: mockUserStories,
  tech_constraints: ["AWS infrastructure", "Microservices architecture"],
  scale_expectation: "10K concurrent users",
  existing_systems: ["Stripe payment gateway", "AWS Cognito for auth"]
};

const techLeadOutput = await designSystemArchitecture(techLeadInput);
console.log(techLeadOutput.content[0].text);
console.log("\n" + "=".repeat(60) + "\n");

// Extract architecture from Tech Lead output
const techLeadText = techLeadOutput.content[0].text;

// Parse architecture (use actual output structure)
const mockComponents = [
  {
    id: 'C1',
    name: 'Web Application',
    type: 'frontend',
    trust_level: 'untrusted',
    processes_sensitive_data: false
  },
  {
    id: 'C2',
    name: 'API Gateway',
    type: 'backend',
    trust_level: 'semi-trusted',
    processes_sensitive_data: false
  },
  {
    id: 'C3',
    name: 'Payment Service',
    type: 'backend',
    trust_level: 'trusted',
    processes_sensitive_data: true
  },
  {
    id: 'C4',
    name: 'Database',
    type: 'database',
    trust_level: 'trusted',
    processes_sensitive_data: true
  }
];

const mockDataFlows = [
  {
    id: 'DF1',
    from_component: 'C1',
    to_component: 'C2',
    protocol: 'HTTPS',
    crosses_trust_boundary: true,
    encryption_required: true,
    authentication_required: true
  },
  {
    id: 'DF2',
    from_component: 'C2',
    to_component: 'C3',
    protocol: 'gRPC',
    crosses_trust_boundary: false,
    encryption_required: true,
    authentication_required: true
  },
  {
    id: 'DF3',
    from_component: 'C3',
    to_component: 'C4',
    protocol: 'PostgreSQL/TLS',
    crosses_trust_boundary: false,
    encryption_required: true,
    authentication_required: true
  }
];

const mockTrustBoundaries = [
  { id: 'TB1', name: 'Public Internet Zone', trust_level: 'untrusted' },
  { id: 'TB2', name: 'DMZ/API Layer', trust_level: 'semi-trusted' },
  { id: 'TB3', name: 'Internal Services', trust_level: 'trusted' }
];

// Phase 10: Security - STRIDE Threat Modeling
console.log("🛡️ Phase 10: Security - STRIDE Threat Modeling\n");

const securityInput = {
  components: mockComponents,
  data_flows: mockDataFlows,
  trust_boundaries: mockTrustBoundaries
};

const securityOutput = await threatModelArchitecture(securityInput);
console.log(securityOutput.content[0].text);
console.log("\n" + "=".repeat(60) + "\n");

// Extract threats from Security output
const securityText = securityOutput.content[0].text;
const threatsMatch = securityText.match(/Total Threats Identified:\*\* (\d+)/);
const totalThreats = threatsMatch ? parseInt(threatsMatch[1]) : 0;

// Parse threats (use actual structure from threat-model.ts)
const mockThreats = [
  {
    id: 'T-1',
    category: 'Spoofing' as const,
    target_component: 'C1',
    description: 'Attacker impersonates legitimate user',
    cwe_id: 'CWE-287',
    cwe_name: 'Improper Authentication',
    owasp_category: 'A07',
    cvss_score: 8.1,
    exploited_in_wild: true,
    risk_score: 8.5,
    likelihood: 'high' as const,
    impact: 'critical' as const,
    mitigation_strategy: ['Implement MFA', 'Use OAuth2/OIDC'],
    testing_approach: ['Attempt authentication bypass', 'Test weak passwords']
  },
  {
    id: 'T-2',
    category: 'Information Disclosure' as const,
    target_component: 'C3',
    description: 'Payment data leaked from Payment Service',
    cwe_id: 'CWE-200',
    cwe_name: 'Exposure of Sensitive Information',
    owasp_category: 'A01',
    cvss_score: 6.5,
    exploited_in_wild: false,
    risk_score: 6.5,
    likelihood: 'medium' as const,
    impact: 'high' as const,
    mitigation_strategy: ['Encrypt at rest (AES-256)', 'Encrypt in transit (TLS 1.3)'],
    testing_approach: ['Verify encryption', 'Check error messages']
  }
];

// Phase 11: QA - Design Test Strategy
console.log("🧪 Phase 11: QA - Design Test Strategy\n");

const qaInput = {
  threats: mockThreats,
  compliance_requirements: ["PCI-DSS", "GDPR"],
  risk_tolerance: 'low' as const
};

const qaOutput = await designTestStrategy(qaInput);
console.log(qaOutput.content[0].text);
console.log("\n" + "=".repeat(60) + "\n");

// Summary
console.log("✅ SSDLC Orchestration Complete!\n");
console.log("📊 Summary:");
console.log(`  - User Stories: ${mockUserStories.length}`);
console.log(`  - Components: ${mockComponents.length}`);
console.log(`  - Trust Boundaries: ${mockTrustBoundaries.length}`);
console.log(`  - Data Flows: ${mockDataFlows.length}`);
console.log(`  - Threats Identified: ${totalThreats}`);
console.log(`  - Test Cases Generated: Check QA output\n`);

console.log("🎯 Next Steps:");
console.log("  1. Review threat model and prioritize mitigations");
console.log("  2. Implement security test cases in CI/CD");
console.log("  3. Schedule external penetration testing");
console.log("  4. Create sprint plan with PM tool (Phase 12)\n");
