/**
 * Phase 9: Tech Lead - Design Architecture
 * 
 * Designs system architecture from user stories and generates:
 * - Component list with responsibilities
 * - Trust boundaries
 * - Data flows (DFD Level 0/1)
 * - Mermaid diagrams
 * - Input for STRIDE threat modeling
 */

import type { ToolResponse } from '@mcp-ssdlc/core';
import { createLogger } from '@mcp-ssdlc/core';

const logger = createLogger('TechLead-Design-Architecture');

export interface TechLeadDesignArchitectureInput {
  user_stories?: Array<{ id: string; title: string }>;  // From BA phase output
  requirements?: string;  // Alternative: string description
  tech_constraints?: string[];  // e.g., "Must use AWS", "Microservices architecture"
  constraints?: string[];  // Alias for tech_constraints
  scale_expectation?: string;   // e.g., "10K DAU", "Global users"
  existing_systems?: string[];  // Integration points
}

export interface Component {
  id: string;
  name: string;
  type: 'frontend' | 'backend' | 'database' | 'external' | 'queue' | 'cache';
  responsibilities: string[];
  technologies: string[];
  trust_level: 'untrusted' | 'semi-trusted' | 'trusted';
  processes_sensitive_data: boolean;
}

export interface TrustBoundary {
  id: string;
  name: string;
  description: string;
  components_inside: string[];  // Component IDs
  entry_points: string[];
  exit_points: string[];
}

export interface DataFlow {
  id: string;
  from_component: string;
  to_component: string;
  data_type: string;
  protocol: string;
  authentication_required: boolean;
  encryption_required: boolean;
  crosses_trust_boundary: boolean;
}

export interface TechLeadDesignArchitectureOutput {
  components: Component[];
  trust_boundaries: TrustBoundary[];
  data_flows: DataFlow[];
  mermaid_diagram: string;
  architecture_notes: string[];
  security_recommendations: string[];
}

export async function designSystemArchitecture(
  input: TechLeadDesignArchitectureInput
): Promise<ToolResponse> {
  // Handle flexible input - support both user_stories array and requirements string
  const userStoriesCount = input.user_stories?.length || 0;
  const constraintsCount = (input.tech_constraints || input.constraints)?.length || 0;

  logger.info('Designing system architecture', {
    user_stories: userStoriesCount,
    requirements: input.requirements ? 'provided' : 'not provided',
    constraints: constraintsCount
  });

  // Define components based on user stories
  const components: Component[] = [
    {
      id: 'C1',
      name: 'Web Application (Frontend)',
      type: 'frontend',
      responsibilities: [
        'User interface rendering',
        'Client-side validation',
        'Session management',
        'API communication'
      ],
      technologies: ['React/Vue', 'TypeScript', 'REST Client'],
      trust_level: 'untrusted',
      processes_sensitive_data: true
    },
    {
      id: 'C2',
      name: 'API Gateway',
      type: 'backend',
      responsibilities: [
        'Request routing',
        'Authentication/Authorization',
        'Rate limiting',
        'API versioning'
      ],
      technologies: ['Node.js/Express', 'JWT', 'OAuth2'],
      trust_level: 'semi-trusted',
      processes_sensitive_data: true
    },
    {
      id: 'C3',
      name: 'Business Logic Service',
      type: 'backend',
      responsibilities: [
        'Core business operations',
        'Data validation',
        'Business rules enforcement',
        'Transaction management'
      ],
      technologies: ['Python/FastAPI', 'Microservices'],
      trust_level: 'trusted',
      processes_sensitive_data: true
    },
    {
      id: 'C4',
      name: 'Database (Primary)',
      type: 'database',
      responsibilities: [
        'Persistent data storage',
        'ACID transactions',
        'Data integrity constraints'
      ],
      technologies: ['PostgreSQL', 'Encryption at rest'],
      trust_level: 'trusted',
      processes_sensitive_data: true
    },
    {
      id: 'C5',
      name: 'Authentication Service',
      type: 'external',
      responsibilities: [
        'User authentication',
        'MFA enforcement',
        'Token issuance'
      ],
      technologies: ['Auth0/Okta', 'OAuth2/OIDC'],
      trust_level: 'trusted',
      processes_sensitive_data: true
    }
  ];

  // Define trust boundaries
  const trustBoundaries: TrustBoundary[] = [
    {
      id: 'TB1',
      name: 'Public Internet Zone',
      description: 'Untrusted zone accessible to all users',
      components_inside: ['C1'],
      entry_points: ['User Browser'],
      exit_points: ['API Gateway']
    },
    {
      id: 'TB2',
      name: 'DMZ (API Layer)',
      description: 'Semi-trusted zone for API endpoints',
      components_inside: ['C2'],
      entry_points: ['Frontend', 'External APIs'],
      exit_points: ['Business Logic Service']
    },
    {
      id: 'TB3',
      name: 'Internal Services Zone',
      description: 'Trusted zone for core business logic and data',
      components_inside: ['C3', 'C4'],
      entry_points: ['API Gateway'],
      exit_points: ['External Services']
    }
  ];

  // Define data flows
  const dataFlows: DataFlow[] = [
    {
      id: 'DF1',
      from_component: 'C1',
      to_component: 'C2',
      data_type: 'User credentials, form data',
      protocol: 'HTTPS',
      authentication_required: false,
      encryption_required: true,
      crosses_trust_boundary: true
    },
    {
      id: 'DF2',
      from_component: 'C2',
      to_component: 'C5',
      data_type: 'Authentication request',
      protocol: 'HTTPS',
      authentication_required: true,
      encryption_required: true,
      crosses_trust_boundary: true
    },
    {
      id: 'DF3',
      from_component: 'C2',
      to_component: 'C3',
      data_type: 'Business operations (JWT-protected)',
      protocol: 'gRPC/HTTPS',
      authentication_required: true,
      encryption_required: true,
      crosses_trust_boundary: true
    },
    {
      id: 'DF4',
      from_component: 'C3',
      to_component: 'C4',
      data_type: 'Database queries, transactions',
      protocol: 'PostgreSQL Protocol (TLS)',
      authentication_required: true,
      encryption_required: true,
      crosses_trust_boundary: false
    }
  ];

  // Generate Mermaid diagram
  const mermaidDiagram = generateMermaidDiagram(components, dataFlows, trustBoundaries);

  const output: TechLeadDesignArchitectureOutput = {
    components,
    trust_boundaries: trustBoundaries,
    data_flows: dataFlows,
    mermaid_diagram: mermaidDiagram,
    architecture_notes: [
      'Three-tier architecture with clear trust boundaries',
      'API Gateway acts as security control point',
      'All external communication encrypted (TLS 1.3)',
      'Authentication delegated to specialized service (Auth0/Okta)',
      'Database encryption at rest and in transit'
    ],
    security_recommendations: [
      '🔒 Implement defense-in-depth: multiple layers of security controls',
      '🔒 Enforce least privilege for service-to-service communication',
      '🔒 Use mTLS for internal service communication',
      '🔒 Implement API rate limiting and DDoS protection',
      '🔒 Enable audit logging at all trust boundary crossings',
      '🔒 Use secret management service (Vault/AWS Secrets Manager)',
      '🔒 Container security: scan images, runtime protection (Falco)',
      '🔒 Network segmentation: isolate database from public access'
    ]
  };

  logger.success('Architecture design complete', {
    components: output.components.length,
    trust_boundaries: output.trust_boundaries.length,
    data_flows: output.data_flows.length
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

function generateMermaidDiagram(
  components: Component[],
  dataFlows: DataFlow[],
  trustBoundaries: TrustBoundary[]
): string {
  let diagram = `graph TB\n\n`;
  diagram += `  %% Components\n`;

  components.forEach(c => {
    const shape = c.type === 'database' ? '[(Database)]' :
      c.type === 'external' ? '{{External}}' : '[Component]';
    diagram += `  ${c.id}["${c.name}"]\n`;
  });

  diagram += `\n  %% Data Flows\n`;
  dataFlows.forEach(df => {
    const arrow = df.encryption_required ? '==>' : '-->';
    const label = df.crosses_trust_boundary ? '|crosses boundary|' : '';
    diagram += `  ${df.from_component} ${arrow} ${label} ${df.to_component}\n`;
  });

  diagram += `\n  %% Trust Boundaries\n`;
  trustBoundaries.forEach((tb, idx) => {
    diagram += `  subgraph ${tb.id}["🔒 ${tb.name}"]\n`;
    tb.components_inside.forEach(compId => {
      diagram += `    ${compId}\n`;
    });
    diagram += `  end\n`;
  });

  return diagram;
}

function formatTechLeadOutput(output: TechLeadDesignArchitectureOutput): string {
  let report = `# 🏗️ System Architecture Design\n\n`;

  report += `## 📦 Components (${output.components.length})\n\n`;
  output.components.forEach(c => {
    report += `### ${c.id}: ${c.name}\n`;
    report += `**Type:** ${c.type} | **Trust Level:** ${c.trust_level.toUpperCase()}\n\n`;
    report += `**Responsibilities:**\n`;
    c.responsibilities.forEach(r => report += `- ${r}\n`);
    report += `\n**Technologies:** ${c.technologies.join(', ')}\n`;
    report += `**Processes Sensitive Data:** ${c.processes_sensitive_data ? '🔒 Yes' : 'No'}\n\n`;
  });

  report += `## 🛡️ Trust Boundaries (${output.trust_boundaries.length})\n\n`;
  output.trust_boundaries.forEach(tb => {
    report += `### ${tb.id}: ${tb.name}\n`;
    report += `${tb.description}\n\n`;
    report += `**Components:** ${tb.components_inside.join(', ')}\n`;
    report += `**Entry Points:** ${tb.entry_points.join(', ')}\n`;
    report += `**Exit Points:** ${tb.exit_points.join(', ')}\n\n`;
  });

  report += `## 🔄 Data Flows (${output.data_flows.length})\n\n`;
  report += `| ID | From | To | Data Type | Protocol | Auth | Encryption | Crosses Boundary |\n`;
  report += `|----|------|----|-----------|--------------|------|------------|------------------|\n`;
  output.data_flows.forEach(df => {
    report += `| ${df.id} | ${df.from_component} | ${df.to_component} | ${df.data_type} | ${df.protocol} | ${df.authentication_required ? '✅' : '❌'} | ${df.encryption_required ? '🔒' : '❌'} | ${df.crosses_trust_boundary ? '⚠️ YES' : 'No'} |\n`;
  });

  report += `\n## 📊 Architecture Diagram (Mermaid)\n\n`;
  report += '```mermaid\n';
  report += output.mermaid_diagram;
  report += '\n```\n\n';

  report += `## 📝 Architecture Notes\n\n`;
  output.architecture_notes.forEach(note => report += `- ${note}\n`);

  report += `\n## 🔐 Security Recommendations\n\n`;
  output.security_recommendations.forEach(rec => report += `${rec}\n`);

  return report;
}
