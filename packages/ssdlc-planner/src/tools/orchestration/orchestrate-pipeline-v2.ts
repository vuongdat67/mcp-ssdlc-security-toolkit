/**
 * MCP-CORRECT SSDLC Pipeline Orchestrator
 * 
 * This tool generates an execution PLAN for Claude to execute step-by-step.
 * It does NOT call other tools directly (that would be function chaining, not MCP orchestration).
 * 
 * MCP Orchestration Model:
 * 1. Orchestrator creates structured plan (JSON)
 * 2. Claude reads plan and executes each phase
 * 3. Claude passes output from phase N to phase N+1
 * 4. No tool-to-tool direct calls
 * 
 * Philosophy: Orchestrator = Plan Generator, Claude = Executor
 */

import type { MCPToolResult } from '@mcp-ssdlc/core';
import { createLogger } from '@mcp-ssdlc/core';

const logger = createLogger('SSDLC-Orchestrator');

// ============================================================================
// Types
// ============================================================================

export interface PipelineInput {
  project_name: string;
  project_description: string;
  business_goals: string[];
  stakeholders?: string[];
  tech_stack: string[];
  team_size: number;
  sprint_duration: number; // weeks
  deployment_target?: 'kubernetes' | 'docker' | 'vm' | 'serverless';
  repository_platform?: 'github' | 'gitlab' | 'azure-devops' | 'bitbucket';
  compliance_requirements?: string[];
}

export interface PhaseDefinition {
  phase_number: number;
  phase_name: string;
  role: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
  depends_on: string[] | null; // Which phases this depends on
  expected_output: {
    description: string;
    required_fields: string[];
    format: 'json';
  };
  success_criteria: {
    coverage_target: string;
    quality_gates: string[];
  };
}

export interface OrchestrationPlan {
  orchestration_id: string;
  project_name: string;
  created_at: string;
  phases: PhaseDefinition[];
  execution_instructions: string;
  coverage_targets: {
    requirements: string;
    security: string;
    architecture: string;
    pseudocode: string;
    testing: string;
    overall: string;
  };
  quality_gates: {
    phase_1: string[];
    phase_2: string[];
    phase_3: string[];
    phase_4: string[];
    phase_5: string[];
    phase_6: string[];
    phase_7: string[];
  };
  success_criteria: string[];
}

// ============================================================================
// Plan Generator
// ============================================================================

export async function orchestrateSSDLCPipeline(args: unknown): Promise<MCPToolResult> {
  logger.info('Generating SSDLC orchestration plan...');

  // Validate input
  const input = args as PipelineInput;
  
  if (!input.project_name || !input.project_description || !input.business_goals) {
    throw new Error('Missing required fields: project_name, project_description, business_goals');
  }

  // Generate orchestration plan
  const plan: OrchestrationPlan = {
    orchestration_id: `ssdlc-${Date.now()}`,
    project_name: input.project_name,
    created_at: new Date().toISOString(),
    
    phases: [
      // =================================================================
      // Phase 1: Business Analysis & Security Requirements
      // =================================================================
      {
        phase_number: 1,
        phase_name: 'Business Analysis & Security Requirements',
        role: 'Business Analyst',
        tool_name: 'ba_analyze_requirements',
        tool_input: {
          project_name: input.project_name,
          project_description: input.project_description,
          business_goals: input.business_goals,
          stakeholders: input.stakeholders || [
            'End Users',
            'Business Stakeholders',
            'Development Team',
            'Security Team',
            'Compliance Officers'
          ]
        },
        depends_on: null,
        expected_output: {
          description: 'User stories with acceptance criteria, prioritization matrix, and security requirements',
          required_fields: [
            'user_stories',
            'prioritization_matrix',
            'security_requirements'
          ],
          format: 'json'
        },
        success_criteria: {
          coverage_target: '90-95% of functional and security requirements',
          quality_gates: [
            'All user stories have acceptance criteria',
            'Security requirements mapped to HIPAA/GDPR/PCI-DSS (if applicable)',
            'Prioritization matrix includes security impact scores'
          ]
        }
      },

      // =================================================================
      // Phase 2: Architecture Design
      // =================================================================
      {
        phase_number: 2,
        phase_name: 'Architecture Design',
        role: 'Tech Lead',
        tool_name: 'techlead_design_architecture',
        tool_input: {
          requirements: `{{PHASE_1_OUTPUT.user_stories}} + {{PHASE_1_OUTPUT.security_requirements}}`,
          constraints: [
            `Tech stack: ${input.tech_stack.join(', ')}`,
            `Team size: ${input.team_size}`,
            `Deployment: ${input.deployment_target || 'kubernetes'}`,
            ...(input.compliance_requirements || [])
          ]
        },
        depends_on: ['Phase 1'],
        expected_output: {
          description: 'System architecture with components, trust boundaries, data flows, and Mermaid diagram',
          required_fields: [
            'components',
            'trust_boundaries',
            'data_flows',
            'mermaid_diagram'
          ],
          format: 'json'
        },
        success_criteria: {
          coverage_target: '85-90% of architectural decisions documented',
          quality_gates: [
            'All components have security boundaries defined',
            'Data flows show encryption points',
            'Trust boundaries clearly marked'
          ]
        }
      },

      // =================================================================
      // Phase 3: Security Threat Modeling (STRIDE)
      // =================================================================
      {
        phase_number: 3,
        phase_name: 'Security Threat Modeling',
        role: 'Security Engineer',
        tool_name: 'security_threat_model',
        tool_input: {
          project_name: input.project_name,
          components: '{{PHASE_2_OUTPUT.components}}',
          tech_stack: input.tech_stack,
          compliance_requirements: input.compliance_requirements || []
        },
        depends_on: ['Phase 2'],
        expected_output: {
          description: 'STRIDE analysis with threats, mitigations, and CVE mappings',
          required_fields: [
            'threats',
            'mitigations',
            'risk_matrix'
          ],
          format: 'json'
        },
        success_criteria: {
          coverage_target: '85-95% of STRIDE categories covered',
          quality_gates: [
            'All threats have severity scores',
            'All high/critical threats have mitigations',
            'Mitigations reference CWE/CVE where applicable'
          ]
        }
      },

      // =================================================================
      // Phase 4: Pseudocode Generation
      // =================================================================
      {
        phase_number: 4,
        phase_name: 'Pseudocode Generation',
        role: 'Tech Lead',
        tool_name: 'techlead_generate_pseudocode',
        tool_input: {
          function_name: '{{EXTRACT_CRITICAL_FUNCTIONS_FROM_PHASE_2_AND_3}}',
          description: '{{FUNCTION_DESCRIPTION}}',
          language: input.tech_stack[0] || 'python',
          security_considerations: '{{PHASE_3_OUTPUT.relevant_threats}}'
        },
        depends_on: ['Phase 2', 'Phase 3'],
        expected_output: {
          description: 'Pseudocode for critical functions with security annotations',
          required_fields: [
            'function_signature',
            'pseudocode',
            'security_notes'
          ],
          format: 'json'
        },
        success_criteria: {
          coverage_target: '80-90% of critical security-sensitive functions',
          quality_gates: [
            'All functions have input validation',
            'All functions have error handling',
            'Security considerations documented inline'
          ]
        }
      },

      // =================================================================
      // Phase 5: QA Test Strategy & Test Cases
      // =================================================================
      {
        phase_number: 5,
        phase_name: 'QA Test Strategy',
        role: 'QA Engineer',
        tool_name: 'qa_generate_test_cases',
        tool_input: {
          project_name: input.project_name,
          user_stories: '{{PHASE_1_OUTPUT.user_stories}}',
          threats: '{{PHASE_3_OUTPUT.threats}}',
          tech_stack: input.tech_stack
        },
        depends_on: ['Phase 1', 'Phase 3'],
        expected_output: {
          description: 'Comprehensive test cases including functional, security, and penetration tests',
          required_fields: [
            'test_cases',
            'penetration_test_plan',
            'automation_coverage'
          ],
          format: 'json'
        },
        success_criteria: {
          coverage_target: '85-90% of requirements and threats covered by test cases',
          quality_gates: [
            'All user stories have test cases',
            'All high/critical threats have security test cases',
            'Penetration test plan includes OWASP Top 10'
          ]
        }
      },

      // =================================================================
      // Phase 6: Sprint Planning
      // =================================================================
      {
        phase_number: 6,
        phase_name: 'Sprint Planning',
        role: 'Project Manager',
        tool_name: 'pm_create_sprint_plan',
        tool_input: {
          project_name: input.project_name,
          user_stories: '{{PHASE_1_OUTPUT.user_stories}}',
          architecture: '{{PHASE_2_OUTPUT}}',
          team_size: input.team_size,
          sprint_duration: input.sprint_duration
        },
        depends_on: ['Phase 1', 'Phase 2', 'Phase 4'],
        expected_output: {
          description: 'Sprint breakdown with story points, timeline, and resource allocation',
          required_fields: [
            'sprints',
            'timeline',
            'resource_allocation'
          ],
          format: 'json'
        },
        success_criteria: {
          coverage_target: '100% of user stories allocated to sprints',
          quality_gates: [
            'Security-critical stories prioritized in early sprints',
            'Story points balanced across sprints',
            'Dependencies identified and sequenced'
          ]
        }
      },

      // =================================================================
      // Phase 7: CI/CD Pipeline Design
      // =================================================================
      {
        phase_number: 7,
        phase_name: 'CI/CD Pipeline Design',
        role: 'DevOps Engineer',
        tool_name: 'devops_design_cicd',
        tool_input: {
          project_name: input.project_name,
          tech_stack: input.tech_stack,
          deployment_target: input.deployment_target || 'kubernetes',
          repository_platform: input.repository_platform || 'github',
          security_requirements: '{{PHASE_3_OUTPUT.mitigations}}'
        },
        depends_on: ['Phase 1', 'Phase 2', 'Phase 3', 'Phase 4', 'Phase 5', 'Phase 6'],
        expected_output: {
          description: 'CI/CD pipeline with security gates (SAST, DAST, dependency scanning)',
          required_fields: [
            'pipeline_stages',
            'security_gates',
            'deployment_strategy'
          ],
          format: 'json'
        },
        success_criteria: {
          coverage_target: '100% of security gates implemented',
          quality_gates: [
            'SAST scan in every PR',
            'DAST scan before production deployment',
            'Dependency scanning daily',
            'Secret scanning enabled'
          ]
        }
      }
    ],

    // =====================================================================
    // Execution Instructions for Claude
    // =====================================================================
    execution_instructions: `
# 🎯 SSDLC Pipeline Execution Instructions

## Overview
This plan contains **7 phases** that must be executed **sequentially**.
Each phase depends on the output of previous phases.

## Execution Protocol

### For Each Phase:

1. **Read the phase definition** (tool_name, tool_input, depends_on)
2. **Replace placeholders** in tool_input with actual data from previous phases:
   - \`{{PHASE_1_OUTPUT.user_stories}}\` → Actual user stories from Phase 1
   - \`{{PHASE_2_OUTPUT.components}}\` → Actual components from Phase 2
   - etc.
3. **Call the MCP tool** with the resolved input
4. **Validate the output** against expected_output.required_fields
5. **Check quality gates** in success_criteria
6. **Store the output** for use in subsequent phases
7. **Proceed to next phase**

### Error Handling:

- If a tool returns **non-JSON**, stop and report error
- If output **missing required_fields**, request retry with explicit JSON schema
- If **quality gates fail**, note the gap but continue (report at end)

### Output Format:

Each tool **MUST** return:
\`\`\`json
{
  "content": [{
    "type": "text",
    "text": "{\\"field1\\": \\"value1\\", ...}"  // STRICT JSON, no markdown
  }]
}
\`\`\`

### Coverage Validation:

After all phases complete, verify:
- Requirements coverage: ${input.business_goals.length} goals covered
- Security coverage: STRIDE categories analyzed
- Test coverage: Functional + Security test cases generated
- Overall coverage: 85-95% target met

## Example Execution Flow:

\`\`\`
1. Call ba_analyze_requirements
   → Get user_stories[], security_requirements[]
   
2. Call techlead_design_architecture with:
   {
     "requirements": "<user_stories + security_requirements from Phase 1>"
   }
   → Get components[], trust_boundaries[]
   
3. Call security_threat_model with:
   {
     "components": "<components from Phase 2>"
   }
   → Get threats[], mitigations[]
   
... continue for all 7 phases
\`\`\`

## Final Deliverable:

After completing all phases, generate a **summary report** with:
- ✅ Phases completed
- 📊 Coverage metrics
- ⚠️ Quality gate failures (if any)
- 📁 Artifacts generated (user stories, architecture, threats, tests, etc.)
`,

    // =====================================================================
    // Coverage Targets
    // =====================================================================
    coverage_targets: {
      requirements: '90-95% (all business goals + security requirements documented)',
      security: '85-95% (STRIDE categories + mitigations)',
      architecture: '85-90% (components + boundaries + data flows)',
      pseudocode: '80-90% (critical security-sensitive functions)',
      testing: '85-90% (functional + security test cases)',
      overall: '85-95% (comprehensive SSDLC planning coverage)'
    },

    // =====================================================================
    // Quality Gates (per phase)
    // =====================================================================
    quality_gates: {
      phase_1: [
        'All user stories have acceptance criteria',
        'Security requirements mapped to compliance standards',
        'Prioritization matrix includes security impact scores'
      ],
      phase_2: [
        'All components have security boundaries defined',
        'Data flows show encryption points',
        'Trust boundaries clearly marked'
      ],
      phase_3: [
        'All STRIDE categories analyzed',
        'All high/critical threats have mitigations',
        'Mitigations reference CWE/CVE where applicable'
      ],
      phase_4: [
        'All critical functions have input validation',
        'All functions have error handling',
        'Security considerations documented inline'
      ],
      phase_5: [
        'All user stories have test cases',
        'All high/critical threats have security test cases',
        'Penetration test plan includes OWASP Top 10'
      ],
      phase_6: [
        'Security-critical stories prioritized',
        'Story points balanced across sprints',
        'Dependencies identified and sequenced'
      ],
      phase_7: [
        'SAST scan in every PR',
        'DAST scan before production deployment',
        'Dependency scanning enabled',
        'Secret scanning enabled'
      ]
    },

    // =====================================================================
    // Success Criteria
    // =====================================================================
    success_criteria: [
      'All 7 phases executed successfully',
      'All phase outputs validated (required fields present)',
      'All high/critical threats have mitigations',
      'All user stories have test cases',
      'CI/CD pipeline includes SAST + DAST + dependency scanning',
      'Sprint plan allocates all user stories',
      'Overall coverage ≥ 85%'
    ]
  };

  // Log plan generation
  logger.success(`Generated orchestration plan with ${plan.phases.length} phases`);

  // Return the PLAN (not execution results)
  return {
    content: [{
      type: 'text',
      text: JSON.stringify(plan, null, 2)
    }]
  };
}

// ============================================================================
// Tool Registration Metadata
// ============================================================================

export const orchestrateSSDLCPipelineTool = {
  name: 'orchestrate_ssdlc_pipeline',
  description: `
Generates a comprehensive execution plan for the complete SSDLC (Secure Software Development Lifecycle) planning phase.

**THIS TOOL DOES NOT EXECUTE THE PIPELINE** - it creates a structured plan for Claude to execute step-by-step.

Returns a JSON plan with 7 phases:
1. BA - Requirements Analysis
2. Tech Lead - Architecture Design
3. Security - Threat Modeling (STRIDE)
4. Tech Lead - Pseudocode Generation
5. QA - Test Strategy & Test Cases
6. PM - Sprint Planning
7. DevOps - CI/CD Pipeline Design

Each phase includes:
- Tool to call
- Input parameters (with placeholders for previous phase outputs)
- Expected output schema
- Success criteria & quality gates

Target Coverage: 85-95% of SSDLC planning artifacts

**Usage Pattern:**
1. Call this tool to get the execution plan
2. Execute each phase sequentially using the plan
3. Pass output from phase N to phase N+1
4. Validate coverage at the end
  `.trim(),
  inputSchema: {
    type: 'object',
    properties: {
      project_name: {
        type: 'string',
        description: 'Project name'
      },
      project_description: {
        type: 'string',
        description: 'Detailed project description including features and context'
      },
      business_goals: {
        type: 'array',
        items: { type: 'string' },
        description: 'List of business goals and objectives'
      },
      stakeholders: {
        type: 'array',
        items: { type: 'string' },
        description: 'List of stakeholders (optional, defaults to common roles)'
      },
      tech_stack: {
        type: 'array',
        items: { type: 'string' },
        description: 'Technology stack (languages, frameworks, databases)'
      },
      team_size: {
        type: 'number',
        description: 'Team size (number of developers)'
      },
      sprint_duration: {
        type: 'number',
        description: 'Sprint duration in weeks'
      },
      deployment_target: {
        type: 'string',
        enum: ['kubernetes', 'docker', 'vm', 'serverless'],
        description: 'Deployment target platform'
      },
      repository_platform: {
        type: 'string',
        enum: ['github', 'gitlab', 'azure-devops', 'bitbucket'],
        description: 'Repository platform for CI/CD'
      },
      compliance_requirements: {
        type: 'array',
        items: { type: 'string' },
        description: 'Compliance requirements (HIPAA, GDPR, PCI-DSS, etc.)'
      }
    },
    required: ['project_name', 'project_description', 'business_goals', 'tech_stack', 'team_size', 'sprint_duration']
  }
};
