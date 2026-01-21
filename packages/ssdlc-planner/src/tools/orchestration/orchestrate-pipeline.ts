/**
 * SSDLC Pipeline Orchestration Tool
 * 
 * Chains all role-based tools together to automate the complete SSDLC planning phase:
 * BA → Tech Lead → Security → QA → PM → DevOps
 * 
 * This tool aims for 85-95% planning coverage with a single invocation.
 */

import type { MCPToolResult } from '@mcp-ssdlc/core';
import { baAnalyzeRequirements } from '../requirements/analyze-requirements.js';
import { techleadDesignArchitecture } from '../architecture/design-architecture.js';
import { securityThreatModel } from '../security/threat-modeling.js';
import { techleadGeneratePseudocode } from '../implementation/generate-pseudocode.js';
import { qaGenerateTestCases } from '../testing/generate-test-cases.js';
import { pmCreateSprintPlan } from '../pm/create-sprint-plan.js';
import { devopsDesignCICD } from '../devops/design-cicd.js';

/**
 * Safely parse JSON output from tools
 */
function safeParse<T = Record<string, unknown>>(raw: string, phase: string): T {
  try {
    return JSON.parse(raw) as T;
  } catch (error) {
    throw new Error(`${phase} returned non-JSON output: ${error}`);
  }
}

// Tool output interfaces for type safety
interface BAOutput {
  user_stories?: Array<{ id: string; title: string; story_points?: number; [key: string]: unknown }>;
  non_functional_requirements?: string[];
  acceptance_criteria?: unknown[];
  functional_requirements?: string[];
  data_classification?: unknown[];
}

interface ArchOutput {
  components?: Array<{ name: string; [key: string]: unknown }>;
  diagrams?: string[];
  interfaces?: unknown[];
}

interface ThreatOutput {
  threats?: Array<{ id: string; [key: string]: unknown }>;
  risk_score?: number;
  mitigations?: unknown[];
  security_controls?: unknown[];
}

interface TestOutput {
  test_cases?: unknown[];
  test_suites?: unknown[];
  coverage_summary?: unknown;
}

interface SprintOutput {
  sprints?: unknown[];
  tasks?: unknown[];
  timeline?: string;
}

interface CicdOutput {
  pipeline?: string;
  stages?: string[];
  security_gates?: unknown[];
  platform?: string;
  security_scans?: unknown[];
}

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

export interface PipelineOutput {
  project_overview: {
    name: string;
    description: string;
    goals: string[];
    tech_stack: string[];
  };
  requirements: {
    user_stories: any[];
    acceptance_criteria: any[];
    functional_requirements: string[];
    non_functional_requirements: string[];
  };
  architecture: {
    components: any[];
    diagrams: string[];
    interfaces: any[];
  };
  threat_model: {
    threats: any[];
    mitigations: any[];
    security_controls: string[];
  };
  pseudocode: {
    functions: any[];
    total_functions: number;
  };
  test_cases: {
    test_suites: any[];
    total_cases: number;
  };
  sprint_plan: {
    sprints: any[];
    tasks: any[];
    timeline: string;
  };
  cicd_pipeline: {
    platform: string;
    stages: string[];
    security_scans: string[];
  };
  coverage_metrics: {
    requirements_coverage: number; // percentage
    security_coverage: number;
    test_coverage: number;
    architecture_coverage: number;
    overall_coverage: number;
  };
  execution_summary: {
    total_duration_ms: number;
    tools_executed: string[];
    success: boolean;
    errors: string[];
  };
}

/**
 * Orchestrate the complete SSDLC planning pipeline
 */
export async function orchestratePipeline(args: PipelineInput): Promise<MCPToolResult> {
  const startTime = Date.now();
  const errors: string[] = [];
  const toolsExecuted: string[] = [];

  try {
    console.error('🚀 Starting SSDLC Pipeline Orchestration...');
    console.error(`📋 Project: ${args.project_name}`);
    console.error(`👥 Team Size: ${args.team_size}`);
    console.error(`⏱️  Sprint Duration: ${args.sprint_duration} weeks\n`);

    // ====================
    // Phase 1: Business Analysis
    // ====================
    console.error('📊 Phase 1: Business Analysis...');
    toolsExecuted.push('ba_analyze_requirements');
    
    const baResult = await baAnalyzeRequirements({
      project_description: args.project_description,
      business_goals: args.business_goals,
      stakeholders: args.stakeholders || ['Product Owner', 'End Users', 'Security Team']
    });

    if (!baResult.content?.[0]?.text) {
      throw new Error('BA analysis failed to produce output');
    }

    const baOutput = safeParse<BAOutput>(baResult.content[0].text, 'BA');
    console.error(`✅ Generated ${baOutput.user_stories?.length || 0} user stories`);

    // ====================
    // Phase 2: Architecture Design
    // ====================
    console.error('\n🏗️  Phase 2: Architecture Design...');
    toolsExecuted.push('techlead_design_architecture');

    const archResult = await techleadDesignArchitecture({
      project_name: args.project_name,
      tech_stack: args.tech_stack,
      user_stories: baOutput.user_stories || [],
      non_functional_requirements: baOutput.non_functional_requirements || []
    });

    if (!archResult.content?.[0]?.text) {
      throw new Error('Architecture design failed to produce output');
    }

    const archOutput = safeParse<ArchOutput>(archResult.content[0].text, 'Architecture');
    console.error(`✅ Designed ${archOutput.components?.length || 0} components`);

    // ====================
    // Phase 3: Security Threat Modeling
    // ====================
    console.error('\n🔒 Phase 3: Security Threat Modeling...');
    toolsExecuted.push('security_threat_model');

    const threatResult = await securityThreatModel({
      project_name: args.project_name,
      components: archOutput.components || [],
      tech_stack: args.tech_stack,
      compliance_requirements: args.compliance_requirements || []
    });

    if (!threatResult.content?.[0]?.text) {
      throw new Error('Threat modeling failed to produce output');
    }

    const threatOutput = safeParse<ThreatOutput>(threatResult.content[0].text, 'Threat Modeling');
    console.error(`✅ Identified ${threatOutput.threats?.length || 0} threats with mitigations`);

    // ====================
    // Phase 4: Pseudocode Generation
    // ====================
    console.error('\n💻 Phase 4: Pseudocode Generation...');
    toolsExecuted.push('techlead_generate_pseudocode');

    // Generate pseudocode for critical functions
    const criticalFunctions = extractCriticalFunctions(archOutput, threatOutput);
    const pseudocodeResults = [];

    for (const func of criticalFunctions.slice(0, 5)) { // Limit to 5 for performance
      try {
        const pseudoResult = await techleadGeneratePseudocode({
          function_name: func.name,
          description: func.description,
          language: inferPrimaryLanguage(args.tech_stack),
          parameters: func.parameters || [],
          return_type: func.return_type || 'void',
          security_considerations: func.security_notes || []
        });

        if (pseudoResult.content?.[0]?.text) {
          pseudocodeResults.push(safeParse(pseudoResult.content[0].text, 'Pseudocode'));
        }
      } catch (err) {
        errors.push(`Pseudocode generation failed for ${func.name}: ${err}`);
      }
    }

    console.error(`✅ Generated pseudocode for ${pseudocodeResults.length} critical functions`);

    // ====================
    // Phase 5: Test Case Generation
    // ====================
    console.error('\n🧪 Phase 5: Test Case Generation...');
    toolsExecuted.push('qa_generate_test_cases');

    const testResult = await qaGenerateTestCases({
      project_name: args.project_name,
      user_stories: baOutput.user_stories || [],
      threat_model: threatOutput.threats || [],
      components: archOutput.components || []
    });

    if (!testResult.content?.[0]?.text) {
      throw new Error('Test case generation failed to produce output');
    }

    const testOutput = safeParse<TestOutput>(testResult.content[0].text, 'Test Cases');
    console.error(`✅ Generated ${testOutput.test_suites?.length || 0} test suites`);

    // ====================
    // Phase 6: Sprint Planning
    // ====================
    console.error('\n📅 Phase 6: Sprint Planning...');
    toolsExecuted.push('pm_create_sprint_plan');

    const sprintResult = await pmCreateSprintPlan({
      sprint_duration: args.sprint_duration,
      team_size: args.team_size,
      user_stories: baOutput.user_stories || [],
      priorities: extractPriorities(baOutput.user_stories || [])
    });

    if (!sprintResult.content?.[0]?.text) {
      throw new Error('Sprint planning failed to produce output');
    }

    const sprintOutput = safeParse<SprintOutput>(sprintResult.content[0].text, 'Sprint Planning');
    console.error(`✅ Created ${sprintOutput.sprints?.length || 0} sprint plan`);

    // ====================
    // Phase 7: CI/CD Pipeline Design
    // ====================
    console.error('\n🔄 Phase 7: CI/CD Pipeline Design...');
    toolsExecuted.push('devops_design_cicd');

    const cicdResult = await devopsDesignCICD({
      project_name: args.project_name,
      repository_platform: args.repository_platform || 'github',
      tech_stack: args.tech_stack,
      deployment_target: args.deployment_target || 'kubernetes',
      security_requirements: threatOutput.security_controls || []
    });

    if (!cicdResult.content?.[0]?.text) {
      throw new Error('CI/CD design failed to produce output');
    }

    const cicdOutput = safeParse<CicdOutput>(cicdResult.content[0].text, 'CI/CD Pipeline');
    console.error(`✅ Designed CI/CD pipeline with ${cicdOutput.stages?.length || 0} stages`);

    // ====================
    // Calculate Coverage Metrics
    // ====================
    console.error('\n📊 Calculating Coverage Metrics...');
    const coverageMetrics = calculateCoverage({
      baOutput,
      archOutput,
      threatOutput,
      testOutput,
      pseudocodeResults
    });

    console.error(`✅ Requirements Coverage: ${coverageMetrics.requirements_coverage}%`);
    console.error(`✅ Security Coverage: ${coverageMetrics.security_coverage}%`);
    console.error(`✅ Test Coverage: ${coverageMetrics.test_coverage}%`);
    console.error(`✅ Architecture Coverage: ${coverageMetrics.architecture_coverage}%`);
    console.error(`✅ Overall Coverage: ${coverageMetrics.overall_coverage}%`);

    // ====================
    // Build Final Output
    // ====================
    const duration = Date.now() - startTime;
    console.error(`\n✨ Pipeline completed in ${(duration / 1000).toFixed(2)}s`);

    const output: PipelineOutput = {
      project_overview: {
        name: args.project_name,
        description: args.project_description,
        goals: args.business_goals,
        tech_stack: args.tech_stack
      },
      requirements: {
        user_stories: baOutput.user_stories || [],
        acceptance_criteria: baOutput.acceptance_criteria || [],
        functional_requirements: baOutput.functional_requirements || [],
        non_functional_requirements: baOutput.non_functional_requirements || []
      },
      architecture: {
        components: archOutput.components || [],
        diagrams: archOutput.diagrams || [],
        interfaces: archOutput.interfaces || []
      },
      threat_model: {
        threats: threatOutput.threats || [],
        mitigations: threatOutput.mitigations || [],
        security_controls: (threatOutput.security_controls || []) as string[]
      },
      pseudocode: {
        functions: pseudocodeResults,
        total_functions: pseudocodeResults.length
      },
      test_cases: {
        test_suites: testOutput.test_suites || [],
        total_cases: countTotalTestCases(testOutput.test_suites || [])
      },
      sprint_plan: {
        sprints: sprintOutput.sprints || [],
        tasks: sprintOutput.tasks || [],
        timeline: sprintOutput.timeline || ''
      },
      cicd_pipeline: {
        platform: cicdOutput.platform || args.repository_platform || 'github',
        stages: (cicdOutput.stages || []) as string[],
        security_scans: (cicdOutput.security_scans || []) as string[]
      },
      coverage_metrics: coverageMetrics,
      execution_summary: {
        total_duration_ms: duration,
        tools_executed: toolsExecuted,
        success: true,
        errors: errors
      }
    };

    // Generate comprehensive markdown report
    const report = generatePipelineReport(output);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(output, null, 2)
        },
        {
          type: 'text',
          text: report
        }
      ]
    };

  } catch (error) {
    const duration = Date.now() - startTime;
    console.error(`\n❌ Pipeline failed after ${(duration / 1000).toFixed(2)}s`);
    console.error(`Error: ${error}`);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            execution_summary: {
              total_duration_ms: duration,
              tools_executed: toolsExecuted,
              success: false,
              errors: [...errors, String(error)]
            }
          }, null, 2)
        }
      ],
      isError: true
    };
  }
}

// ====================
// Helper Functions
// ====================

function extractCriticalFunctions(archOutput: any, threatOutput: any): any[] {
  const functions: any[] = [];

  // Extract from architecture components
  for (const component of archOutput.components || []) {
    if (component.interfaces) {
      for (const iface of component.interfaces) {
        if (iface.methods) {
          functions.push(...iface.methods.map((m: any) => ({
            name: m.name,
            description: m.description || `${m.name} from ${component.name}`,
            parameters: m.parameters || [],
            return_type: m.return_type || 'void',
            security_notes: []
          })));
        }
      }
    }
  }

  // Prioritize functions related to threats
  const securityCriticalFunctions = new Set<string>();
  for (const threat of threatOutput.threats || []) {
    if (threat.affected_component) {
      securityCriticalFunctions.add(threat.affected_component.toLowerCase());
    }
  }

  // Mark security-critical functions
  functions.forEach(f => {
    const isSecurityCritical = Array.from(securityCriticalFunctions).some(
      critical => f.name.toLowerCase().includes(critical)
    );
    if (isSecurityCritical) {
      f.security_notes.push('This function handles security-critical operations');
    }
  });

  return functions;
}

function inferPrimaryLanguage(techStack: string[]): string {
  const languageMap: Record<string, string> = {
    'python': 'python',
    'javascript': 'javascript',
    'typescript': 'typescript',
    'node': 'javascript',
    'nodejs': 'javascript',
    'go': 'go',
    'golang': 'go',
    'csharp': 'csharp',
    'c#': 'csharp',
    '.net': 'csharp',
    'java': 'java',
    'rust': 'rust',
    'ruby': 'ruby'
  };

  for (const tech of techStack) {
    const normalized = tech.toLowerCase();
    if (languageMap[normalized]) {
      return languageMap[normalized];
    }
  }

  return 'python'; // Default
}

function extractPriorities(userStories: any[]): string[] {
  return userStories
    .filter(story => story.priority)
    .map(story => `${story.id}:${story.priority}`)
    .sort((a, b) => {
      const priorityA = a.split(':')[1];
      const priorityB = b.split(':')[1];
      return priorityA.localeCompare(priorityB);
    });
}

function calculateCoverage(data: {
  baOutput: any;
  archOutput: any;
  threatOutput: any;
  testOutput: any;
  pseudocodeResults: any[];
}): PipelineOutput['coverage_metrics'] {
  // Requirements Coverage: Based on user stories completeness
  const userStories = data.baOutput.user_stories || [];
  const completeStories = userStories.filter((s: any) => 
    s.acceptance_criteria && s.acceptance_criteria.length > 0
  ).length;
  const requirementsCoverage = userStories.length > 0 
    ? Math.round((completeStories / userStories.length) * 100) 
    : 0;

  // Security Coverage: Based on threats identified and mitigated
  const threats = data.threatOutput.threats || [];
  const mitigatedThreats = threats.filter((t: any) => 
    t.mitigation && t.mitigation.length > 0
  ).length;
  const securityCoverage = threats.length > 0 
    ? Math.round((mitigatedThreats / threats.length) * 100) 
    : 0;

  // Test Coverage: Based on test cases vs user stories
  const testSuites = data.testOutput.test_suites || [];
  const totalTestCases = countTotalTestCases(testSuites);
  const expectedTestsPerStory = 3; // Unit, integration, security
  const expectedTotalTests = userStories.length * expectedTestsPerStory;
  const testCoverage = expectedTotalTests > 0 
    ? Math.min(100, Math.round((totalTestCases / expectedTotalTests) * 100)) 
    : 0;

  // Architecture Coverage: Based on components and interfaces
  const components = data.archOutput.components || [];
  const componentsWithInterfaces = components.filter((c: any) => 
    c.interfaces && c.interfaces.length > 0
  ).length;
  const architectureCoverage = components.length > 0 
    ? Math.round((componentsWithInterfaces / components.length) * 100) 
    : 0;

  // Overall Coverage: Weighted average
  const weights = {
    requirements: 0.25,
    security: 0.30,
    test: 0.25,
    architecture: 0.20
  };

  const overallCoverage = Math.round(
    requirementsCoverage * weights.requirements +
    securityCoverage * weights.security +
    testCoverage * weights.test +
    architectureCoverage * weights.architecture
  );

  return {
    requirements_coverage: requirementsCoverage,
    security_coverage: securityCoverage,
    test_coverage: testCoverage,
    architecture_coverage: architectureCoverage,
    overall_coverage: overallCoverage
  };
}

function countTotalTestCases(testSuites: any[]): number {
  return testSuites.reduce((total, suite) => {
    return total + (suite.test_cases?.length || 0);
  }, 0);
}

function generatePipelineReport(output: PipelineOutput): string {
  return `
# SSDLC Pipeline Orchestration Report

## Project Overview
**Name**: ${output.project_overview.name}
**Description**: ${output.project_overview.description}
**Tech Stack**: ${output.project_overview.tech_stack.join(', ')}

## Business Goals
${output.project_overview.goals.map(g => `- ${g}`).join('\n')}

## Coverage Metrics 📊

| Metric | Coverage | Target | Status |
|--------|----------|--------|--------|
| Requirements | ${output.coverage_metrics.requirements_coverage}% | 90-95% | ${output.coverage_metrics.requirements_coverage >= 90 ? '✅' : '⚠️'} |
| Security | ${output.coverage_metrics.security_coverage}% | 85-95% | ${output.coverage_metrics.security_coverage >= 85 ? '✅' : '⚠️'} |
| Testing | ${output.coverage_metrics.test_coverage}% | 85-90% | ${output.coverage_metrics.test_coverage >= 85 ? '✅' : '⚠️'} |
| Architecture | ${output.coverage_metrics.architecture_coverage}% | 85-90% | ${output.coverage_metrics.architecture_coverage >= 85 ? '✅' : '⚠️'} |
| **Overall** | **${output.coverage_metrics.overall_coverage}%** | **85-95%** | **${output.coverage_metrics.overall_coverage >= 85 ? '✅' : '⚠️'}** |

## Artifacts Generated

### 📋 Requirements (BA)
- **User Stories**: ${output.requirements.user_stories.length}
- **Functional Requirements**: ${output.requirements.functional_requirements.length}
- **Non-Functional Requirements**: ${output.requirements.non_functional_requirements.length}

### 🏗️ Architecture (Tech Lead)
- **Components**: ${output.architecture.components.length}
- **Interfaces**: ${output.architecture.interfaces.length}
- **Diagrams**: ${output.architecture.diagrams.length}

### 🔒 Security (Security Engineer)
- **Threats Identified**: ${output.threat_model.threats.length}
- **Mitigations**: ${output.threat_model.mitigations.length}
- **Security Controls**: ${output.threat_model.security_controls.length}

### 💻 Pseudocode (Tech Lead)
- **Functions Implemented**: ${output.pseudocode.total_functions}

### 🧪 Testing (QA Engineer)
- **Test Suites**: ${output.test_cases.test_suites.length}
- **Total Test Cases**: ${output.test_cases.total_cases}

### 📅 Sprint Planning (Project Manager)
- **Sprints Planned**: ${output.sprint_plan.sprints.length}
- **Tasks Breakdown**: ${output.sprint_plan.tasks.length}

### 🔄 CI/CD (DevOps Engineer)
- **Platform**: ${output.cicd_pipeline.platform}
- **Pipeline Stages**: ${output.cicd_pipeline.stages.length}
- **Security Scans**: ${output.cicd_pipeline.security_scans.length}

## Execution Summary

- **Duration**: ${(output.execution_summary.total_duration_ms / 1000).toFixed(2)}s
- **Tools Executed**: ${output.execution_summary.tools_executed.length}
- **Status**: ${output.execution_summary.success ? '✅ Success' : '❌ Failed'}
${output.execution_summary.errors.length > 0 ? `\n### Errors\n${output.execution_summary.errors.map(e => `- ${e}`).join('\n')}` : ''}

## Next Steps

1. **Review Artifacts**: Examine each generated document for accuracy
2. **Validate Coverage**: Ensure all metrics meet 85%+ thresholds
3. **Refine Requirements**: Add missing details identified during review
4. **Begin Implementation**: Use pseudocode and test cases for development
5. **Setup CI/CD**: Implement the designed pipeline configuration

---
*Generated by MCP SSDLC Security Toolkit - Phase 3 Pipeline Orchestration*
`;
}
