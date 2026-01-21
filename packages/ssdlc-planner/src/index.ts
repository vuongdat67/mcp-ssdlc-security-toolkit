#!/usr/bin/env node

/**
 * MCP SSDLC Planner Server
 * 
 * Main entry point for the MCP server that provides SSDLC planning tools
 * across 6 professional roles.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { createLogger, safeParseToolArgs, JSONNormalizationError, generateJSONErrorHelp } from "@mcp-ssdlc/core";
import { ToolMap } from "./types.js";
import { registerBusinessAnalystTools } from "./tools/business-analyst.js";
import { registerTechLeadTools } from "./tools/tech-lead.js";
import { registerSecurityTools } from "./tools/security.js";
import { registerQATools } from "./tools/qa.js";
import { registerDevOpsTools } from "./tools/devops.js";
import { registerProjectManagementTools } from "./tools/project-management.js";
import { registerCodingTools } from "./tools/coding.js";
import { orchestrateSSDLCPipeline } from "./tools/orchestration/orchestrate-pipeline-v2.js";
import { registerWorkspaceDiagnosticTools } from "./tools/workspace/index.js";

const logger = createLogger("MCP-SSDLC-Planner");

/**
 * Initialize and start the MCP server
 */
async function main(): Promise<void> {
  logger.info("Starting MCP SSDLC Planner Server");

  const server = new Server(
    {
      name: "mcp-ssdlc-planner",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Register all role-based tools
  const tools: ToolMap = new Map();

  registerBusinessAnalystTools(tools);
  registerTechLeadTools(tools);
  registerSecurityTools(tools);
  registerQATools(tools);
  registerDevOpsTools(tools);
  registerProjectManagementTools(tools);
  registerCodingTools(tools);
  registerWorkspaceDiagnosticTools(tools);

  // Register orchestration tool (v2 - plan generator)
  tools.set("orchestrate_ssdlc_pipeline", async (input: unknown) => {
    logger.info("Generating SSDLC orchestration plan (v2)");
    return orchestrateSSDLCPipeline(input);
  });

  logger.info(`Registered ${tools.size} tools across 7 roles + orchestration + diagnostics`);

  // Handle tool listing
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const toolsList = Array.from(tools.entries()).map(([name, _]) => ({
      name,
      description: getToolDescription(name),
      inputSchema: getToolInputSchema(name),
    }));

    return { tools: toolsList };
  });

  // Handle tool execution
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  server.setRequestHandler(CallToolRequestSchema, async (request: any): Promise<{ content: Array<{ type: string; text: string }> }> => {
    const { name, arguments: args } = request.params;

    logger.info(`Executing tool: ${name}`);

    const tool = tools.get(name);
    if (!tool) {
      throw new Error(`Unknown tool: ${name}`);
    }

    try {
      // Normalize JSON input (fix backticks, single quotes, etc.)
      let normalizedArgs = args;

      try {
        if (typeof args === 'string') {
          normalizedArgs = safeParseToolArgs(args, name);
        } else if (typeof args === 'object' && args !== null) {
          // Already an object, no normalization needed
          normalizedArgs = args;
        }
      } catch (error) {
        if (error instanceof JSONNormalizationError) {
          logger.error(`JSON normalization failed for ${name}`, error);
          return {
            content: [{
              type: 'text',
              text: generateJSONErrorHelp(error)
            }]
          };
        }
        throw error;
      }

      const result = await tool(normalizedArgs);
      logger.success(`Tool ${name} completed successfully`);

      // Tools already return content in the correct format
      return result as { content: Array<{ type: string; text: string }> };
    } catch (error) {
      logger.error(`Tool ${name} failed`, error);

      // Return helpful error message
      return {
        content: [{
          type: 'text',
          text: `❌ Tool execution failed: ${error instanceof Error ? error.message : String(error)}\n\nTool: ${name}\nPlease ensure your input matches the tool's schema.`
        }]
      };
    }
  });

  // Start server with stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.success("MCP SSDLC Planner Server running");
}

/**
 * Get tool description by name
 */
function getToolDescription(name: string): string {
  const descriptions: Record<string, string> = {
    ba_analyze_requirements: "Business Analyst analyzes requirements and creates user stories",
    ba_analyze_requirements_security: "Business Analyst analyzes requirements with security focus (STRIDE, abuse cases)",
    ba_create_business_case: "Business Analyst creates business case for features",
    techlead_design_architecture: "Tech Lead designs system architecture with trust boundaries",
    techlead_generate_pseudocode: "Tech Lead generates pseudocode with security annotations",
    security_threat_model: "Security Engineer performs STRIDE threat modeling on architecture",
    security_review_code: "Security Engineer reviews code for security vulnerabilities",
    qa_design_test_strategy: "QA Engineer designs comprehensive security test strategy (OWASP-based)",
    qa_generate_test_cases: "QA Engineer generates test cases from requirements",
    devops_design_cicd: "DevOps Engineer designs CI/CD pipeline with security gates",
    pm_create_sprint_plan: "Project Manager creates sprint planning",
    orchestrate_ssdlc_pipeline: "Orchestrate full SSDLC pipeline: BA → Tech Lead → Security → QA → PM → DevOps",
    // Coding support tools
    generate_secure_code: "Generate secure code implementation from requirements with security patterns",
    review_file: "Review an entire file for security vulnerabilities with line-by-line analysis",
    suggest_fix: "Generate fix suggestions for security vulnerabilities with code examples",
    // Workspace diagnostic tools
    workspace_snapshot: "Creates a complete snapshot of workspace structure, build system, and environment. Respects .gitignore.",
    environment_diagnostics: "Runs diagnostics on development environment: Node.js, Git, Python, PATH, and build setup.",
    validate_path: "Validates a file or directory path. Checks existence, accessibility, and suggests similar paths if not found.",
    run_diagnostic_playbook: "Runs a predefined diagnostic playbook: node-setup, build-check, path-debug, env-verify.",
  };

  return descriptions[name] || "No description available";
}

/**
 * Get tool input schema by name
 */
function getToolInputSchema(name: string): object {
  // Simplified schemas - full schemas defined in tool implementations
  const schemas: Record<string, object> = {
    ba_analyze_requirements: {
      type: "object",
      properties: {
        project_description: { type: "string", description: "Description of the project including features and context" },
        stakeholders: { type: "array", items: { type: "string" }, description: "List of stakeholders (users, admins, etc.)" },
        business_goals: { type: "array", items: { type: "string" }, description: "Business goals and objectives" },
      },
      required: ["project_description", "stakeholders", "business_goals"],
    },
    ba_analyze_requirements_security: {
      type: "object",
      properties: {
        project_description: { type: "string", description: "Description of the project including features and context" },
        stakeholders: { type: "array", items: { type: "string" }, description: "List of stakeholders (users, admins, etc.)" },
        business_goals: { type: "array", items: { type: "string" }, description: "Business goals and objectives" },
      },
      required: ["project_description", "stakeholders", "business_goals"],
    },
    techlead_design_architecture: {
      type: "object",
      properties: {
        requirements: { type: "string" },
        constraints: { type: "array", items: { type: "string" } },
      },
      required: ["requirements"],
    },
    security_threat_model: {
      type: "object",
      properties: {
        component: { type: "string" },
        architecture: { type: "string" },
      },
      required: ["component", "architecture"],
    },
    security_review_code: {
      type: "object",
      properties: {
        code_snippet: { type: "string" },
        language: { type: "string" },
        context: { type: "string" },
        severity_threshold: { type: "string", enum: ["low", "medium", "high", "critical"] },
      },
      required: ["code_snippet", "language"],
    },
    qa_design_test_strategy: {
      type: "object",
      properties: {
        project_name: { type: "string", description: "Name of the project" },
        threats: { type: "array", items: { type: "object" }, description: "STRIDE threats from threat modeling (optional)" },
        tech_stack: { type: "array", items: { type: "string" }, description: "Technology stack used" },
        risk_level: { type: "string", enum: ["low", "medium", "high", "critical"], description: "Project risk level" },
        compliance_requirements: { type: "array", items: { type: "string" }, description: "Compliance requirements (GDPR, PCI-DSS, HIPAA, etc.)" },
      },
      required: [],
    },
    qa_generate_test_cases: {
      type: "object",
      properties: {
        pseudocode: { type: "string" },
        test_type: { type: "string", enum: ["unit", "integration", "security", "e2e"] },
      },
      required: ["pseudocode"],
    },
    orchestrate_ssdlc_pipeline: {
      type: "object",
      properties: {
        project_name: { type: "string" },
        project_description: { type: "string" },
        business_goals: { type: "array", items: { type: "string" } },
        tech_stack: { type: "array", items: { type: "string" } },
        team_size: { type: "number" },
        sprint_duration: { type: "number" },
      },
      required: ["project_name", "project_description", "business_goals", "tech_stack", "team_size", "sprint_duration"],
    },
    devops_design_cicd: {
      type: "object",
      properties: {
        project_name: { type: "string", description: "Name of the project" },
        repository_platform: { type: "string", enum: ["github", "gitlab", "azure-devops", "bitbucket"], description: "Git platform (default: github)" },
        tech_stack: { type: "array", items: { type: "string" }, description: "Technology stack" },
        deployment_target: { type: "string", enum: ["kubernetes", "docker", "vm", "serverless", "paas"], description: "Deployment target (default: kubernetes)" },
        security_requirements: { type: "array", items: { type: "string" }, description: "Security requirements (SAST, DAST, etc.)" },
      },
      required: [],
    },
    pm_create_sprint_plan: {
      type: "object",
      properties: {
        project_name: { type: "string", description: "Name of the project" },
        sprint_duration: { type: "number", description: "Sprint duration in weeks (1-4, default: 2)" },
        team_size: { type: "number", description: "Team size (default: 5)" },
        user_stories: { 
          type: "array", 
          items: { type: "object" }, 
          description: "User stories with id, title, priority (P0/P1/P2/P3 or High/Medium/Low/Critical), story_points" 
        },
        team_velocity: { type: "number", description: "Story points per sprint (optional)" },
      },
      required: [],
    },
    // Workspace diagnostic tools
    workspace_snapshot: {
      type: "object",
      properties: {
        rootPath: { type: "string", description: "Root path to analyze (defaults to cwd)" },
        maxDepth: { type: "number", description: "Maximum directory depth (default: 5)" },
        includeHidden: { type: "boolean", description: "Include hidden files (default: false)" },
        respectGitignore: { type: "boolean", description: "Respect .gitignore rules (default: true)" },
      },
      required: [],
    },
    environment_diagnostics: {
      type: "object",
      properties: {
        categories: { 
          type: "array", 
          items: { type: "string", enum: ["node", "python", "git", "build", "path", "all"] },
          description: "Categories to diagnose (default: ['all'])" 
        },
      },
      required: [],
    },
    validate_path: {
      type: "object",
      properties: {
        targetPath: { type: "string", description: "Path to validate" },
        basePath: { type: "string", description: "Base path for relative resolution" },
        findSimilar: { type: "boolean", description: "Find similar paths if not found (default: true)" },
      },
      required: ["targetPath"],
    },
    run_diagnostic_playbook: {
      type: "object",
      properties: {
        playbook: { 
          type: "string", 
          enum: ["node-setup", "build-check", "path-debug", "env-verify"],
          description: "Diagnostic playbook to run" 
        },
        workspacePath: { type: "string", description: "Workspace path" },
      },
      required: ["playbook"],
    },
  };

  return schemas[name] || { type: "object" };
}

// Run server
main().catch((error) => {
  logger.error("Server failed to start", error);
  process.exit(1);
});
