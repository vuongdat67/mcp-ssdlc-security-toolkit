/**
 * Common types used across all MCP SSDLC packages
 */

import { z } from "zod";

/**
 * Professional roles in SSDLC workflow
 */
export enum Role {
  BusinessAnalyst = "business_analyst",
  TechLead = "tech_lead",
  SecurityEngineer = "security_engineer",
  QAEngineer = "qa_engineer",
  DevOpsEngineer = "devops_engineer",
  ProjectManager = "project_manager",
}

/**
 * Role definition with responsibilities and outputs
 */
export interface RoleDefinition {
  name: string;
  perspective: string;
  responsibilities: string[];
  outputs: string[];
}

/**
 * Project domain types
 */
export enum ProjectDomain {
  Web = "web",
  Mobile = "mobile",
  API = "api",
  Embedded = "embedded",
  Malware = "malware",
  Cloud = "cloud",
}

/**
 * Security level classification
 */
export enum SecurityLevel {
  High = "high",
  Medium = "medium",
  Low = "low",
}

/**
 * Project configuration
 */
export const ProjectConfigSchema = z.object({
  project_name: z.string().min(3).max(100),
  project_description: z.string().min(10),
  domain: z.nativeEnum(ProjectDomain),
  team_size: z.number().int().min(1).max(20),
  sprint_duration: z.number().int().min(1).max(4), // weeks
  security_level: z.nativeEnum(SecurityLevel).default(SecurityLevel.High),
  tech_stack: z.object({
    languages: z.array(z.string()),
    frameworks: z.array(z.string()).optional(),
    databases: z.array(z.string()).optional(),
  }).optional(),
});

export type ProjectConfig = z.infer<typeof ProjectConfigSchema>;

/**
 * User story format
 */
export const UserStorySchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  role: z.string(), // "As a..."
  goal: z.string(), // "I want..."
  benefit: z.string(), // "So that..."
  acceptance_criteria: z.array(z.string()),
  priority: z.enum(["P0", "P1", "P2", "P3"]),
  story_points: z.number().int().min(1).max(13).optional(),
});

export type UserStory = z.infer<typeof UserStorySchema>;

/**
 * STRIDE threat categories
 */
export enum ThreatType {
  Spoofing = "Spoofing",
  Tampering = "Tampering",
  Repudiation = "Repudiation",
  InformationDisclosure = "InformationDisclosure",
  DenialOfService = "DenialOfService",
  ElevationOfPrivilege = "ElevationOfPrivilege",
}

/**
 * Threat scenario
 */
export const ThreatScenarioSchema = z.object({
  id: z.string(),
  type: z.nativeEnum(ThreatType),
  component: z.string(),
  attack_vector: z.string(),
  impact: z.number().int().min(1).max(5),
  likelihood: z.number().int().min(1).max(5),
  risk_score: z.number().int().min(1).max(25), // impact * likelihood
  mitigation: z.string(),
  residual_risk: z.string(),
  owasp_mapping: z.string().optional(),
  cwe_id: z.string().optional(),
});

export type ThreatScenario = z.infer<typeof ThreatScenarioSchema>;

/**
 * Test case format
 */
export const TestCaseSchema = z.object({
  id: z.string(),
  type: z.enum(["unit", "integration", "security", "e2e", "performance"]),
  description: z.string(),
  given: z.string(), // Preconditions
  when: z.string(), // Action
  then: z.string(), // Expected result
  priority: z.enum(["P0", "P1", "P2"]),
  security_risk: z.boolean().default(false),
  related_threat: z.string().optional(),
});

export type TestCase = z.infer<typeof TestCaseSchema>;

/**
 * Architecture component
 */
export const ComponentSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.enum(["service", "database", "queue", "cache", "gateway", "frontend"]),
  description: z.string(),
  responsibilities: z.array(z.string()),
  dependencies: z.array(z.string()),
  interfaces: z.array(z.object({
    name: z.string(),
    methods: z.array(z.string()),
  })),
  security_considerations: z.array(z.string()),
});

export type Component = z.infer<typeof ComponentSchema>;

/**
 * Result type for error handling
 */
export type Result<T, E = Error> =
  | { ok: true; value: T }
  | { ok: false; error: E };

/**
 * MCP tool response
 */
export interface ToolResponse<T = unknown> {
  content: Array<{
    type: "text" | "json" | "markdown";
    text?: string;
    json?: T;
  }>;
  metadata?: Record<string, unknown>;
}

/**
 * MCP Tool Result - standard format for MCP tool handlers
 */
export interface MCPToolResult {
  content: Array<{
    type: "text" | "json" | "markdown" | "image";
    text?: string;
    json?: unknown;
  }>;
  isError?: boolean;
}

/**
 * Template context
 */
export interface TemplateContext {
  project: ProjectConfig;
  timestamp: string;
  role: Role;
  data: Record<string, unknown>;
}
