/**
 * Business Analyst Tools
 * 
 * Tools for requirements analysis, user story creation, and business case development.
 */

import { z } from "zod";
import { format } from "date-fns";
import {
  createLogger,
  validate,
  UserStorySchema,
  ProjectConfigSchema,
  Role,
} from "@mcp-ssdlc/core";
import { renderTemplate } from "../utils/template-engine.js";

const logger = createLogger("BA-Tools");

/**
 * Input schema for requirements analysis
 */
const AnalyzeRequirementsInputSchema = z.object({
  project_description: z.string().min(10),
  stakeholders: z.array(z.string()).optional().default([]),
  business_goals: z.array(z.string()).optional().default([]),
  domain: z.enum(["web", "mobile", "api", "embedded", "malware", "cloud"]).optional(),
});

/**
 * ba_analyze_requirements tool
 * 
 * Analyzes project requirements and generates structured user stories
 */
async function baAnalyzeRequirements(input: unknown) {
  logger.info("Analyzing requirements");

  const validation = validate(AnalyzeRequirementsInputSchema, input);
  if (!validation.ok) {
    throw new Error(`Validation failed: ${validation.error.message}`);
  }

  const { project_description, stakeholders, business_goals, domain } = validation.value;

  // Extract key features from description
  const features = extractFeatures(project_description);

  // Generate user stories for each feature
  const user_stories = features.map((feature, index) =>
    generateUserStory(feature, index + 1, domain || "web")
  );

  // Create prioritization matrix
  const prioritization = prioritizeFeatures(features, business_goals);

  const result = {
    role: Role.BusinessAnalyst,
    timestamp: format(new Date(), "yyyy-MM-dd HH:mm:ss"),
    project_description,
    stakeholders,
    business_goals,
    user_stories,
    prioritization,
    acceptance_criteria: user_stories.map((story) => ({
      story_id: story.id,
      criteria: story.acceptance_criteria,
    })),
  };

  // Render markdown output
  const markdown = await renderTemplate("requirements/user-stories.hbs", result);

  return {
    ...result,
    markdown_output: markdown,
  };
}

/**
 * Extract features from project description using keywords
 */
function extractFeatures(description: string): string[] {
  // Simple feature extraction based on common patterns
  const features: string[] = [];

  // Look for action verbs
  const actionPatterns = [
    /(?:need to|want to|should|must|will)\s+(\w+(?:\s+\w+){0,4})/gi,
    /(?:user|system|application)\s+(?:can|should|must|will)\s+(\w+(?:\s+\w+){0,4})/gi,
  ];

  for (const pattern of actionPatterns) {
    const matches = description.matchAll(pattern);
    for (const match of matches) {
      if (match[1] && match[1].length > 3) {
        features.push(match[1].trim());
      }
    }
  }

  // If no features found, create generic ones
  if (features.length === 0) {
    features.push("user authentication", "data management", "reporting");
  }

  // Remove duplicates and limit to 10 features
  return [...new Set(features)].slice(0, 10);
}

/**
 * Generate a user story from a feature
 */
function generateUserStory(
  feature: string,
  index: number,
  domain: string
): z.infer<typeof UserStorySchema> {
  // Determine user role based on domain
  const userRole = domain === "api" ? "API consumer" : 
                   domain === "mobile" ? "mobile app user" : "user";

  return {
    id: `US-${String(index).padStart(3, "0")}`,
    title: `Implement ${feature}`,
    description: `Enable ${feature} functionality for ${userRole}s`,
    role: userRole,
    goal: feature,
    benefit: `improve system functionality and user experience`,
    acceptance_criteria: [
      `Given a ${userRole} has proper permissions`,
      `When they attempt to ${feature}`,
      `Then the system should process the request successfully`,
      `And appropriate feedback should be provided`,
    ],
    priority: index <= 3 ? "P0" : index <= 6 ? "P1" : "P2",
    story_points: Math.min(Math.ceil(feature.split(" ").length / 2) + 2, 13),
  };
}

/**
 * Prioritize features based on business goals
 */
function prioritizeFeatures(
  features: string[],
  business_goals: string[]
): Array<{ feature: string; priority: string; rationale: string }> {
  return features.map((feature, index) => {
    let priority: string;
    let rationale: string;

    // Match feature against business goals
    const matchesGoal = business_goals.some((goal) =>
      feature.toLowerCase().includes(goal.toLowerCase().split(" ")[0])
    );

    if (index < 3 || matchesGoal) {
      priority = "High";
      rationale = matchesGoal
        ? "Directly aligns with business goals"
        : "Core functionality required for MVP";
    } else if (index < 6) {
      priority = "Medium";
      rationale = "Important for user experience";
    } else {
      priority = "Low";
      rationale = "Nice to have, can be deferred";
    }

    return { feature, priority, rationale };
  });
}

/**
 * Input schema for business case creation
 */
const CreateBusinessCaseInputSchema = z.object({
  feature: z.string(),
  estimated_effort: z.number().min(1).max(40), // story points
  target_users: z.number().int().min(1),
  revenue_impact: z.number().optional(),
});

/**
 * ba_create_business_case tool
 * 
 * Creates a business case analysis for a feature
 */
async function baCreateBusinessCase(input: unknown) {
  logger.info("Creating business case");

  const validation = validate(CreateBusinessCaseInputSchema, input);
  if (!validation.ok) {
    throw new Error(`Validation failed: ${validation.error.message}`);
  }

  const { feature, estimated_effort, target_users, revenue_impact } = validation.value;

  // Simple ROI calculation
  const estimated_cost = estimated_effort * 1000; // $1000 per story point
  const potential_revenue = revenue_impact || target_users * 10; // $10 per user default

  const roi = ((potential_revenue - estimated_cost) / estimated_cost) * 100;

  const result = {
    role: Role.BusinessAnalyst,
    timestamp: format(new Date(), "yyyy-MM-dd HH:mm:ss"),
    feature,
    estimated_effort,
    estimated_cost,
    target_users,
    potential_revenue,
    roi: Math.round(roi),
    recommendation:
      roi > 50
        ? "Strongly recommended - High ROI"
        : roi > 20
        ? "Recommended - Positive ROI"
        : roi > 0
        ? "Consider - Marginal ROI"
        : "Not recommended - Negative ROI",
    value_proposition: generateValueProposition(feature, target_users),
  };

  return result;
}

/**
 * Generate value proposition for a feature
 */
function generateValueProposition(feature: string, target_users: number): string {
  return `By implementing ${feature}, we can serve ${target_users} users, improving overall system value and user satisfaction.`;
}

/**
 * Register Business Analyst tools
 */
export function registerBusinessAnalystTools(tools: Map<string, CallableFunction>): void {
  // Phase 9: Requirements analysis with security focus  
  tools.set("ba_analyze_requirements_security", async (input: unknown) => {
    const { baAnalyzeRequirements } = await import("./requirements/analyze-requirements.js");
    logger.info("BA: Analyzing requirements (security-focused)");
    return baAnalyzeRequirements(input);
  });

  // Main BA tool (same implementation, different name for backwards compatibility)
  tools.set("ba_analyze_requirements", async (input: unknown) => {
    const { baAnalyzeRequirements } = await import("./requirements/analyze-requirements.js");
    return baAnalyzeRequirements(input);
  });
  
  // Legacy business case tool
  tools.set("ba_create_business_case", baCreateBusinessCase);
  
  logger.info("Registered 3 Business Analyst tools");
}
