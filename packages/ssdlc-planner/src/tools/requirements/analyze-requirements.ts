/**
 * Business Analyst Tool: Analyze Requirements
 * 
 * Analyzes project requirements and generates user stories with acceptance criteria
 */

import { z } from "zod";
import Handlebars from "handlebars";
import { readFile } from "fs/promises";
import { join } from "path";
import { createLogger, safeParseToolArgs, validateJSONSchema, JSONNormalizationError, generateJSONErrorHelp } from "@mcp-ssdlc/core";
import type { MCPToolResult } from "@mcp-ssdlc/core";

const logger = createLogger("ba-analyze-requirements");

// Input validation schema
const AnalyzeRequirementsSchema = z.object({
  project_name: z.string().optional(),
  project_description: z.string().min(10, "Project description too short"),
  stakeholders: z.array(z.string()).min(1, "At least one stakeholder required"),
  business_goals: z.array(z.string()).min(1, "At least one business goal required"),
});

interface UserStory {
  id: string;
  title: string;
  as_a: string;
  i_want: string;
  so_that: string;
  acceptance_criteria: string[];
  priority: "High" | "Medium" | "Low";
  estimated_effort: string;
  security_considerations: string[];
}

interface AnalyzeRequirementsOutput {
  project_name: string;
  timestamp: string;
  user_stories: UserStory[];
  prioritization_matrix: {
    high_priority: string[];
    medium_priority: string[];
    low_priority: string[];
  };
  security_requirements: string[];
}

/**
 * Generate user stories from project requirements
 */
function generateUserStories(
  projectDescription: string,
  stakeholders: string[],
  businessGoals: string[]
): UserStory[] {
  // Extract key features from project description
  const features = extractFeatures(projectDescription);
  
  const userStories: UserStory[] = features.map((feature, index) => {
    const storyId = `US-${String(index + 1).padStart(3, "0")}`;
    
    // Determine priority based on security keywords and business goals
    const priority = determineStoryPriority(feature, businessGoals);
    
    // Generate acceptance criteria
    const acceptanceCriteria = generateAcceptanceCriteria(feature);
    
    // Identify security considerations
    const securityConsiderations = identifySecurityConsiderations(feature);
    
    return {
      id: storyId,
      title: feature.title,
      as_a: feature.actor || stakeholders[0] || "user",
      i_want: feature.action,
      so_that: feature.benefit,
      acceptance_criteria: acceptanceCriteria,
      priority,
      estimated_effort: estimateEffort(feature),
      security_considerations: securityConsiderations,
    };
  });

  return userStories;
}

/**
 * Extract features from project description
 */
function extractFeatures(description: string): Array<{
  title: string;
  action: string;
  benefit: string;
  actor?: string;
}> {
  // Simple heuristic-based feature extraction
  // In production, this would use NLP or LLM analysis
  
  const features: Array<{
    title: string;
    action: string;
    benefit: string;
    actor?: string;
  }> = [];

  // Common security project patterns
  if (description.toLowerCase().includes("authentication") || description.toLowerCase().includes("oauth")) {
    features.push({
      title: "User Authentication",
      action: "securely authenticate using credentials",
      benefit: "I can access protected resources safely",
      actor: "user",
    });
  }

  if (description.toLowerCase().includes("oauth") || description.toLowerCase().includes("token")) {
    features.push({
      title: "OAuth2/Token Management",
      action: "obtain and manage secure access tokens",
      benefit: "API access is authorized and controlled",
      actor: "client application",
    });
  }

  if (description.toLowerCase().includes("authorization") || description.toLowerCase().includes("permission")) {
    features.push({
      title: "Role-Based Access Control",
      action: "define and enforce user permissions",
      benefit: "only authorized users can access sensitive resources",
      actor: "admin",
    });
  }

  if (description.toLowerCase().includes("api") || description.toLowerCase().includes("endpoint")) {
    features.push({
      title: "API Security",
      action: "secure API endpoints with rate limiting and validation",
      benefit: "APIs are protected from abuse and attacks",
      actor: "developer",
    });
  }

  if (description.toLowerCase().includes("logging") || description.toLowerCase().includes("audit")) {
    features.push({
      title: "Audit Logging",
      action: "track all security-relevant events",
      benefit: "I can investigate security incidents",
      actor: "security analyst",
    });
  }

  if (description.toLowerCase().includes("encryption") || description.toLowerCase().includes("crypto")) {
    features.push({
      title: "Data Encryption",
      action: "encrypt sensitive data at rest and in transit",
      benefit: "data is protected from unauthorized access",
      actor: "system",
    });
  }

  // Generic feature if no specific patterns found
  if (features.length === 0) {
    features.push({
      title: "Core Functionality",
      action: "use the system's primary features",
      benefit: "I can accomplish my goals securely",
      actor: "user",
    });
  }

  return features;
}

/**
 * Determine story priority
 */
function determineStoryPriority(
  feature: { title: string; action: string; benefit: string },
  businessGoals: string[]
): "High" | "Medium" | "Low" {
  const featureText = `${feature.title} ${feature.action} ${feature.benefit}`.toLowerCase();
  
  // High priority: Security-critical features
  const highPriorityKeywords = [
    "authentication",
    "authorization",
    "encryption",
    "security",
    "audit",
    "compliance",
    "vulnerability",
  ];

  if (highPriorityKeywords.some((keyword) => featureText.includes(keyword))) {
    return "High";
  }

  // Check if aligned with business goals
  const alignsWithGoals = businessGoals.some((goal) =>
    featureText.includes(goal.toLowerCase())
  );

  if (alignsWithGoals) {
    return "High";
  }

  // Medium priority by default
  return "Medium";
}

/**
 * Generate acceptance criteria
 */
function generateAcceptanceCriteria(feature: {
  title: string;
  action: string;
  benefit: string;
}): string[] {
  const criteria: string[] = [];

  // Given-When-Then format
  criteria.push(
    `Given I am a ${feature.actor || "user"} with valid credentials`
  );
  criteria.push(`When I ${feature.action}`);
  criteria.push(`Then ${feature.benefit}`);

  // Security criteria
  if (feature.title.toLowerCase().includes("authentication")) {
    criteria.push("And the system uses secure password hashing (bcrypt/argon2)");
    criteria.push("And failed login attempts are rate-limited");
    criteria.push("And sessions expire after inactivity");
  }

  if (feature.title.toLowerCase().includes("api")) {
    criteria.push("And API requests are validated against schema");
    criteria.push("And rate limiting prevents abuse (e.g., 100 req/min)");
    criteria.push("And all responses include security headers");
  }

  // Non-functional criteria
  criteria.push("And the feature responds within 2 seconds");
  criteria.push("And all actions are logged for audit purposes");

  return criteria;
}

/**
 * Identify security considerations
 */
function identifySecurityConsiderations(feature: {
  title: string;
  action: string;
}): string[] {
  const considerations: string[] = [];
  const featureText = `${feature.title} ${feature.action}`.toLowerCase();

  if (featureText.includes("authentication") || featureText.includes("login")) {
    considerations.push("Implement multi-factor authentication (MFA)");
    considerations.push("Protect against brute force attacks");
    considerations.push("Use secure session management");
  }

  if (featureText.includes("api") || featureText.includes("endpoint")) {
    considerations.push("Implement OWASP API Security Top 10 protections");
    considerations.push("Validate and sanitize all inputs");
    considerations.push("Use API keys or OAuth2 for authentication");
  }

  if (featureText.includes("data") || featureText.includes("database")) {
    considerations.push("Prevent SQL injection attacks");
    considerations.push("Encrypt sensitive data at rest");
    considerations.push("Implement proper access controls");
  }

  // Always include
  considerations.push("Follow secure coding best practices");
  considerations.push("Perform security testing (SAST/DAST)");

  return considerations;
}

/**
 * Estimate effort (T-shirt sizing)
 */
function estimateEffort(feature: {
  title: string;
  action: string;
}): string {
  const featureText = `${feature.title} ${feature.action}`.toLowerCase();

  // Complex features
  if (
    featureText.includes("authentication") ||
    featureText.includes("encryption") ||
    featureText.includes("integration")
  ) {
    return "Large (5-8 days)";
  }

  // Medium features
  if (
    featureText.includes("api") ||
    featureText.includes("logging") ||
    featureText.includes("validation")
  ) {
    return "Medium (3-5 days)";
  }

  // Simple features
  return "Small (1-2 days)";
}

/**
 * Load and render Handlebars template
 */
async function renderTemplate(
  templateName: string,
  data: AnalyzeRequirementsOutput
): Promise<string> {
  const templatePath = join(
    __dirname,
    "../../templates/requirements",
    `${templateName}.hbs`
  );

  try {
    const templateSource = await readFile(templatePath, "utf-8");
    const template = Handlebars.compile(templateSource);
    return template(data);
  } catch (error) {
    logger.warn(`Template not found: ${templateName}, using fallback`);
    return JSON.stringify(data, null, 2);
  }
}

/**
 * Main BA tool handler
 */
export async function baAnalyzeRequirements(args: unknown) {
  try {
    // Validate input
    const input = AnalyzeRequirementsSchema.parse(args);

    logger.info("Analyzing requirements...");

    // Generate user stories
    const userStories = generateUserStories(
      input.project_description,
      input.stakeholders,
      input.business_goals
    );

    // Create prioritization matrix
    const prioritization_matrix = {
      high_priority: userStories
        .filter((s) => s.priority === "High")
        .map((s) => s.id),
      medium_priority: userStories
        .filter((s) => s.priority === "Medium")
        .map((s) => s.id),
      low_priority: userStories
        .filter((s) => s.priority === "Low")
        .map((s) => s.id),
    };

    // Aggregate security requirements
    const securityRequirements = Array.from(
      new Set(
        userStories.flatMap((story) => story.security_considerations)
      )
    );

    const output: AnalyzeRequirementsOutput = {
      project_name: input.project_name || extractProjectName(input.project_description),
      timestamp: new Date().toISOString(),
      user_stories: userStories,
      prioritization_matrix,
      security_requirements: securityRequirements,
    };

    logger.info(`Generated ${userStories.length} user stories`);

    // Return JSON for orchestration compatibility
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(output, null, 2),
        },
      ],
    };
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errorMessage = error.errors
        .map((e) => `${e.path.join(".")}: ${e.message}`)
        .join(", ");
      throw new Error(`Validation failed: ${errorMessage}`);
    }
    throw error;
  }
}

/**
 * Extract project name from description
 */
function extractProjectName(description: string): string {
  // Try to find project name in first sentence
  const firstSentence = description.split(/[.!?]/)[0];
  const words = firstSentence.split(" ");
  
  // Take first 3-5 meaningful words
  const projectName = words
    .slice(0, Math.min(5, words.length))
    .join(" ")
    .replace(/[^a-zA-Z0-9\s]/g, "")
    .trim();

  return projectName || "Project";
}
