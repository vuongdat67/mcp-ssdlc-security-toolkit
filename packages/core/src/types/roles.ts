/**
 * Role definitions for SSDLC workflow
 */

import { Role, RoleDefinition } from "./common.js";

export const ROLES: Record<Role, RoleDefinition> = {
  [Role.BusinessAnalyst]: {
    name: "Business Analyst",
    perspective: "Business value, requirements clarity, stakeholder needs",
    responsibilities: [
      "Gather and validate requirements",
      "Define acceptance criteria",
      "Prioritize features by business value",
      "Create user stories",
      "Analyze market fit and ROI",
    ],
    outputs: [
      "Requirements document",
      "User stories (As a...I want...So that...)",
      "Acceptance criteria",
      "Business case analysis",
      "Feature prioritization matrix",
    ],
  },

  [Role.TechLead]: {
    name: "Technical Lead",
    perspective: "Architecture, technical feasibility, team coordination",
    responsibilities: [
      "Design system architecture",
      "Review technical decisions",
      "Manage technical debt",
      "Generate pseudocode specifications",
      "Ensure code quality standards",
    ],
    outputs: [
      "Architecture diagrams (high/low level)",
      "Technical specifications",
      "Pseudocode with security annotations",
      "Technology stack decisions",
      "Development standards",
    ],
  },

  [Role.SecurityEngineer]: {
    name: "Security Engineer",
    perspective: "Security posture, threat landscape, compliance",
    responsibilities: [
      "Conduct threat modeling (STRIDE/DREAD)",
      "Define security requirements",
      "Review for vulnerabilities",
      "Ensure compliance (OWASP, PCI-DSS, etc.)",
      "Design secure architecture",
    ],
    outputs: [
      "Threat model (STRIDE/DREAD)",
      "Security requirements",
      "Vulnerability assessment",
      "Secure coding guidelines",
      "Security test cases",
    ],
  },

  [Role.QAEngineer]: {
    name: "QA/QC Engineer",
    perspective: "Quality assurance, defect prevention, test coverage",
    responsibilities: [
      "Design test strategy",
      "Create test cases and scenarios",
      "Define quality gates",
      "Review code for testability",
      "Plan automation strategy",
    ],
    outputs: [
      "Test plan document",
      "Test cases (unit/integration/e2e)",
      "Quality metrics definition",
      "Bug severity classification",
      "Test automation roadmap",
    ],
  },

  [Role.DevOpsEngineer]: {
    name: "DevOps Engineer",
    perspective: "Deployment, scalability, reliability",
    responsibilities: [
      "Design CI/CD pipeline",
      "Infrastructure as code",
      "Monitoring and observability",
      "Disaster recovery planning",
      "Performance optimization",
    ],
    outputs: [
      "CI/CD pipeline configuration",
      "Infrastructure diagrams",
      "Monitoring strategy",
      "Deployment runbook",
      "Scaling plan",
    ],
  },

  [Role.ProjectManager]: {
    name: "Project Manager",
    perspective: "Timeline, resources, risk management",
    responsibilities: [
      "Create project timeline",
      "Manage resources allocation",
      "Track progress and metrics",
      "Identify and mitigate risks",
      "Coordinate team communication",
    ],
    outputs: [
      "Sprint planning",
      "Gantt chart / timeline",
      "Risk register",
      "Resource allocation matrix",
      "Status reports",
    ],
  },
};

/**
 * Get role definition by role type
 */
export function getRoleDefinition(role: Role): RoleDefinition {
  return ROLES[role];
}

/**
 * Get all available roles
 */
export function getAllRoles(): RoleDefinition[] {
  return Object.values(ROLES);
}
