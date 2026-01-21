# MCP SSDLC Tools Reference

Complete reference for all 13 MCP tools available in the SSDLC Security Toolkit.

---

## Business Analyst Tools

### `ba_analyze_requirements`

Analyzes project requirements and creates structured user stories.

**Input Schema:**
```json
{
  "project_description": "string (required) - Description of the project",
  "stakeholders": "string[] (required) - List of stakeholders",
  "business_goals": "string[] (required) - Business goals and objectives",
  "project_name": "string (optional) - Project name for context"
}
```

**Output:**
- User stories with acceptance criteria
- Stakeholder analysis
- Goal prioritization
- Security-related requirements

**Example:**
```json
{
  "project_description": "E-commerce platform with user authentication and payment processing",
  "stakeholders": ["Customers", "Merchants", "Admins"],
  "business_goals": ["Secure transactions", "User privacy", "Fast checkout"]
}
```

---

### `ba_analyze_requirements_security`

Security-focused requirements analysis with STRIDE and abuse cases.

**Input Schema:**
```json
{
  "project_description": "string (required)",
  "stakeholders": "string[] (required)",
  "business_goals": "string[] (required)"
}
```

**Output:**
- Security user stories
- STRIDE threat categories
- Abuse case scenarios
- Security acceptance criteria

---

### `ba_create_business_case`

Creates business case documentation for features.

**Input Schema:**
```json
{
  "feature_name": "string",
  "problem_statement": "string",
  "proposed_solution": "string"
}
```

---

## Tech Lead Tools

### `techlead_design_architecture`

Designs system architecture with trust boundaries.

**Input Schema:**
```json
{
  "requirements": "string (required) - System requirements",
  "constraints": "string[] (optional) - Technical constraints"
}
```

**Output:**
- Component diagram (Mermaid)
- Trust boundaries
- Data flow analysis
- Security zones
- Technology recommendations

---

## Security Engineer Tools

### `security_review_code`

Reviews code for security vulnerabilities with CWE/OWASP mapping.

**Input Schema:**
```json
{
  "code_snippet": "string (required) - Code to review",
  "language": "string (required) - Programming language",
  "context": "string (optional) - Additional context",
  "severity_threshold": "enum: low|medium|high|critical (optional)"
}
```

**Output:**
```json
{
  "risk_score": 0-10,
  "confidence": 0-100,
  "findings": [
    {
      "line": 5,
      "code": "eval(userInput)",
      "cwe": "CWE-95",
      "owasp": "A05:2025-Injection",
      "severity": "critical",
      "confidence": 95,
      "explanation": "...",
      "remediation": "...",
      "secure_example": "..."
    }
  ]
}
```

---

### `security_threat_model`

Performs STRIDE threat modeling on system architecture.

**Input Schema:**
```json
{
  "component": "string (required) - Component to analyze",
  "architecture": "string (required) - Architecture description"
}
```

**Output:**
- STRIDE analysis (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege)
- Threat scenarios
- Risk ratings
- Mitigation strategies

---

## QA Engineer Tools

### `qa_design_test_strategy`

Designs comprehensive security test strategy with OWASP coverage.

**Input Schema:**
```json
{
  "project_name": "string (optional)",
  "tech_stack": "string[] (optional)",
  "risk_level": "enum: low|medium|high|critical (optional)",
  "threats": "object[] (optional) - STRIDE threats",
  "compliance_requirements": "string[] (optional) - GDPR, PCI-DSS, etc."
}
```

**Output:**
- Test categories (unit, integration, security)
- OWASP Top 10 test cases
- Penetration test scenarios
- Compliance test matrix
- Automation recommendations

---

## DevOps Engineer Tools

### `devops_design_cicd`

Designs CI/CD pipeline with security gates.

**Input Schema:**
```json
{
  "project_name": "string (optional)",
  "tech_stack": "string[] (optional)",
  "repository_platform": "enum: github|gitlab|azure-devops|bitbucket (optional)",
  "deployment_target": "enum: kubernetes|docker|vm|serverless|paas (optional)",
  "security_requirements": "string[] (optional)"
}
```

**Output:**
- Pipeline stages (build, test, security, deploy)
- Security scan integration (SAST, DAST, SCA)
- Deployment strategies
- Rollback procedures
- Infrastructure as Code templates

---

## Project Manager Tools

### `pm_create_sprint_plan`

Creates sprint planning with security priorities.

**Input Schema:**
```json
{
  "project_name": "string (optional)",
  "user_stories": "object[] (optional) - Stories with priority (High/Medium/Low or P0-P3)",
  "team_size": "number (optional, default: 5)",
  "sprint_duration": "number (optional, default: 2 weeks)",
  "team_velocity": "number (optional) - Story points per sprint"
}
```

**Priority Normalization:**
- `Critical`, `P0`, `urgent` → P0
- `High`, `P1` → P1
- `Medium`, `P2`, `normal` → P2
- `Low`, `P3` → P3

**Output:**
- Sprint backlog
- Story point allocation
- Risk assessment
- Dependencies
- Security task priorities

---

## Orchestration Tools

### `orchestrate_ssdlc_pipeline`

Orchestrates complete SSDLC pipeline across all roles.

**Input Schema:**
```json
{
  "project_name": "string (required)",
  "project_description": "string (required)",
  "business_goals": "string[] (required)",
  "tech_stack": "string[] (required)",
  "team_size": "number (required)",
  "sprint_duration": "number (required)"
}
```

**Pipeline Phases:**
1. **Requirements Analysis** (BA)
2. **Architecture Design** (Tech Lead)
3. **Threat Modeling** (Security)
4. **Secure Code Planning** (Tech Lead)
5. **Test Strategy** (QA)
6. **Sprint Planning** (PM)
7. **CI/CD Design** (DevOps)

**Output:**
- Complete phase-by-phase plan
- Tool invocation sequence
- Dependencies between phases
- Quality gates
- Timeline estimates

---

## Coding Support Tools

### `generate_secure_code`

Generates secure code implementation from requirements.

**Input Schema:**
```json
{
  "requirements": "string",
  "language": "string",
  "security_patterns": "string[]"
}
```

---

### `review_file`

Reviews an entire file for security vulnerabilities.

**Input Schema:**
```json
{
  "file_path": "string",
  "language": "string"
}
```

---

### `suggest_fix`

Suggests fixes for identified security vulnerabilities.

**Input Schema:**
```json
{
  "finding": "object - Security finding from review",
  "context": "string"
}
```

---

## Error Handling

All tools return structured errors:
```json
{
  "error": true,
  "code": "VALIDATION_ERROR",
  "message": "Invalid input: project_description is required",
  "details": {}
}
```

Common error codes:
- `VALIDATION_ERROR` - Invalid input schema
- `NOT_FOUND` - Resource not found
- `SECURITY_KB_ERROR` - Knowledge base query failed
- `INTERNAL_ERROR` - Unexpected server error
