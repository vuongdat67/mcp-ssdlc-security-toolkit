/**
 * DevOps Tool: Design CI/CD Pipeline
 * 
 * Generates CI/CD pipeline configuration with security scanning
 */

import { z } from "zod";
import { createLogger } from "@mcp-ssdlc/core";

const logger = createLogger("devops-design-cicd");

// Make all fields optional with defaults for standalone usage
const DesignCICDSchema = z.object({
  project_name: z.string().optional().default("Secure Application"),
  repository_platform: z.enum(["github", "gitlab", "azure-devops", "bitbucket"]).optional().default("github"),
  tech_stack: z.array(z.string()).optional().default(["Node.js", "TypeScript", "Docker"]),
  deployment_target: z.enum(["kubernetes", "docker", "vm", "serverless", "paas"]).optional().default("kubernetes"),
  security_requirements: z.array(z.string()).optional().default(["SAST", "DAST", "Dependency Scanning"]),
});

export async function devopsDesignCICD(args: unknown) {
  try {
    // Handle empty input
    const normalizedArgs = (args && typeof args === 'object' && Object.keys(args).length > 0)
      ? args
      : {};

    const input = DesignCICDSchema.parse(normalizedArgs);

    logger.info(`Designing CI/CD pipeline for: ${input.project_name}`);

    const pipeline = generatePipelineConfig(input);
    const securityStages = generateSecurityStages(input);
    const deploymentStrategy = generateDeploymentStrategy(input);

    const output = `# CI/CD Pipeline Design: ${input.project_name}
Generated: ${new Date().toISOString()}
Platform: ${input.repository_platform}
Deployment Target: ${input.deployment_target}

## Pipeline Overview

\`\`\`mermaid
graph LR
    A[Code Push] --> B[Build]
    B --> C[Test]
    C --> D[Security Scan]
    D --> E[Package]
    E --> F[Deploy Staging]
    F --> G[Integration Tests]
    G --> H{Manual Approval}
    H -->|Approved| I[Deploy Production]
    H -->|Rejected| J[Rollback]
\`\`\`

## Pipeline Configuration

${pipeline}

## Security Stages

${securityStages}

## Deployment Strategy

${deploymentStrategy}

## Environment Variables

Required secrets to configure:
${generateSecrets(input).map((s, i) => `${i + 1}. \`${s.name}\` - ${s.description}`).join('\n')}

## Monitoring & Alerts

- **Application Monitoring**: APM for performance metrics
- **Security Monitoring**: WAF logs, security scan results
- **Infrastructure Monitoring**: Resource utilization, uptime
- **Log Aggregation**: Centralized logging for all services
- **Alerting**: Slack/Email notifications for failures

## Rollback Strategy

1. **Automatic Rollback**: On deployment failure
2. **Manual Rollback**: Via pipeline trigger
3. **Canary Rollback**: Gradual traffic shift back
4. **Database Rollback**: Migration revert scripts

## Compliance Checks

- Code quality gates (>80% coverage)
- Security vulnerability threshold (no HIGH/CRITICAL)
- License compliance verification
- SBOM (Software Bill of Materials) generation

---

**Next Steps:**
1. Review pipeline configuration
2. Configure repository secrets
3. Set up deployment environments
4. Test pipeline with sample deployment
5. Configure monitoring dashboards
`;

    return {
      content: [
        {
          type: "text",
          text: output,
        },
      ],
    };
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new Error(`Validation failed: ${error.errors.map(e => e.message).join(', ')}`);
    }
    throw error;
  }
}

function generatePipelineConfig(input: z.infer<typeof DesignCICDSchema>): string {
  const platform = input.repository_platform;

  if (platform === "github") {
    return `### GitHub Actions Workflow

\`\`\`yaml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Environment
        run: |
          ${input.tech_stack.includes("node") ? "node --version" : ""}
          ${input.tech_stack.includes("python") ? "python --version" : ""}
      
      - name: Install Dependencies
        run: |
          ${input.tech_stack.includes("node") ? "npm ci" : ""}
          ${input.tech_stack.includes("python") ? "pip install -r requirements.txt" : ""}
      
      - name: Build
        run: npm run build
      
      - name: Unit Tests
        run: npm test -- --coverage
      
      - name: Upload Coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info
  
  security:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: SAST Scan
        uses: github/codeql-action/analyze@v2
      
      - name: Dependency Check
        run: npm audit --production
      
      - name: Container Scan
        if: contains(inputs.tech_stack, 'docker')
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: \${docker.io/library/\${{ inputs.project_name }}:latest}
  
  deploy:
    needs: [build, security]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to ${input.deployment_target}
        run: |
          echo "Deploying to ${input.deployment_target}"
\`\`\``;
  }

  return "Platform-specific configuration...";
}

function generateSecurityStages(input: z.infer<typeof DesignCICDSchema>): string {
  return `### 1. Static Application Security Testing (SAST)
- **Tool**: CodeQL / Semgrep / SonarQube
- **Scope**: Scan source code for vulnerabilities
- **Threshold**: Block on HIGH/CRITICAL findings

### 2. Dependency Scanning (SCA)
- **Tool**: npm audit / pip-audit / Snyk
- **Scope**: Identify vulnerable dependencies
- **Action**: Fail build on known CVEs

### 3. Secrets Scanning
- **Tool**: GitGuardian / TruffleHog
- **Scope**: Detect hardcoded credentials
- **Action**: Block commit with secrets

### 4. Container Security
- **Tool**: Trivy / Clair
- **Scope**: Scan Docker images
- **Layers**: Base image + application layers

### 5. Dynamic Application Security Testing (DAST)
- **Tool**: OWASP ZAP / Burp Suite
- **Scope**: Runtime vulnerability testing
- **Environment**: Staging only

### 6. Infrastructure as Code Scanning
- **Tool**: Checkov / tfsec
- **Scope**: Terraform/CloudFormation templates
- **Compliance**: CIS Benchmarks`;
}

function generateDeploymentStrategy(input: z.infer<typeof DesignCICDSchema>): string {
  const target = input.deployment_target;

  if (target === "kubernetes") {
    return `### Kubernetes Deployment

**Strategy**: Blue-Green Deployment with Canary

\`\`\`yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${input.project_name}
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      containers:
      - name: app
        image: ${input.project_name}:latest
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
\`\`\`

**Rollout Process:**
1. Deploy to 10% of pods (Canary)
2. Monitor metrics for 10 minutes
3. If healthy, gradually increase to 50%
4. Final rollout to 100%
5. Keep previous version for quick rollback`;
  }

  return `Deployment to ${target} with progressive rollout`;
}

function generateSecrets(input: z.infer<typeof DesignCICDSchema>): Array<{ name: string; description: string }> {
  const secrets = [
    { name: "DEPLOY_TOKEN", description: "Deployment authentication token" },
    { name: "DATABASE_URL", description: "Production database connection string" },
    { name: "API_KEYS", description: "Third-party service API keys" },
  ];

  if (input.deployment_target === "kubernetes") {
    secrets.push(
      { name: "KUBECONFIG", description: "Kubernetes cluster configuration" },
      { name: "REGISTRY_TOKEN", description: "Container registry credentials" }
    );
  }

  if (input.tech_stack.some(t => t.includes("aws"))) {
    secrets.push(
      { name: "AWS_ACCESS_KEY_ID", description: "AWS access key" },
      { name: "AWS_SECRET_ACCESS_KEY", description: "AWS secret key" }
    );
  }

  return secrets;
}
