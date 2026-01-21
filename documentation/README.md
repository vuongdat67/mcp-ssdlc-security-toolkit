# MCP SSDLC Security Toolkit - Documentation

## Overview

MCP SSDLC Security Toolkit is a Model Context Protocol (MCP) server system designed to automate 85-95% of the SSDLC (Secure Software Development Life Cycle) planning phase. It orchestrates multiple professional roles to generate comprehensive security planning artifacts.

## Quick Links

- [Getting Started](./getting-started.md) - First-time setup and basic usage
- [Architecture](./architecture.md) - System design and component overview
- [Tools Reference](./tools-reference.md) - Complete MCP tools documentation
- [Integration Guide](./integration.md) - VS Code, Claude Desktop, and Docker setup
- [API Reference](./api-reference.md) - TypeScript APIs and schemas
- [Contributing](./contributing.md) - How to contribute to this project

## Key Features

### Multi-Role SSDLC Orchestration
- **Business Analyst (BA)**: Requirements analysis, user stories, security-focused analysis
- **Tech Lead**: Architecture design with trust boundaries
- **Security Engineer**: STRIDE threat modeling, code security review
- **QA Engineer**: Test strategy design with OWASP-based security tests
- **DevOps Engineer**: CI/CD pipeline with security gates
- **Project Manager**: Sprint planning with security priorities

### 13 MCP Tools Available
| Tool | Role | Description |
|------|------|-------------|
| `ba_analyze_requirements` | BA | Analyze requirements and create user stories |
| `ba_analyze_requirements_security` | BA | Security-focused requirements with STRIDE/abuse cases |
| `ba_create_business_case` | BA | Create business case for features |
| `techlead_design_architecture` | Tech Lead | Design system architecture with trust boundaries |
| `security_review_code` | Security | Review code for security vulnerabilities |
| `security_threat_model` | Security | Perform STRIDE threat modeling |
| `qa_design_test_strategy` | QA | Design comprehensive security test strategy |
| `pm_create_sprint_plan` | PM | Create sprint planning with priorities |
| `devops_design_cicd` | DevOps | Design CI/CD pipeline with security gates |
| `orchestrate_ssdlc_pipeline` | Orchestrator | Full SSDLC pipeline orchestration |
| `generate_secure_code` | Coding | Generate secure code from requirements |
| `review_file` | Security | Review file for security vulnerabilities |
| `suggest_fix` | Security | Suggest fixes for security issues |

## Installation

### Using pnpm (Recommended)
```bash
pnpm add @mcp-ssdlc/ssdlc-planner
```

### Using Docker
```bash
docker pull ghcr.io/yourusername/mcp-ssdlc-planner:latest
docker run --rm -it ghcr.io/yourusername/mcp-ssdlc-planner:latest
```

### From Source
```bash
git clone https://github.com/yourusername/mcp-ssdlc-security-toolkit.git
cd mcp-ssdlc-security-toolkit
pnpm install
pnpm build
pnpm seed  # Initialize security knowledge base
```

## Configuration

### VS Code Integration
Create `.vscode/mcp.json`:
```json
{
  "servers": {
    "mcp-ssdlc-planner": {
      "command": "node",
      "args": ["${workspaceFolder}/packages/ssdlc-planner/dist/index.js"]
    }
  }
}
```

### Claude Desktop
Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "mcp-ssdlc-planner": {
      "command": "node",
      "args": ["path/to/packages/ssdlc-planner/dist/index.js"]
    }
  }
}
```

## Project Structure
```
mcp-ssdlc-security-toolkit/
├── packages/
│   ├── core/              # Shared types, utilities, validators
│   ├── security-kb/       # CVE/CWE/OWASP knowledge base
│   └── ssdlc-planner/     # Main MCP server
├── config/
│   ├── domains/           # Domain-specific security configurations
│   └── threat-patterns/   # Security threat patterns
├── data/
│   ├── cwec/              # CWE database
│   ├── nist/              # NVD CVE data
│   └── top10_owasp/       # OWASP Top 10 2025
├── docker/                # Docker configurations
└── documentation/         # This folder
```

## License

MIT License - See [LICENSE](../LICENSE) for details.

## Support

- GitHub Issues: Report bugs and feature requests
- Discussions: Ask questions and share ideas

## Reference

- [CWE MITRE](https://cwe.mitre.org/data/downloads.html)

- [NIST GOV](https://nvd.nist.gov/vuln/data-feeds#APIS)

- [TOP10 OWASP](https://github.com/OWASP/Top10/tree/master/2025/docs/en)

- [cwe list](https://github.com/alejandrosaenz117/fetch-cwe-list)

- [cwe list V5](https://github.com/CVEProject/cvelistV5)


