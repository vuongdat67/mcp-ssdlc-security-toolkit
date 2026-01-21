# System Architecture

## Overview

MCP SSDLC Security Toolkit follows a monorepo architecture with three core packages that work together to provide comprehensive SSDLC planning automation.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        MCP Client (Claude/VS Code)                       │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ stdio (JSON-RPC)
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         ssdlc-planner (MCP Server)                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐ │
│  │  BA Tools   │ │ TechLead    │ │  Security   │ │    Orchestrator     │ │
│  │  (3 tools)  │ │   Tools     │ │   Tools     │ │    (Pipeline)       │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────────────┘ │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐ │
│  │  QA Tools   │ │  PM Tools   │ │DevOps Tools │ │   Coding Tools      │ │
│  │  (1 tool)   │ │  (1 tool)   │ │  (1 tool)   │ │    (3 tools)        │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────────────┘ │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────────┐
│        core         │ │    security-kb      │ │   config/domains    │
│ (Types, Validators) │ │ (CVE/CWE/OWASP DB)  │ │ (Domain Configs)    │
└─────────────────────┘ └─────────────────────┘ └─────────────────────┘
```

## Package Architecture

### @mcp-ssdlc/core

Shared foundation package providing:

```
packages/core/
├── src/
│   ├── types/
│   │   ├── mcp.types.ts       # MCP protocol types
│   │   ├── tools.types.ts     # Tool input/output schemas
│   │   └── ssdlc.types.ts     # SSDLC domain types
│   ├── utils/
│   │   ├── json-normalizer.ts # LLM output normalization
│   │   ├── validators.ts      # Zod schema validators
│   │   └── logger.ts          # Structured logging
│   └── index.ts
└── dist/                      # Compiled ESM output
```

Key Components:
- **Result Type**: `{ ok: true, value: T } | { ok: false, error: Error }`
- **JSON Normalizer**: Handles malformed JSON from LLM outputs
- **Validators**: Zod schemas for all tool inputs/outputs

### @mcp-ssdlc/security-kb

Security knowledge base with threat intelligence:

```
packages/security-kb/
├── src/
│   ├── database/
│   │   ├── schema.ts          # SQLite schema definitions
│   │   └── connection.ts      # sql.js wrapper
│   ├── parsers/
│   │   ├── cwe-parser.ts      # CWE XML parser
│   │   ├── cve-parser.ts      # NVD JSON parser
│   │   └── owasp-parser.ts    # OWASP Top 10 parser
│   ├── services/
│   │   ├── threat-patterns.ts # Pattern matching
│   │   └── intelligence.ts    # CVE/CWE queries
│   └── index.ts
├── scripts/
│   └── seed.ts                # Database seeding
└── data/
    └── security.db            # SQLite database (generated)
```

Database Schema:
```sql
-- Core tables
CREATE TABLE cwes (id, name, description, severity, ...);
CREATE TABLE owasp_categories (id, name, description, year);
CREATE TABLE cve_references (cwe_id, cve_id, cvss_score);
CREATE TABLE threat_patterns (pattern, cwe_id, language, confidence);
CREATE TABLE cwe_remediations (cwe_id, language, secure_example, insecure_example);

-- Mappings
CREATE TABLE cwe_owasp_mapping (cwe_id, owasp_id);
```

### @mcp-ssdlc/ssdlc-planner

Main MCP server with role-based tools:

```
packages/ssdlc-planner/
├── src/
│   ├── index.ts               # MCP server entry point
│   ├── tools/
│   │   ├── requirements/      # BA tools
│   │   ├── architecture/      # Tech Lead tools
│   │   ├── security/          # Security Engineer tools
│   │   ├── testing/           # QA tools
│   │   ├── pm/                # Project Manager tools
│   │   ├── devops/            # DevOps tools
│   │   ├── coding/            # Coding support tools
│   │   └── orchestration/     # Pipeline orchestrator
│   └── templates/             # Handlebars templates
├── __tests__/                 # Unit tests
└── templates/
    ├── requirements/
    ├── security/
    └── architecture/
```

## Data Flow

### Single Tool Invocation

```
Client Request
     │
     ▼
┌─────────────────┐
│ Input Validation│ ← Zod schema
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Tool Handler  │ ← Business logic
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌──────────┐
│ KB    │ │ Template │
│ Query │ │ Render   │
└───┬───┘ └────┬─────┘
    │          │
    └────┬─────┘
         ▼
┌─────────────────┐
│ JSON Response   │
└─────────────────┘
```

### Orchestrated Pipeline

```
orchestrate_ssdlc_pipeline
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│ Phase 1: Requirements (BA)                               │
│   Tool: ba_analyze_requirements                          │
│   Output: user_stories, acceptance_criteria              │
└────────────────────────┬────────────────────────────────┘
                         │ depends_on: []
                         ▼
┌─────────────────────────────────────────────────────────┐
│ Phase 2: Architecture (Tech Lead)                        │
│   Tool: techlead_design_architecture                     │
│   Output: components, trust_boundaries                   │
└────────────────────────┬────────────────────────────────┘
                         │ depends_on: [phase_1]
                         ▼
┌─────────────────────────────────────────────────────────┐
│ Phase 3: Threat Modeling (Security)                      │
│   Tool: security_threat_model                            │
│   Output: stride_analysis, mitigations                   │
└────────────────────────┬────────────────────────────────┘
                         │ depends_on: [phase_2]
                         ▼
              ... (Phases 4-7) ...
```

## Security Architecture

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│                    Untrusted Zone                        │
│  ┌───────────────────────────────────────────────────┐  │
│  │              Client Input (LLM Output)             │  │
│  └───────────────────────┬───────────────────────────┘  │
└──────────────────────────┼──────────────────────────────┘
                           │ JSON Normalization + Validation
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    Trusted Zone                          │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐  │
│  │ Tool Handlers │  │  Security KB  │  │  Templates  │  │
│  └───────────────┘  └───────────────┘  └─────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Input Validation

All inputs validated with Zod schemas:

```typescript
const AnalyzeRequirementsSchema = z.object({
  project_description: z.string().min(10).max(10000),
  stakeholders: z.array(z.string()).min(1).max(20),
  business_goals: z.array(z.string()).min(1).max(20),
  project_name: z.string().optional()
});
```

### Output Sanitization

- No user input directly in templates
- CWE/CVE data sanitized before storage
- Path traversal prevention on file operations

## Deployment Architecture

### Standalone Mode
```
[Node.js] → packages/ssdlc-planner/dist/index.js
                    ↓ stdio
            [MCP Client]
```

### Docker Mode
```
[Docker Container]
├── /app/packages/ssdlc-planner/dist/
├── /app/packages/security-kb/data/security.db
└── /app/config/domains/
           ↓ stdio
    [Docker Host MCP Client]
```

### Kubernetes (Future)
```
[Pod: mcp-ssdlc-planner]
├── Container: ssdlc-planner
├── Volume: security-kb-data (PVC)
└── ConfigMap: domain-configs
           ↓ TCP (planned)
    [MCP Gateway Service]
```
