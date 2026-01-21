# Getting Started with MCP SSDLC Security Toolkit

## Prerequisites

- **Node.js**: v20.0.0 or higher
- **pnpm**: v8.0.0 or higher
- **Docker** (optional): For containerized deployment

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/vuongdat67/mcp-ssdlc-security-toolkit.git
cd mcp-ssdlc-security-toolkit
```

### 2. Install Dependencies
```bash
pnpm install
```

### 3. Build All Packages
```bash
pnpm build
```

### 4. Initialize Security Knowledge Base
```bash
cd packages/security-kb
pnpm seed
```

This creates a SQLite database with:
- 969+ CWE entries
- OWASP Top 10 2025 mappings
- Threat patterns and detection rules
- CVE references

## Quick Test

### Verify Installation
```bash
node packages/ssdlc-planner/dist/index.js
```

You should see:
```
[INFO] Starting MCP SSDLC Planner Server
[INFO] Registered 13 tools across 6 roles + orchestration
[SUCCESS] MCP SSDLC Planner Server running
```

### Run Tests
```bash
pnpm test
```

Expected: 59/59 tests passing (100%)

## Integration Options

### Option 1: VS Code Copilot

1. Create `.vscode/mcp.json`:
```json
{
  "servers": {
    "mcp-ssdlc-planner": {
      "type": "stdio",
      "command": "node",
      "args": ["${workspaceFolder}/packages/ssdlc-planner/dist/index.js"]
    }
  }
}
```

2. Open VS Code Command Palette
3. Search "MCP: List Servers"
4. Verify "mcp-ssdlc-planner" appears with status "Running"

### Option 2: Claude Desktop

1. Open Claude Desktop settings
2. Add to `mcpServers`:
```json
{
  "mcp-ssdlc-planner": {
    "command": "node",
    "args": ["D:/source/v1/lastest/packages/ssdlc-planner/dist/index.js"]
  }
}
```

3. Restart Claude Desktop
4. Check MCP icon shows 13 tools available

### Option 3: Docker

```bash
# Build image
cd docker
docker compose up -d

# Or manually
docker build -f docker/Dockerfile -t mcp-ssdlc-planner .
docker run --rm -it mcp-ssdlc-planner
```

## Your First SSDLC Analysis

Once integrated, ask Claude or Copilot:

```
Using the mcp-ssdlc-planner tools, analyze requirements for:
- Project: OAuth2 Authentication Provider
- Stakeholders: End users, Developers, Security team
- Business goals: Secure authentication, Multi-factor support, API access
```

This will:
1. Generate user stories with security acceptance criteria
2. Perform STRIDE threat analysis
3. Create architecture with trust boundaries
4. Design test strategy with OWASP coverage
5. Plan sprints with security priorities

## Next Steps

- [Tools Reference](./tools-reference.md) - Explore all 13 tools
- [Architecture](./architecture.md) - Understand system design
- [Integration Guide](./integration.md) - Advanced configuration
