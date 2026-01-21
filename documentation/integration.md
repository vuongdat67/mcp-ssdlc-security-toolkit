# Integration Guide

## Overview

MCP SSDLC Security Toolkit can be integrated with multiple clients:
- VS Code with GitHub Copilot
- Claude Desktop
- Docker deployments
- Custom MCP clients

---

## VS Code Integration

### Prerequisites
- VS Code 1.99+ with GitHub Copilot extension
- MCP support enabled (Preview feature)

### Configuration

1. **Create `.vscode/mcp.json`** in your project root:

```json
{
  "servers": {
    "mcp-ssdlc-planner": {
      "type": "stdio",
      "command": "node",
      "args": ["${workspaceFolder}/packages/ssdlc-planner/dist/index.js"],
      "env": {
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

2. **Verify Connection**:
   - Open Command Palette (Ctrl+Shift+P)
   - Run "MCP: List Servers"
   - Check "mcp-ssdlc-planner" shows "Running"

3. **View Logs**:
   - Open "Output" panel
   - Select "MCP" from dropdown
   - Look for: `Discovered 13 tools`

### Usage in Copilot Chat

```markdown
@workspace Using mcp-ssdlc-planner, analyze requirements for:
- Project: User Authentication Service
- Stakeholders: End users, Admins, API consumers
- Goals: Secure login, MFA support, Session management
```

---

## Claude Desktop Integration

### Prerequisites
- Claude Desktop app
- Admin access to config file

### Configuration

1. **Locate config file**:
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

2. **Add MCP server**:

```json
{
  "mcpServers": {
    "mcp-ssdlc-planner": {
      "command": "node",
      "args": ["D:/path/to/packages/ssdlc-planner/dist/index.js"],
      "env": {
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

3. **Restart Claude Desktop**

4. **Verify**: Click the MCP icon (🔧) → Should show 13 tools

### Using with Claude

Simply ask Claude to use the tools:

```
Using the SSDLC tools, create a threat model for a JWT authentication system
with the following architecture:
- Frontend: React SPA
- Backend: Node.js API
- Database: PostgreSQL
- Auth: JWT with refresh tokens
```

---

## Docker Integration

### Quick Start

```bash
# Production image
docker run --rm -it ghcr.io/yourusername/mcp-ssdlc-planner:latest

# From source
cd docker
docker compose up -d
```

### Docker Compose with MCP Client

```yaml
# docker-compose.mcp.yml
services:
  mcp-ssdlc-planner:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    stdin_open: true
    tty: true
    volumes:
      - security-db:/app/packages/security-kb/data
      - ./config/domains:/app/config/domains:ro
    environment:
      - LOG_LEVEL=info
      
volumes:
  security-db:
```

### Connecting External MCP Client

```bash
# Run container with named pipe (Windows)
docker run --rm -i mcp-ssdlc-planner:latest | your-mcp-client

# Run with Unix socket (Linux/macOS)
docker run --rm -i -v /tmp/mcp:/tmp/mcp mcp-ssdlc-planner:latest
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `NODE_ENV` | `development` | Environment: `development`, `production` |
| `SECURITY_DB_PATH` | `./data/security.db` | Path to security knowledge base |
| `DOMAIN_CONFIG_PATH` | `./config/domains` | Path to domain configurations |

---

## Custom MCP Client Integration

### Protocol

MCP SSDLC uses standard MCP protocol over stdio:
- **Transport**: stdio (stdin/stdout)
- **Format**: JSON-RPC 2.0
- **Encoding**: UTF-8

### Handshake

```json
// Client → Server: Initialize
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": { "name": "your-client", "version": "1.0.0" }
  }
}

// Server → Client: Initialize response
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": { "tools": {} },
    "serverInfo": { "name": "mcp-ssdlc-planner", "version": "1.0.0" }
  }
}
```

### List Tools

```json
// Client → Server
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list"
}

// Server → Client
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "ba_analyze_requirements",
        "description": "...",
        "inputSchema": { ... }
      }
      // ... 12 more tools
    ]
  }
}
```

### Call Tool

```json
// Client → Server
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "security_review_code",
    "arguments": {
      "code_snippet": "eval(userInput)",
      "language": "javascript"
    }
  }
}
```

---

## Troubleshooting

### VS Code: "Server not running"

1. Check Node.js version: `node --version` (must be 20+)
2. Verify build: `ls packages/ssdlc-planner/dist/index.js`
3. Test manually: `node packages/ssdlc-planner/dist/index.js`

### Claude Desktop: "Tools not loading"

1. Check config JSON syntax
2. Verify absolute path to index.js
3. Restart Claude Desktop completely
4. Check Claude Desktop logs

### Docker: "Module not found"

1. Rebuild image: `docker build --no-cache ...`
2. Check Dockerfile copies all node_modules
3. Verify `pnpm prune --prod` doesn't remove needed deps

### General: "security.db not found"

1. Run `pnpm seed` in security-kb package
2. Check SECURITY_DB_PATH environment variable
3. Ensure write permissions on data directory
