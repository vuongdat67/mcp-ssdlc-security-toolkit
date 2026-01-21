# Security Policy

## 🔒 Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## 🚨 Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security vulnerabilities via one of these methods:

1. **GitHub Security Advisories** (Preferred):
   - Go to [Security Advisories](https://github.com/vuongdat67/mcp-ssdlc-security-toolkit/security/advisories/new)
   - Click "Report a vulnerability"
   - Fill out the form with details

2. **Email**:
   - Send details to: security@example.com (replace with actual email)
   - Use subject: `[SECURITY] MCP SSDLC Vulnerability Report`

### What to Include

- **Description**: Clear description of the vulnerability
- **Impact**: What could an attacker achieve?
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Affected Versions**: Which versions are affected?
- **Suggested Fix**: If you have ideas for remediation

### Example Report

```markdown
## Vulnerability: SQL Injection in security_review_code

### Description
The `security_review_code` tool is vulnerable to SQL injection when 
processing malformed language parameters.

### Impact
An attacker could execute arbitrary SQL queries against the security
database, potentially extracting or modifying CVE/CWE data.

### Steps to Reproduce
1. Call the tool with: `{ "language": "'; DROP TABLE cves;--" }`
2. Observe SQL error in logs

### Affected Versions
- 1.0.0
- 1.0.1

### Suggested Fix
Use parameterized queries in `security-kb/src/intelligence.ts`
```

## ⏱️ Response Timeline

| Action | Timeline |
|--------|----------|
| Initial Response | Within 48 hours |
| Triage & Assessment | Within 1 week |
| Fix Development | Depends on severity |
| Disclosure | After fix is released |

### Severity Levels

| Severity | Response Time | Description |
|----------|--------------|-------------|
| Critical | 24-48 hours | RCE, data breach, full system compromise |
| High | 1 week | Privilege escalation, significant data exposure |
| Medium | 2 weeks | Limited impact, requires specific conditions |
| Low | 1 month | Minor issues, defense-in-depth improvements |

## 🏆 Recognition

We appreciate security researchers who help improve our security:

- **Hall of Fame**: Researchers who report valid vulnerabilities will be credited (with permission)
- **Responsible Disclosure**: We commit to transparent communication throughout the process

## 📋 Security Best Practices for Users

### Deployment

1. **Run with minimal privileges**: Use non-root users in Docker
2. **Network isolation**: Don't expose MCP servers to the internet
3. **Keep updated**: Regularly update to the latest version
4. **Audit logs**: Monitor tool execution logs for anomalies

### Configuration

```json
{
  "mcpServers": {
    "ssdlc-planner": {
      "command": "node",
      "args": ["/path/to/dist/index.js"],
      "env": {
        "NODE_ENV": "production",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

### Data Handling

- The security database contains public CVE/CWE data
- No sensitive user data is stored by default
- Review generated artifacts before sharing

## 🔐 Security Features

This toolkit implements several security measures:

| Feature | Description |
|---------|-------------|
| Input Validation | Zod schemas validate all tool inputs |
| Path Traversal Prevention | File paths are sanitized |
| SQL Injection Prevention | Parameterized queries in security-kb |
| No Code Execution | Tools generate artifacts, not executable code |
| Minimal Permissions | Docker runs as non-root user |

## 📚 Security Resources

- [OWASP MCP Security Guide](#)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Docker Security](https://docs.docker.com/engine/security/)

---

*This security policy is subject to change. Last updated: January 2026*
