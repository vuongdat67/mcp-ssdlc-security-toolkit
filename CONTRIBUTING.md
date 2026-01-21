# Contributing to MCP SSDLC Security Toolkit

Thank you for your interest in contributing! This document provides guidelines and information for contributors.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## 📜 Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Be kind, constructive, and professional in all interactions.

## 🚀 Getting Started

### Prerequisites

- **Node.js** 20 LTS or later
- **pnpm** 8.x or later
- **Git** 2.x or later

### Fork & Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/mcp-ssdlc-security-toolkit.git
cd mcp-ssdlc-security-toolkit

# Add upstream remote
git remote add upstream https://github.com/vuongdat67/mcp-ssdlc-security-toolkit.git
```

## 💻 Development Setup

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Seed security database
cd packages/security-kb && pnpm seed

# Run tests
pnpm test

# Start development mode (with watch)
pnpm dev
```

### Project Structure

```
packages/
├── core/              # Shared types, utilities, validators
├── security-kb/       # CVE/CWE/OWASP knowledge base
└── ssdlc-planner/     # Main MCP server with tools

config/
├── domains/           # Security domain definitions
└── threat-patterns/   # Detection patterns
```

## ✏️ Making Changes

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation
- `refactor/description` - Code refactoring

### Commit Messages

Follow [Conventional Commits](https://conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting, no code change
- `refactor`: Code restructuring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(security): add CWE-502 detection pattern
fix(planner): resolve JSON parsing error in orchestrator
docs(readme): update installation instructions
```

## 📏 Coding Standards

### TypeScript

- Enable strict mode
- Use Zod for runtime validation
- Prefer pure functions
- Document public APIs with JSDoc

```typescript
/**
 * Analyzes code for security vulnerabilities.
 * @param language - Programming language (e.g., "javascript", "python")
 * @param code - Source code to analyze
 * @returns Security findings with CWE/CVE mappings
 */
async function reviewCode(language: string, code: string): Promise<SecurityReviewResult> {
  // Implementation
}
```

### File Naming

- Source files: `kebab-case.ts` (e.g., `threat-model.ts`)
- Test files: `*.test.ts` (e.g., `threat-model.test.ts`)
- Types/Interfaces: `PascalCase` (e.g., `ThreatModel`)

### Linting & Formatting

```bash
# Run linting
pnpm lint

# Format code
pnpm format

# Check types
pnpm -r exec tsc --noEmit
```

## ✅ Testing

### Running Tests

```bash
# All tests
pnpm test

# With coverage
pnpm test -- --coverage

# Watch mode
pnpm test -- --watch

# Specific package
cd packages/ssdlc-planner && pnpm test
```

### Writing Tests

```typescript
import { describe, it, expect } from 'vitest';
import { reviewCode } from '../src/security-review';

describe('reviewCode', () => {
  it('should detect XSS vulnerability', async () => {
    const result = await reviewCode('javascript', 'el.innerHTML = userInput');
    
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].cwe.id).toBe('CWE-79');
  });

  it('should return empty findings for safe code', async () => {
    const result = await reviewCode('javascript', 'const x = 1 + 2');
    
    expect(result.findings).toHaveLength(0);
  });
});
```

### Coverage Targets

| Package | Target | Type |
|---------|--------|------|
| core | 80%+ | Unit |
| security-kb | 70%+ | Unit + Integration |
| ssdlc-planner | 60%+ | Unit + Integration |

## 🔄 Pull Request Process

1. **Create branch** from `develop`:
   ```bash
   git checkout develop
   git pull upstream develop
   git checkout -b feature/your-feature
   ```

2. **Make changes** and commit following conventions

3. **Test thoroughly**:
   ```bash
   pnpm lint
   pnpm test
   pnpm build
   ```

4. **Push and create PR**:
   ```bash
   git push origin feature/your-feature
   ```

5. **PR Requirements**:
   - Fill out the PR template completely
   - Link related issues
   - Ensure CI passes
   - Request review from maintainers

6. **Address review feedback** promptly

7. **Squash and merge** once approved

## 📦 Release Process

Releases are automated via GitHub Actions when version tags are pushed:

```bash
# Bump version (maintainers only)
npm version patch|minor|major

# Push tag
git push --follow-tags
```

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

## 🆘 Getting Help

- **Discussions**: GitHub Discussions for questions
- **Issues**: GitHub Issues for bugs/features
- **Discord**: [Join our server](#) for real-time chat

## 🙏 Thank You!

Your contributions make this project better for everyone. We appreciate your time and effort!
