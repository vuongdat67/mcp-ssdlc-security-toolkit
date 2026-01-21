/**
 * Review File Tool
 * 
 * Reviews an entire file for security vulnerabilities.
 * Provides comprehensive analysis with line-by-line findings.
 */

import { z } from 'zod';
import { readFileSync, existsSync } from 'fs';
import { extname } from 'path';
import type { MCPToolResult } from '@mcp-ssdlc/core';
import { createLogger } from '@mcp-ssdlc/core';

const logger = createLogger('ReviewFile');

// ============================================================================
// Input Schema
// ============================================================================

const ReviewFileInputSchema = z.object({
  filePath: z.string().optional().describe('Path to the file to review'),
  code: z.string().optional().describe('Code content to review (if file path not provided)'),
  language: z.string().optional().describe('Programming language (auto-detected if file path provided)'),
  mode: z.enum(['quick', 'deep']).optional().default('quick').describe('Review mode'),
  includeMetrics: z.boolean().optional().default(true).describe('Include code metrics'),
});

type ReviewFileInput = z.infer<typeof ReviewFileInputSchema>;

// ============================================================================
// Language Detection
// ============================================================================

const extensionToLanguage: Record<string, string> = {
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.jsx': 'javascript',
  '.py': 'python',
  '.go': 'go',
  '.java': 'java',
  '.cs': 'csharp',
  '.rb': 'ruby',
  '.php': 'php',
  '.rs': 'rust',
  '.swift': 'swift',
  '.kt': 'kotlin',
};

// ============================================================================
// Security Patterns
// ============================================================================

interface SecurityPattern {
  name: string;
  regex: RegExp;
  cwe: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
}

const universalPatterns: SecurityPattern[] = [
  {
    name: 'Hardcoded Secret',
    regex: /(password|secret|api_?key|token|private_?key)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    cwe: 'CWE-798',
    severity: 'HIGH',
    description: 'Potential hardcoded secret detected',
    recommendation: 'Use environment variables or a secrets manager',
  },
  {
    name: 'Eval Usage',
    regex: /\beval\s*\(/gi,
    cwe: 'CWE-95',
    severity: 'CRITICAL',
    description: 'Use of eval() can lead to code injection',
    recommendation: 'Avoid eval(); use safer alternatives',
  },
  {
    name: 'SQL String Concatenation',
    regex: /(?:execute|query|cursor\.execute)\s*\([^)]*\+[^)]*(?:request|input|user|param)/gi,
    cwe: 'CWE-89',
    severity: 'CRITICAL',
    description: 'Potential SQL injection via string concatenation',
    recommendation: 'Use parameterized queries or prepared statements',
  },
  {
    name: 'Insecure Random',
    regex: /Math\.random\(\)|random\.random\(\)/gi,
    cwe: 'CWE-330',
    severity: 'MEDIUM',
    description: 'Using non-cryptographic random for security-sensitive operations',
    recommendation: 'Use crypto.randomBytes() or secrets module for security',
  },
  {
    name: 'HTTP (not HTTPS)',
    regex: /http:\/\/(?!localhost|127\.0\.0\.1)/gi,
    cwe: 'CWE-319',
    severity: 'MEDIUM',
    description: 'Cleartext HTTP URL detected',
    recommendation: 'Use HTTPS for all remote connections',
  },
  {
    name: 'Debug Mode',
    regex: /debug\s*[=:]\s*true|DEBUG\s*=\s*True/gi,
    cwe: 'CWE-489',
    severity: 'MEDIUM',
    description: 'Debug mode may be enabled in production',
    recommendation: 'Ensure debug mode is disabled in production',
  },
  {
    name: 'TODO Security',
    regex: /(?:TODO|FIXME|XXX|HACK).*(?:security|vuln|auth|password|secret)/gi,
    cwe: 'CWE-546',
    severity: 'LOW',
    description: 'Security-related TODO comment found',
    recommendation: 'Address security TODO before deployment',
  },
];

const jsPatterns: SecurityPattern[] = [
  {
    name: 'innerHTML Assignment',
    regex: /\.innerHTML\s*=/gi,
    cwe: 'CWE-79',
    severity: 'HIGH',
    description: 'Direct innerHTML assignment may lead to XSS',
    recommendation: 'Use textContent or sanitize with DOMPurify',
  },
  {
    name: 'document.write',
    regex: /document\.write\s*\(/gi,
    cwe: 'CWE-79',
    severity: 'HIGH',
    description: 'document.write can lead to XSS',
    recommendation: 'Use DOM manipulation methods instead',
  },
  {
    name: 'Prototype Pollution',
    regex: /\[['"]__proto__['"]\]|\[['"]constructor['"]\]|\[['"]prototype['"]\]/gi,
    cwe: 'CWE-1321',
    severity: 'HIGH',
    description: 'Potential prototype pollution vulnerability',
    recommendation: 'Validate object keys, use Object.create(null)',
  },
  {
    name: 'Child Process Exec',
    regex: /child_process\.exec\s*\(|exec\s*\([^)]*(?:req|input|user)/gi,
    cwe: 'CWE-78',
    severity: 'CRITICAL',
    description: 'Command injection risk with child_process.exec',
    recommendation: 'Use execFile with argument array instead',
  },
];

const pythonPatterns: SecurityPattern[] = [
  {
    name: 'Pickle Deserialization',
    regex: /pickle\.load|pickle\.loads|cPickle\.load/gi,
    cwe: 'CWE-502',
    severity: 'CRITICAL',
    description: 'Pickle deserialization of untrusted data is dangerous',
    recommendation: 'Use JSON or other safe serialization formats',
  },
  {
    name: 'Shell=True',
    regex: /subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True/gi,
    cwe: 'CWE-78',
    severity: 'HIGH',
    description: 'shell=True can lead to command injection',
    recommendation: 'Use shell=False with argument list',
  },
  {
    name: 'YAML Load',
    regex: /yaml\.load\s*\([^)]*(?!Loader\s*=)/gi,
    cwe: 'CWE-502',
    severity: 'HIGH',
    description: 'yaml.load without safe Loader is dangerous',
    recommendation: 'Use yaml.safe_load() instead',
  },
  {
    name: 'Assert Statement',
    regex: /^\s*assert\s+/gim,
    cwe: 'CWE-617',
    severity: 'LOW',
    description: 'Assert statements are removed with -O flag',
    recommendation: 'Use proper validation for security checks',
  },
];

// ============================================================================
// Review Implementation
// ============================================================================

export async function reviewFile(input: unknown): Promise<MCPToolResult> {
  logger.info('Starting file security review');

  // Validate input
  const validation = ReviewFileInputSchema.safeParse(input);
  if (!validation.success) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Validation failed',
          details: validation.error.format()
        }, null, 2)
      }]
    };
  }

  const { filePath, code, language, mode, includeMetrics } = validation.data;

  // Get code content
  let codeContent: string;
  let detectedLanguage: string;
  let fileName = 'inline-code';

  if (filePath) {
    if (!existsSync(filePath)) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ error: `File not found: ${filePath}` }, null, 2)
        }]
      };
    }
    codeContent = readFileSync(filePath, 'utf-8');
    const ext = extname(filePath).toLowerCase();
    detectedLanguage = language || extensionToLanguage[ext] || 'unknown';
    fileName = filePath;
  } else if (code) {
    codeContent = code;
    detectedLanguage = language || 'unknown';
  } else {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({ error: 'Either filePath or code must be provided' }, null, 2)
      }]
    };
  }

  const lines = codeContent.split('\n');

  // Get patterns for this language
  const patterns = [...universalPatterns];
  if (detectedLanguage === 'javascript' || detectedLanguage === 'typescript') {
    patterns.push(...jsPatterns);
  } else if (detectedLanguage === 'python') {
    patterns.push(...pythonPatterns);
  }

  // Scan for vulnerabilities
  const findings: any[] = [];

  for (const pattern of patterns) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const matches = line.match(pattern.regex);
      
      if (matches) {
        findings.push({
          line_number: i + 1,
          line_content: line.trim().substring(0, 100),
          pattern: pattern.name,
          cwe: pattern.cwe,
          severity: pattern.severity,
          description: pattern.description,
          recommendation: pattern.recommendation,
        });
      }
    }
  }

  // Sort by severity
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Calculate metrics
  const metrics = includeMetrics ? {
    total_lines: lines.length,
    code_lines: lines.filter(l => l.trim() && !l.trim().startsWith('//')).length,
    comment_lines: lines.filter(l => l.trim().startsWith('//')).length,
  } : undefined;

  // Calculate summary
  const summary = {
    critical: findings.filter(f => f.severity === 'CRITICAL').length,
    high: findings.filter(f => f.severity === 'HIGH').length,
    medium: findings.filter(f => f.severity === 'MEDIUM').length,
    low: findings.filter(f => f.severity === 'LOW').length,
    total: findings.length,
  };

  const riskScore = Math.min(10, 
    summary.critical * 3 + 
    summary.high * 2 + 
    summary.medium * 1 + 
    summary.low * 0.5
  );

  const result = {
    file: fileName,
    language: detectedLanguage,
    mode,
    metrics,
    summary,
    risk_score: Math.round(riskScore * 10) / 10,
    risk_level: riskScore >= 7 ? 'HIGH' : riskScore >= 4 ? 'MEDIUM' : 'LOW',
    findings,
    recommendations: generateRecommendations(findings),
  };

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(result, null, 2)
    }]
  };
}

function generateRecommendations(findings: any[]): string[] {
  const recommendations: string[] = [];
  const cwes = new Set(findings.map(f => f.cwe));

  if (cwes.has('CWE-89')) {
    recommendations.push('Implement parameterized queries for all database operations');
  }
  if (cwes.has('CWE-79')) {
    recommendations.push('Use contextual output encoding for all user-controlled data');
  }
  if (cwes.has('CWE-78')) {
    recommendations.push('Avoid shell execution; use library functions instead');
  }
  if (cwes.has('CWE-798')) {
    recommendations.push('Move all secrets to environment variables or a secrets manager');
  }
  if (cwes.has('CWE-502')) {
    recommendations.push('Use safe serialization formats (JSON) instead of pickle/yaml.load');
  }

  if (recommendations.length === 0) {
    recommendations.push('Continue following secure coding practices');
  }

  return recommendations;
}
