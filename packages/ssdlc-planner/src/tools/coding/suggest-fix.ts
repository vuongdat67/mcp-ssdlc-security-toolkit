/**
 * Suggest Fix Tool
 * 
 * Generates fix suggestions for security vulnerabilities.
 */

import { z } from 'zod';
import type { MCPToolResult } from '@mcp-ssdlc/core';
import { createLogger } from '@mcp-ssdlc/core';

const logger = createLogger('SuggestFix');

// ============================================================================
// Input Schema
// ============================================================================

const SuggestFixInputSchema = z.object({
  code: z.string().describe('The vulnerable code snippet'),
  vulnerability: z.string().describe('Description of the vulnerability'),
  cweId: z.string().optional().describe('CWE ID (e.g., CWE-79)'),
  language: z.string().optional().default('javascript').describe('Programming language'),
});

type SuggestFixInput = z.infer<typeof SuggestFixInputSchema>;

// ============================================================================
// Fix Templates
// ============================================================================

interface FixTemplate {
  pattern: RegExp;
  cwe: string;
  fixGenerator: (match: string, language: string) => { fixed: string; explanation: string };
}

const fixTemplates: FixTemplate[] = [
  {
    pattern: /\.innerHTML\s*=\s*(\w+)/,
    cwe: 'CWE-79',
    fixGenerator: (match, lang) => ({
      fixed: match.replace(/\.innerHTML\s*=\s*(\w+)/, '.textContent = $1'),
      explanation: 'Changed innerHTML to textContent to prevent XSS. textContent automatically escapes HTML entities.',
    }),
  },
  {
    pattern: /document\.write\s*\(([^)]+)\)/,
    cwe: 'CWE-79',
    fixGenerator: (match, lang) => ({
      fixed: `// document.write removed - use DOM methods instead
const container = document.getElementById('container');
container.textContent = ${match.match(/\(([^)]+)\)/)?.[1] || 'content'};`,
      explanation: 'Replaced document.write with safe DOM manipulation. Use textContent for plain text or DOMPurify for HTML.',
    }),
  },
  {
    pattern: /eval\s*\(([^)]+)\)/,
    cwe: 'CWE-95',
    fixGenerator: (match, lang) => ({
      fixed: `// eval() removed - potential code injection
// Original: ${match}
// Consider using JSON.parse() for data, or a sandboxed approach`,
      explanation: 'eval() is dangerous and should be avoided. Use JSON.parse() for JSON data, or a safe expression evaluator.',
    }),
  },
  {
    pattern: /Math\.random\(\)/,
    cwe: 'CWE-330',
    fixGenerator: (match, lang) => {
      if (lang === 'python') {
        return {
          fixed: `import secrets\nsecrets.token_hex(16)  # For tokens\nsecrets.randbelow(100)  # For random numbers`,
          explanation: 'Use the secrets module for cryptographically secure random values.',
        };
      }
      return {
        fixed: `import crypto from 'crypto';\ncrypto.randomBytes(16).toString('hex')  // For tokens\ncrypto.randomInt(0, 100)  // For random numbers (Node.js 14+)`,
        explanation: 'Use crypto.randomBytes() or crypto.randomInt() for security-sensitive random values.',
      };
    },
  },
  {
    pattern: /query\s*\([`"'].*\$\{(\w+)\}.*[`"']\)/,
    cwe: 'CWE-89',
    fixGenerator: (match, lang) => {
      const varMatch = match.match(/\$\{(\w+)\}/);
      const varName = varMatch ? varMatch[1] : 'value';
      return {
        fixed: `// Use parameterized query instead
const result = await db.query('SELECT * FROM table WHERE column = $1', [${varName}]);`,
        explanation: 'Use parameterized queries to prevent SQL injection. Never interpolate user input directly into SQL.',
      };
    },
  },
  {
    pattern: /pickle\.loads?\s*\(/,
    cwe: 'CWE-502',
    fixGenerator: (match, lang) => ({
      fixed: `import json

# Use JSON instead of pickle for untrusted data
data = json.loads(input_data)

# If pickle is required, only use with trusted sources
# and consider using pickle.safe_load() with restricted types`,
      explanation: 'Pickle deserialization of untrusted data can lead to arbitrary code execution. Use JSON for untrusted data.',
    }),
  },
  {
    pattern: /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/,
    cwe: 'CWE-78',
    fixGenerator: (match, lang) => ({
      fixed: `import subprocess
import shlex

# Use argument list instead of shell string
subprocess.run(['command', 'arg1', 'arg2'], shell=False, check=True)

# If dynamic command needed, validate strictly
allowed_commands = {'ls', 'cat', 'echo'}
if cmd in allowed_commands:
    subprocess.run([cmd] + args, shell=False)`,
      explanation: 'shell=True is dangerous with user input. Use an argument list and shell=False.',
    }),
  },
];

// ============================================================================
// Fix Suggestion Implementation
// ============================================================================

export async function suggestFix(input: unknown): Promise<MCPToolResult> {
  logger.info('Generating fix suggestion');

  // Validate input
  const validation = SuggestFixInputSchema.safeParse(input);
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

  const { code, vulnerability, cweId, language } = validation.data;

  // Find matching fix template
  let fixSuggestion: { fixed: string; explanation: string } | null = null;
  let matchedCWE = cweId;

  for (const template of fixTemplates) {
    if (template.pattern.test(code)) {
      if (!cweId || template.cwe === cweId) {
        fixSuggestion = template.fixGenerator(code, language);
        matchedCWE = template.cwe;
        break;
      }
    }
  }

  // If no specific fix found, provide generic guidance
  if (!fixSuggestion) {
    fixSuggestion = generateGenericFix(vulnerability, cweId, language);
  }

  const result = {
    original_code: code,
    vulnerability,
    cwe: matchedCWE || 'Unknown',
    language,
    suggested_fix: {
      code: fixSuggestion.fixed,
      explanation: fixSuggestion.explanation,
    },
    verification_steps: [
      'Review the fix to ensure it maintains intended functionality',
      'Write unit tests covering the fixed code',
      'Run security_review_code on the fixed implementation',
      'Conduct code review with security focus',
    ],
    references: getReferences(matchedCWE),
  };

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(result, null, 2)
    }]
  };
}

function generateGenericFix(vulnerability: string, cweId?: string, language?: string): { fixed: string; explanation: string } {
  const lower = vulnerability.toLowerCase();

  if (lower.includes('xss') || lower.includes('cross-site scripting')) {
    return {
      fixed: `// Encode output before rendering
// Use framework-specific encoding functions
// Example: textContent instead of innerHTML`,
      explanation: 'Implement context-appropriate output encoding. HTML encode for HTML context, JS encode for JavaScript context.',
    };
  }

  if (lower.includes('sql') || lower.includes('injection')) {
    return {
      fixed: `// Use parameterized queries
// Never concatenate user input into SQL`,
      explanation: 'Use prepared statements or parameterized queries. ORMs typically handle this automatically.',
    };
  }

  if (lower.includes('auth') || lower.includes('password')) {
    return {
      fixed: `// Use secure password hashing (bcrypt, argon2)
// Implement proper session management
// Use HTTPS for all authentication endpoints`,
      explanation: 'Follow authentication best practices: strong password hashing, secure session management, MFA where possible.',
    };
  }

  return {
    fixed: `// Review and fix the vulnerability
// Consider: input validation, output encoding, access control
// Consult OWASP guidelines for specific recommendations`,
    explanation: 'Unable to generate specific fix. Review OWASP guidelines and CWE mitigations for this vulnerability type.',
  };
}

function getReferences(cweId?: string): string[] {
  const refs = [
    'https://owasp.org/www-project-top-ten/',
    'https://cheatsheetseries.owasp.org/',
  ];

  if (cweId) {
    const cweNum = cweId.replace('CWE-', '');
    refs.unshift(`https://cwe.mitre.org/data/definitions/${cweNum}.html`);
  }

  return refs;
}
