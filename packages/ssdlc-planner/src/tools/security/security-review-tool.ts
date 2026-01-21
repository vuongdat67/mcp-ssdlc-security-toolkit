/**
 * Phase 8: Security Review MCP Tool
 * 
 * Production-ready MCP tool for deterministic security code review
 * with optional AI explanations.
 */

import { z } from 'zod';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { 
  createSecurityKB,
  generateSecurityReport,
  generateQuickSummary,
  type SecurityReviewResult,
  type ReportOptions
} from '@mcp-ssdlc/security-kb';

// ============================================================================
// Input Schema
// ============================================================================

const SecurityReviewInputSchema = z.object({
  // Code source (either file_path OR code_snippet required)
  file_path: z.string().optional().describe('Absolute path to file to analyze'),
  code_snippet: z.string().optional().describe('Code snippet to analyze directly'),
  
  // Required parameters
  language: z.enum([
    'javascript',
    'typescript',
    'python',
    'java',
    'go',
    'rust',
    'csharp',
    'php',
    'ruby'
  ]).describe('Programming language of the code'),
  
  // Analysis mode
  mode: z.enum(['quick', 'deep']).default('deep').describe(
    'Analysis mode: quick (pattern matching only) or deep (with CVE/OWASP context)'
  ),
  
  // Report options
  report_format: z.enum(['full', 'executive', 'developer', 'json']).default('full'),
  min_severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).optional(),
  project_name: z.string().optional(),
  
  // Output control
  include_remediation: z.boolean().default(true),
  include_explanations: z.boolean().default(false)
}).refine(
  data => data.file_path || data.code_snippet,
  {
    message: 'Either file_path or code_snippet must be provided'
  }
);

type SecurityReviewInput = z.infer<typeof SecurityReviewInputSchema>;

// ============================================================================
// MCP Tool Definition
// ============================================================================

export const securityReviewCodeTool = {
  name: 'security_review_code',
  description: `Performs deterministic security code review with CWE/CVE/OWASP intelligence.

**Features**:
- Pattern-based vulnerability detection (55+ patterns)
- CWE/CVE/OWASP mapping
- CISA KEV (Known Exploited Vulnerabilities) highlighting
- Confidence scoring
- Severity normalization (developer/security/business)
- Professional markdown reports

**Analysis Modes**:
- quick: Fast pattern matching
- deep: Full context with CVE evidence and threat intelligence

**IMPORTANT**: This tool performs DETERMINISTIC detection only. It does NOT use AI to decide vulnerabilities. AI is only used for optional explanations when include_explanations=true.

**Example Usage**:
\`\`\`json
{
  "code_snippet": "div.innerHTML = userInput;",
  "language": "javascript",
  "mode": "deep",
  "report_format": "developer"
}
\`\`\``,
  
  inputSchema: {
    type: 'object' as const,
    properties: {
      file_path: {
        type: 'string',
        description: 'Absolute path to file to analyze'
      },
      code_snippet: {
        type: 'string',
        description: 'Code snippet to analyze directly'
      },
      language: {
        type: 'string',
        enum: ['javascript', 'typescript', 'python', 'java', 'go', 'rust', 'csharp', 'php', 'ruby'],
        description: 'Programming language'
      },
      mode: {
        type: 'string',
        enum: ['quick', 'deep'],
        description: 'Analysis mode',
        default: 'deep'
      },
      report_format: {
        type: 'string',
        enum: ['full', 'executive', 'developer', 'json'],
        description: 'Report format',
        default: 'full'
      },
      min_severity: {
        type: 'string',
        enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        description: 'Minimum severity to report'
      },
      project_name: {
        type: 'string',
        description: 'Project name for report'
      },
      include_remediation: {
        type: 'boolean',
        description: 'Include remediation examples',
        default: true
      },
      include_explanations: {
        type: 'boolean',
        description: 'Include AI-generated explanations',
        default: false
      }
    },
    required: ['language'],
    oneOf: [
      { required: ['file_path'] },
      { required: ['code_snippet'] }
    ]
  },
  
  async handler(input: SecurityReviewInput): Promise<{ content: Array<{ type: string; text: string }> }> {
    try {
      // Validate input
      const validated = SecurityReviewInputSchema.parse(input);
      
      // Get code content
      let code: string;
      if (validated.file_path) {
        try {
          const absolutePath = resolve(validated.file_path);
          code = readFileSync(absolutePath, 'utf-8');
        } catch (error) {
          throw new Error(`Failed to read file: ${validated.file_path}. Error: ${error instanceof Error ? error.message : String(error)}`);
        }
      } else {
        code = validated.code_snippet!;
      }
      
      // Initialize security knowledge base
      const kb = await createSecurityKB();
      
      // Perform security review (deterministic detection)
      const result: SecurityReviewResult = await kb.reviewCode(validated.language, code);
      
      // Generate output based on format
      if (validated.report_format === 'json') {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }]
        };
      }
      
      // Generate markdown report
      const reportOptions: ReportOptions = {
        projectName: validated.project_name || (validated.file_path ? validated.file_path : 'Code Review'),
        format: validated.report_format,
        minSeverity: validated.min_severity,
        includeRemediation: validated.include_remediation,
        includeExplanations: validated.include_explanations
      };
      
      const report = generateSecurityReport(result, reportOptions);
      
      // Add quick summary if in deep mode
      let output = report;
      if (validated.mode === 'deep') {
        const summary = generateQuickSummary(result);
        output = `\`\`\`\n${summary}\n\`\`\`\n\n${report}`;
      }
      
      return {
        content: [{
          type: 'text',
          text: output
        }]
      };
      
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new Error(`Invalid input: ${error.errors.map(e => e.message).join(', ')}`);
      }
      
      throw error;
    }
  }
};

// ============================================================================
// Helper: Batch Analysis
// ============================================================================

export async function analyzeMultipleFiles(
  files: Array<{ path: string; language: string }>,
  options: Pick<SecurityReviewInput, 'mode' | 'min_severity' | 'project_name'>
): Promise<SecurityReviewResult[]> {
  const kb = await createSecurityKB();
  const results: SecurityReviewResult[] = [];
  
  for (const file of files) {
    try {
      const code = readFileSync(resolve(file.path), 'utf-8');
      const result = await kb.reviewCode(file.language as any, code);
      results.push(result);
    } catch (error) {
      console.error(`Failed to analyze ${file.path}:`, error);
    }
  }
  
  return results;
}

// ============================================================================
// Export for MCP Server Registration
// ============================================================================

export default securityReviewCodeTool;
