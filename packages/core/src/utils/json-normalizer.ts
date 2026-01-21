/**
 * JSON Normalizer & Validator
 * 
 * Fixes common JSON formatting issues from LLM/MCP clients:
 * 1. Backticks (`) instead of double quotes (")
 * 2. Single quotes (') instead of double quotes
 * 3. Trailing commas
 * 4. Comments
 * 
 * MCP tools MUST accept only valid JSON, but LLMs often send malformed JSON.
 * This utility normalizes input before parsing.
 */

import { createLogger } from './logger.js';

const logger = createLogger('JSON-Normalizer');

export class JSONNormalizationError extends Error {
  constructor(
    message: string,
    public readonly originalInput: string,
    public readonly details: string
  ) {
    super(message);
    this.name = 'JSONNormalizationError';
  }
}

/**
 * Normalize potentially malformed JSON string to valid JSON
 * 
 * @param raw - Raw input that might be malformed JSON
 * @param context - Context for error messages (e.g., "ba_analyze_requirements input")
 * @returns Normalized JSON string
 * @throws JSONNormalizationError if normalization fails
 */
export function normalizeJSON(raw: string, context: string = 'input'): string {
  const original = raw;
  
  try {
    // Step 1: Trim whitespace
    let normalized = raw.trim();
    
    // Step 2: Replace backticks with double quotes
    // Pattern: `string` → "string"
    // Must be careful not to replace backticks inside already-quoted strings
    normalized = normalized.replace(/`([^`]*)`/g, '"$1"');
    
    // Step 3: Replace single quotes with double quotes (property names)
    // Pattern: 'key': → "key":
    normalized = normalized.replace(/'([^']*)'(\s*:)/g, '"$1"$2');
    
    // Step 4: Remove trailing commas before } or ]
    normalized = normalized.replace(/,(\s*[}\]])/g, '$1');
    
    // Step 5: Remove comments (// and /* */)
    normalized = normalized.replace(/\/\/.*$/gm, ''); // Single-line comments
    normalized = normalized.replace(/\/\*[\s\S]*?\*\//g, ''); // Multi-line comments
    
    // Step 6: Validate it's parseable
    try {
      JSON.parse(normalized);
      
      // Log warning if normalization was needed
      if (normalized !== original) {
        logger.warn(`JSON normalization applied for ${context}`, {
          changes: [
            original.includes('`') ? 'backticks → double quotes' : null,
            original.includes("'") ? 'single quotes → double quotes' : null,
            /,\s*[}\]]/.test(original) ? 'removed trailing commas' : null,
          ].filter(Boolean)
        });
      }
      
      return normalized;
    } catch (parseError) {
      throw new JSONNormalizationError(
        `${context} - Failed to parse JSON after normalization`,
        original,
        parseError instanceof Error ? parseError.message : String(parseError)
      );
    }
  } catch (error) {
    if (error instanceof JSONNormalizationError) {
      throw error;
    }
    
    throw new JSONNormalizationError(
      `${context} - Normalization failed`,
      original,
      error instanceof Error ? error.message : String(error)
    );
  }
}

/**
 * Parse and validate JSON with normalization
 * 
 * @param raw - Raw input string (may be malformed)
 * @param context - Context for error messages
 * @returns Parsed JSON object
 * @throws JSONNormalizationError if parsing fails
 */
export function parseJSON<T = unknown>(raw: string, context: string = 'input'): T {
  const normalized = normalizeJSON(raw, context);
  return JSON.parse(normalized) as T;
}

/**
 * Safely parse JSON from tool arguments
 * 
 * Usage in MCP tools:
 * ```ts
 * export async function myTool(args: unknown): Promise<MCPToolResult> {
 *   const input = safeParseToolArgs<MyInputSchema>(args, 'my_tool');
 *   // Now input is typed and validated
 * }
 * ```
 */
export function safeParseToolArgs<T = unknown>(
  args: unknown,
  toolName: string
): T {
  // If args is already an object, return it
  if (typeof args === 'object' && args !== null) {
    return args as T;
  }
  
  // If args is a string, try to parse it
  if (typeof args === 'string') {
    return parseJSON<T>(args, `${toolName} arguments`);
  }
  
  throw new JSONNormalizationError(
    `${toolName} - Invalid argument type: expected object or JSON string`,
    String(args),
    `Received type: ${typeof args}`
  );
}

/**
 * Validate JSON schema (basic validation)
 * 
 * @param data - Parsed JSON data
 * @param requiredFields - Array of required field names
 * @param context - Context for error messages
 * @throws Error if required fields are missing
 */
export function validateJSONSchema(
  data: Record<string, unknown>,
  requiredFields: string[],
  context: string = 'input'
): void {
  const missingFields = requiredFields.filter(field => !(field in data));
  
  if (missingFields.length > 0) {
    throw new Error(
      `${context} - Missing required fields: ${missingFields.join(', ')}`
    );
  }
}

/**
 * Generate helpful error message for JSON issues
 */
export function generateJSONErrorHelp(error: JSONNormalizationError): string {
  return `
❌ JSON Parsing Error: ${error.message}

🔍 Original Input (first 200 chars):
${error.originalInput.substring(0, 200)}${error.originalInput.length > 200 ? '...' : ''}

📝 Common Issues:
- Use double quotes (") not backticks (\`) or single quotes (')
- Remove trailing commas before } or ]
- Remove comments (// or /* */)
- Ensure all strings are properly quoted

✅ Valid JSON Example:
{
  "project_name": "My Project",
  "tech_stack": ["Node.js", "PostgreSQL"],
  "team_size": 8
}

Details: ${error.details}
`.trim();
}
