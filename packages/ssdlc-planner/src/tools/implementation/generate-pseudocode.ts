/**
 * Tech Lead Tool: Generate Pseudocode
 * 
 * Generates detailed pseudocode with security annotations
 */

import { z } from "zod";
import { createLogger } from "@mcp-ssdlc/core";
import { createSecurityKB } from "@mcp-ssdlc/security-kb";

const logger = createLogger("techlead-generate-pseudocode");

const GeneratePseudocodeSchema = z.object({
  function_name: z.string().min(1),
  description: z.string().min(10),
  language: z.enum(["python", "javascript", "typescript", "go", "csharp"]),
  parameters: z.array(z.object({
    name: z.string(),
    type: z.string(),
    description: z.string()
  })).optional().default([]),
  return_type: z.string().optional(),
  security_context: z.string().optional(),
});

export async function techleadGeneratePseudocode(args: unknown) {
  try {
    const input = GeneratePseudocodeSchema.parse(args);
    
    logger.info(`Generating pseudocode for: ${input.function_name}`);

    // Get relevant secure patterns from knowledge base
    const securityKB = await createSecurityKB();
    const category = detectCategory(input.description, input.function_name);
    // TODO: Implement getSecurePatterns in SecurityKnowledgeBase
    // For now, use empty array as patterns are generated inline
    const patterns: Array<{ pattern_name: string; description: string; language: string; code_example: string; security_notes?: string[] }> = [];
    securityKB.close();
    
    // Generate function signature
    const signature = generateSignature(input);
    
    // Generate pseudocode logic
    const pseudocode = generatePseudocodeLogic(input, patterns);
    
    // Get security considerations
    const securityNotes = getSecurityNotes(input, patterns);
    
    // Related functions
    const relatedFunctions = identifyRelatedFunctions(input);
    
    // Test requirements
    const testRequirements = generateTestRequirements(input);

    const output = `# Pseudocode: ${input.function_name}
Generated: ${new Date().toISOString()}
Language: ${input.language}

## Function Signature

\`\`\`${input.language}
${signature}
\`\`\`

## Description
${input.description}

## Pseudocode Logic

\`\`\`
${pseudocode}
\`\`\`

## Security Considerations

${securityNotes.map((note, i) => `${i + 1}. ${note}`).join('\n')}

${patterns.length > 0 ? `
## Secure Coding Pattern Reference

${patterns.map(p => `
### ${p.pattern_name}
${p.description}

\`\`\`${p.language}
${p.code_example}
\`\`\`

**Security Notes:**
${(p.security_notes || []).map((n: string) => `- ${n}`).join('\n')}
`).join('\n')}
` : ''}

## Related Functions Needed

${relatedFunctions.map((fn, i) => `${i + 1}. \`${fn.signature}\` - ${fn.purpose}`).join('\n')}

## Test Requirements

${testRequirements.map((req, i) => `${i + 1}. **${req.type}**: ${req.description}`).join('\n')}

## Implementation Notes

- Follow ${input.language} coding standards
- Implement comprehensive error handling
- Add logging for debugging and audit
- Include input validation at function entry
- Write unit tests with >80% coverage
- Consider edge cases and boundary conditions

---

**Next Steps:**
1. Implement function following pseudocode
2. Add security controls from pattern reference
3. Write unit tests for all test requirements
4. Perform security code review
5. Document API usage and examples
`;

    return {
      content: [
        {
          type: "text",
          text: output,
        },
      ],
    };
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new Error(`Validation failed: ${error.errors.map(e => e.message).join(', ')}`);
    }
    throw error;
  }
}

/**
 * Detect category from description
 */
function detectCategory(description: string, functionName: string): string | undefined {
  const text = `${description} ${functionName}`.toLowerCase();
  
  if (text.includes("auth") || text.includes("login") || text.includes("password")) {
    return "authentication";
  }
  if (text.includes("encrypt") || text.includes("decrypt") || text.includes("crypto")) {
    return "cryptography";
  }
  if (text.includes("validate") || text.includes("sanitize") || text.includes("input")) {
    return "input-validation";
  }
  
  return undefined;
}

/**
 * Generate function signature
 */
function generateSignature(input: z.infer<typeof GeneratePseudocodeSchema>): string {
  const params = input.parameters || [];
  
  switch (input.language) {
    case "python":
      const pyParams = params.map(p => `${p.name}: ${p.type}`).join(", ");
      const pyReturn = input.return_type ? ` -> ${input.return_type}` : "";
      return `def ${input.function_name}(${pyParams})${pyReturn}:
    """
    ${input.description}
    
    Args:
        ${params.map(p => `${p.name} (${p.type}): ${p.description}`).join('\n        ')}
    
    Returns:
        ${input.return_type || 'None'}: Function result
        
    Raises:
        ValidationError: If input validation fails
        SecurityError: If security checks fail
    """
    pass`;

    case "javascript":
    case "typescript":
      const jsParams = params.map(p => input.language === "typescript" ? `${p.name}: ${p.type}` : p.name).join(", ");
      const jsReturn = input.language === "typescript" && input.return_type ? `: ${input.return_type}` : "";
      return `/**
 * ${input.description}
 * 
 * @param {${params.map(p => `${p.type} ${p.name} - ${p.description}`).join('\n * @param {')}}
 * @returns {${input.return_type || 'void'}} Function result
 * @throws {ValidationError} If input validation fails
 * @throws {SecurityError} If security checks fail
 */
${input.language === "typescript" ? "async " : ""}function ${input.function_name}(${jsParams})${jsReturn} {
    // Implementation
}`;

    case "go":
      const goParams = params.map(p => `${p.name} ${p.type}`).join(", ");
      const goReturn = input.return_type ? ` ${input.return_type}` : "";
      return `// ${input.function_name} ${input.description}
//
// Parameters:
${params.map(p => `//   ${p.name} (${p.type}): ${p.description}`).join('\n')}
//
// Returns: ${input.return_type || 'void'}
func ${input.function_name}(${goParams})${goReturn} {
    // Implementation
}`;

    case "csharp":
      const csParams = params.map(p => `${p.type} ${p.name}`).join(", ");
      const csReturn = input.return_type || "void";
      return `/// <summary>
/// ${input.description}
/// </summary>
${params.map(p => `/// <param name="${p.name}">${p.description}</param>`).join('\n')}
/// <returns>${input.return_type || 'void'}</returns>
public ${csReturn} ${input.function_name}(${csParams})
{
    // Implementation
}`;

    default:
      return `function ${input.function_name}()`;
  }
}

/**
 * Generate pseudocode logic
 */
function generatePseudocodeLogic(
  input: z.infer<typeof GeneratePseudocodeSchema>,
  patterns: any[]
): string {
  const desc = input.description.toLowerCase();
  const funcName = input.function_name.toLowerCase();
  
  let logic = `FUNCTION ${input.function_name}(${input.parameters?.map(p => p.name).join(', ')})

    // STEP 1: Input Validation
    VALIDATE all input parameters
    IF any parameter is invalid THEN
        RAISE ValidationError with details
        LOG validation failure (parameter, reason)
    END IF
    
    // STEP 2: Security Checks`;

  if (desc.includes("auth") || funcName.includes("auth")) {
    logic += `
    CHECK rate limiting (prevent brute force)
    IF rate limit exceeded THEN
        LOG rate limit violation (user, IP, timestamp)
        RETURN 429 Too Many Requests
    END IF
    
    VERIFY authentication credentials
    IF credentials invalid THEN
        INCREMENT failed attempt counter
        LOG authentication failure
        RETURN 401 Unauthorized
    END IF`;
  }

  if (desc.includes("encrypt") || desc.includes("crypto")) {
    logic += `
    VERIFY encryption key is valid and strong
    GENERATE random nonce/IV (never reuse)
    ENSURE proper key management (no hardcoded keys)`;
  }

  logic += `
    
    // STEP 3: Core Business Logic
    TRY
        `;

  if (desc.includes("create") || desc.includes("add")) {
    logic += `CREATE new resource with validated data
        APPLY business rules and constraints
        PERSIST changes to database`;
  } else if (desc.includes("update") || desc.includes("modify")) {
    logic += `FETCH existing resource
        VERIFY user has permission to modify
        APPLY updates with validated data
        PERSIST changes`;
  } else if (desc.includes("delete") || desc.includes("remove")) {
    logic += `FETCH existing resource
        VERIFY user has permission to delete
        PERFORM soft delete (mark as deleted, keep for audit)
        LOG deletion event`;
  } else if (desc.includes("query") || desc.includes("search") || desc.includes("get")) {
    logic += `QUERY database with parameterized query
        APPLY access control filters (user can only see authorized data)
        PAGINATE results (prevent DoS)
        RETURN sanitized data`;
  } else {
    logic += `PROCESS request according to requirements
        APPLY necessary transformations
        ENFORCE business rules`;
  }

  logic += `
        
        // STEP 4: Audit Logging
        LOG successful operation (user, action, timestamp, details)
        
        // STEP 5: Return Result
        RETURN ${input.return_type || 'success response'}
        
    CATCH Exception AS error
        // STEP 6: Error Handling
        LOG error with context (do NOT log sensitive data)
        ROLLBACK any partial changes
        RETURN appropriate error response (safe, no info leakage)
    END TRY

END FUNCTION`;

  return logic;
}

/**
 * Get security notes
 */
function getSecurityNotes(
  input: z.infer<typeof GeneratePseudocodeSchema>,
  patterns: any[]
): string[] {
  const notes: string[] = [];
  const desc = input.description.toLowerCase();

  // General security notes
  notes.push("**Input Validation**: Validate all inputs at function entry point using allow-lists where possible");
  notes.push("**Error Handling**: Never expose internal details in error messages (avoid stack traces to users)");
  notes.push("**Logging**: Log security events but avoid logging sensitive data (passwords, tokens, PII)");

  // Specific security notes based on function purpose
  if (desc.includes("auth") || desc.includes("login")) {
    notes.push("**Rate Limiting**: Implement exponential backoff after failed attempts (prevent brute force)");
    notes.push("**Timing Attacks**: Use constant-time comparison for password/token verification");
    notes.push("**Session Management**: Generate cryptographically random session tokens, set appropriate timeouts");
  }

  if (desc.includes("sql") || desc.includes("database") || desc.includes("query")) {
    notes.push("**SQL Injection**: Always use parameterized queries, never string concatenation");
    notes.push("**Least Privilege**: Database user should have minimal required permissions");
  }

  if (desc.includes("api") || desc.includes("endpoint")) {
    notes.push("**CSRF Protection**: Implement CSRF tokens for state-changing operations");
    notes.push("**CORS**: Configure CORS properly, avoid wildcard origins in production");
  }

  if (desc.includes("file") || desc.includes("upload")) {
    notes.push("**Path Traversal**: Validate and sanitize file paths, prevent directory traversal");
    notes.push("**File Type**: Validate file types by content (magic bytes), not just extension");
  }

  if (desc.includes("encrypt") || desc.includes("crypto")) {
    notes.push("**Cryptography**: Use well-tested libraries, never implement custom crypto");
    notes.push("**Key Management**: Store keys securely (HSM, key vault), rotate regularly");
  }

  // Add pattern-specific notes
  patterns.forEach(pattern => {
    pattern.security_notes.forEach((note: string) => {
      if (!notes.some(n => n.includes(note))) {
        notes.push(`**${pattern.pattern_name}**: ${note}`);
      }
    });
  });

  return notes;
}

/**
 * Identify related functions needed
 */
function identifyRelatedFunctions(input: z.infer<typeof GeneratePseudocodeSchema>): Array<{
  signature: string;
  purpose: string;
}> {
  const functions: Array<{ signature: string; purpose: string }> = [];
  const desc = input.description.toLowerCase();

  // Always needed
  functions.push({
    signature: `validate_input(params: ${input.parameters?.[0]?.type || 'object'}) -> bool`,
    purpose: "Validate all input parameters against schema"
  });

  if (desc.includes("auth") || desc.includes("login")) {
    functions.push(
      {
        signature: "check_rate_limit(user_id: str, ip: str) -> bool",
        purpose: "Check if rate limit exceeded for user/IP"
      },
      {
        signature: "verify_credentials(username: str, password: str) -> User | None",
        purpose: "Verify user credentials securely"
      },
      {
        signature: "generate_session_token() -> str",
        purpose: "Generate cryptographically secure session token"
      }
    );
  }

  if (desc.includes("database") || desc.includes("query")) {
    functions.push({
      signature: "execute_parameterized_query(query: str, params: list) -> Result",
      purpose: "Execute parameterized query safely"
    });
  }

  functions.push({
    signature: "log_audit_event(user: str, action: str, details: dict) -> None",
    purpose: "Log security-relevant events for audit trail"
  });

  return functions;
}

/**
 * Generate test requirements
 */
function generateTestRequirements(input: z.infer<typeof GeneratePseudocodeSchema>): Array<{
  type: string;
  description: string;
}> {
  const tests: Array<{ type: string; description: string }> = [];

  // Unit tests
  tests.push(
    {
      type: "Unit Test - Valid Input",
      description: "Test function with valid inputs, verify expected output"
    },
    {
      type: "Unit Test - Invalid Input",
      description: "Test function with invalid inputs, verify ValidationError raised"
    },
    {
      type: "Unit Test - Edge Cases",
      description: "Test boundary values (empty, max length, special characters)"
    }
  );

  // Security tests
  const desc = input.description.toLowerCase();

  if (desc.includes("auth") || desc.includes("login")) {
    tests.push(
      {
        type: "Security Test - Brute Force",
        description: "Verify rate limiting prevents brute force attacks"
      },
      {
        type: "Security Test - Timing Attack",
        description: "Verify response time is constant regardless of input validity"
      }
    );
  }

  if (desc.includes("sql") || desc.includes("database")) {
    tests.push({
      type: "Security Test - SQL Injection",
      description: "Test with SQL injection payloads (e.g., ' OR '1'='1), verify proper escaping"
    });
  }

  if (desc.includes("api") || desc.includes("endpoint")) {
    tests.push({
      type: "Security Test - CSRF",
      description: "Verify CSRF token validation on state-changing operations"
    });
  }

  // Integration test
  tests.push({
    type: "Integration Test",
    description: "Test function integrated with actual dependencies (database, external APIs)"
  });

  return tests;
}
