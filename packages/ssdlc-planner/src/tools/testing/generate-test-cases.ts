/**
 * QA Engineer Tool: Generate Test Cases
 * 
 * Generates comprehensive test cases from requirements
 */

import { z } from "zod";
import { createLogger } from "@mcp-ssdlc/core";

const logger = createLogger("qa-generate-test-cases");

const GenerateTestCasesSchema = z.object({
  requirement: z.string().min(10),
  test_level: z.enum(["unit", "integration", "e2e", "security"]),
  coverage_type: z.enum(["positive", "negative", "edge_case"]).optional().default("positive"),
});

interface TestCase {
  id: string;
  name: string;
  given: string;
  when: string;
  then: string;
  test_data: string;
  expected_result: string;
  security_risk: boolean;
}

export async function qaGenerateTestCases(args: unknown) {
  try {
    const input = GenerateTestCasesSchema.parse(args);
    
    logger.info(`Generating ${input.test_level} test cases (${input.coverage_type})`);

    const testCases = generateTestCases(
      input.requirement,
      input.test_level,
      input.coverage_type
    );

    const output = `# Test Cases: ${input.test_level.toUpperCase()}
Generated: ${new Date().toISOString()}

## Test Coverage: ${input.coverage_type}

${testCases.map((tc, i) => `
### ${tc.id}: ${tc.name}
${tc.security_risk ? '⚠️ **Security Test**' : ''}

**Given:** ${tc.given}  
**When:** ${tc.when}  
**Then:** ${tc.then}

**Test Data:**
\`\`\`
${tc.test_data}
\`\`\`

**Expected Result:** ${tc.expected_result}

---
`).join('\n')}

## Test Summary

- **Total Test Cases:** ${testCases.length}
- **Security Tests:** ${testCases.filter(t => t.security_risk).length}
- **Test Level:** ${input.test_level}
- **Coverage Type:** ${input.coverage_type}

## Execution Priority

1. ${testCases.filter(t => t.security_risk).map(t => t.id).join(', ')} (Security Critical)
2. ${testCases.filter(t => !t.security_risk).map(t => t.id).join(', ')} (Functional)

## Next Steps

1. Implement automated tests using framework (Vitest/Jest/Pytest)
2. Integrate tests into CI/CD pipeline
3. Set coverage target: ${input.test_level === 'unit' ? '80%+' : '70%+'}
4. Run tests on every PR before merge
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
 * Generate test cases based on test level
 */
function generateTestCases(
  requirement: string,
  testLevel: string,
  coverageType: string
): TestCase[] {
  const testCases: TestCase[] = [];
  const reqLower = requirement.toLowerCase();

  if (testLevel === "unit") {
    // Unit test cases
    if (coverageType === "positive") {
      testCases.push({
        id: "UT-POS-001",
        name: "Valid input returns expected output",
        given: "Function receives valid input parameters",
        when: "Function is called with valid data",
        then: "Function returns correct result without errors",
        test_data: "{ user_id: '123', name: 'John Doe' }",
        expected_result: "Success status with processed data",
        security_risk: false,
      });
    }

    if (coverageType === "negative") {
      testCases.push({
        id: "UT-NEG-001",
        name: "Invalid input throws validation error",
        given: "Function receives invalid input parameters",
        when: "Function is called with invalid data",
        then: "Function throws ValidationError with descriptive message",
        test_data: "{ user_id: null, name: '' }",
        expected_result: "ValidationError: 'user_id is required'",
        security_risk: true,
      });
    }

    if (coverageType === "edge_case") {
      testCases.push({
        id: "UT-EDGE-001",
        name: "Boundary value handling",
        given: "Function receives boundary values (max length, min value)",
        when: "Function processes edge case input",
        then: "Function handles edge case correctly without overflow/underflow",
        test_data: "{ name: 'A'.repeat(255) }",
        expected_result: "Accepts max length or truncates with warning",
        security_risk: false,
      });
    }
  }

  if (testLevel === "integration") {
    testCases.push({
      id: "IT-001",
      name: "End-to-end component integration",
      given: "Multiple components are deployed and connected",
      when: "Request flows through component chain (API -> Service -> DB)",
      then: "Data is processed correctly across all components",
      test_data: "POST /api/users with valid JSON payload",
      expected_result: "User created in database, 201 response returned",
      security_risk: false,
    });
  }

  if (testLevel === "security") {
    // Security-specific tests
    if (reqLower.includes("auth") || reqLower.includes("login")) {
      testCases.push(
        {
          id: "SEC-001",
          name: "SQL Injection attempt blocked",
          given: "Attacker sends SQL injection payload in login form",
          when: "System processes login with username = \"admin' OR '1'='1\"",
          then: "System rejects input, logs security event, returns safe error",
          test_data: "{ username: \"admin' OR '1'='1\", password: 'x' }",
          expected_result: "401 Unauthorized, no database error leaked",
          security_risk: true,
        },
        {
          id: "SEC-002",
          name: "Brute force protection enforced",
          given: "Attacker attempts multiple failed logins",
          when: "6th failed login attempt within 5 minutes",
          then: "Account temporarily locked, CAPTCHA required, alert sent",
          test_data: "6 consecutive failed login attempts",
          expected_result: "429 Too Many Requests, account locked for 15 minutes",
          security_risk: true,
        }
      );
    }

    if (reqLower.includes("api") || reqLower.includes("endpoint")) {
      testCases.push({
        id: "SEC-003",
        name: "Rate limiting prevents DoS",
        given: "Attacker sends excessive requests to API",
        when: "101st request within 1 minute from same IP",
        then: "Request rejected with 429 status, subsequent requests blocked",
        test_data: "101 requests in 60 seconds",
        expected_result: "429 Too Many Requests, Retry-After header included",
        security_risk: true,
      });
    }
  }

  if (testLevel === "e2e") {
    testCases.push({
      id: "E2E-001",
      name: "Complete user workflow",
      given: "User navigates to application homepage",
      when: "User completes full workflow (signup -> login -> use feature -> logout)",
      then: "All steps succeed, UI updates correctly, data persists",
      test_data: "Selenium/Playwright test script",
      expected_result: "Workflow completes in < 30 seconds, no errors",
      security_risk: false,
    });
  }

  // Ensure at least one test case
  if (testCases.length === 0) {
    testCases.push({
      id: "TC-001",
      name: "Basic functionality test",
      given: "System is in ready state",
      when: "User performs basic operation",
      then: "Operation succeeds as expected",
      test_data: "Standard test input",
      expected_result: "Expected output returned",
      security_risk: false,
    });
  }

  return testCases;
}
