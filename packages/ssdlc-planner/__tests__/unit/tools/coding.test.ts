/**
 * Coding Tools Unit Tests
 */

import { describe, it, expect } from 'vitest';

// Note: Vitest will handle TypeScript imports directly

describe('generate_secure_code', () => {
  it('should generate code with input validation', async () => {
    const { generateSecureCode } = await import('../../../src/tools/coding/generate-secure-code.js');

    const result = await generateSecureCode({
      requirement: 'Create a user registration endpoint with email and password',
      language: 'javascript',
      securityContext: {
        authRequired: true,
        inputValidation: true,
      },
    });

    const output = JSON.parse(result.content[0].text);

    expect(output).toHaveProperty('generated_code');
    expect(output).toHaveProperty('security_notes');
    expect(output.security_notes.length).toBeGreaterThan(0);
    expect(output.language).toBe('javascript');
  });

  it('should include SQL injection prevention for database requirements', async () => {
    const { generateSecureCode } = await import('../../../src/tools/coding/generate-secure-code.js');

    const result = await generateSecureCode({
      requirement: 'Query user from database by ID',
      language: 'python',
    });

    const output = JSON.parse(result.content[0].text);

    expect(output.generated_code).toContain('parameterized');
    expect(output.cwe_coverage).toContain('CWE-89 (SQL Injection)');
  });

  it('should validate input and return error for invalid input', async () => {
    const { generateSecureCode } = await import('../../../src/tools/coding/generate-secure-code.js');

    const result = await generateSecureCode({
      requirement: 'short', // Too short
      language: 'invalid-language',
    });

    const output = JSON.parse(result.content[0].text);

    expect(output).toHaveProperty('error');
  });
});

describe('review_file', () => {
  it('should detect XSS vulnerability in JavaScript code', async () => {
    const { reviewFile } = await import('../../../src/tools/coding/review-file.js');

    const result = await reviewFile({
      code: `
        function displayMessage(msg) {
          document.getElementById('output').innerHTML = msg;
        }
      `,
      language: 'javascript',
    });

    const output = JSON.parse(result.content[0].text);

    expect(output.findings.length).toBeGreaterThan(0);
    expect(output.findings[0].cwe).toBe('CWE-79');
    expect(output.risk_score).toBeGreaterThan(0);
  });

  it('should detect hardcoded secrets', async () => {
    const { reviewFile } = await import('../../../src/tools/coding/review-file.js');

    const result = await reviewFile({
      code: `
        const api_key = "sk-1234567890abcdefghij";
        const password = "supersecretpassword123";
      `,
      language: 'javascript',
    });

    const output = JSON.parse(result.content[0].text);

    expect(output.findings.some((f: any) => f.cwe === 'CWE-798')).toBe(true);
  });

  it('should detect Python pickle deserialization', async () => {
    const { reviewFile } = await import('../../../src/tools/coding/review-file.js');

    const result = await reviewFile({
      code: `
        import pickle
        
        def load_data(data):
            return pickle.loads(data)
      `,
      language: 'python',
    });

    const output = JSON.parse(result.content[0].text);

    expect(output.findings.some((f: any) => f.cwe === 'CWE-502')).toBe(true);
    expect(output.findings[0].severity).toBe('CRITICAL');
  });

  it('should return zero findings for safe code', async () => {
    const { reviewFile } = await import('../../../src/tools/coding/review-file.js');

    const result = await reviewFile({
      code: `
        function add(a, b) {
          return a + b;
        }
        
        const sum = add(1, 2);
        console.log(sum);
      `,
      language: 'javascript',
    });

    const output = JSON.parse(result.content[0].text);

    expect(output.summary.critical).toBe(0);
    expect(output.summary.high).toBe(0);
    expect(output.risk_level).toBe('LOW');
  });
});

describe('suggest_fix', () => {
  it('should suggest fix for innerHTML vulnerability', async () => {
    const { suggestFix } = await import('../../../src/tools/coding/suggest-fix.js');

    const result = await suggestFix({
      code: 'element.innerHTML = userInput;',
      vulnerability: 'Cross-site scripting vulnerability',
      cweId: 'CWE-79',
      language: 'javascript',
    });

    const output = JSON.parse(result.content[0].text);

    expect(output).toHaveProperty('suggested_fix');
    expect(output.suggested_fix.code).toContain('textContent');
    expect(output.verification_steps.length).toBeGreaterThan(0);
  });

  it('should suggest fix for eval usage', async () => {
    const { suggestFix } = await import('../../../src/tools/coding/suggest-fix.js');

    const result = await suggestFix({
      code: 'eval(userExpression)',
      vulnerability: 'Code injection via eval',
      cweId: 'CWE-95',
      language: 'javascript',
    });

    const output = JSON.parse(result.content[0].text);

    expect(output.suggested_fix.code).toContain('eval() removed');
    expect(output.cwe).toBe('CWE-95');
  });

  it('should provide generic fix for unknown vulnerabilities', async () => {
    const { suggestFix } = await import('../../../src/tools/coding/suggest-fix.js');

    const result = await suggestFix({
      code: 'someUnknownCode()',
      vulnerability: 'Some unknown issue',
      language: 'javascript',
    });

    const output = JSON.parse(result.content[0].text);

    expect(output).toHaveProperty('suggested_fix');
    expect(output.references.length).toBeGreaterThan(0);
  });
});
