/**
 * Phase 7: AI Explanation Assistant - Integration Tests
 * 
 * Tests the AI explainer with different confidence levels and validates
 * that guardrails are properly applied.
 */

import { explainFindingWithAI, formatAIExplanation, AI_EXPLANATION_PROMPT_V1 } from '../src/ai-explainer.js';
import type { SecurityFinding } from '../src/types.js';

// ============================================================================
// Test Fixtures
// ============================================================================

function createTestFinding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    pattern: 'innerHTML\\s*=',
    line_number: 42,
    snippet: 'div.innerHTML = userInput;',
    cwe: {
      id: 'CWE-79',
      name: 'Cross-site Scripting (XSS)',
      severity: 'HIGH'
    },
    owasp: ['A03:2021 - Injection'],
    cvss_context: {
      top_cves: [],
      max_cvss: 0
    },
    threat_context: {
      exploited_in_wild: false,
      attack_vector: 'Network-based XSS injection',
      impact: 'Session hijacking, credential theft, defacement',
      urgency: 'HIGH'
    },
    risk_score: 8.5,
    confidence: 0.88,
    confidence_breakdown: {
      pattern: 0.90,
      cwe: 0.85,
      owasp: 0.90,
      cve: 0.0
    },
    explanation: 'Using innerHTML with user input enables XSS attacks',
    ...overrides
  };
}

// ============================================================================
// Test Suite
// ============================================================================

interface TestResult {
  test: string;
  passed: boolean;
  message: string;
}

const testResults: TestResult[] = [];

function test(name: string, fn: () => boolean | Promise<boolean>) {
  return async () => {
    try {
      const result = await fn();
      testResults.push({
        test: name,
        passed: result,
        message: result ? 'PASS' : 'FAIL'
      });
      console.log(result ? `✅ ${name}` : `❌ ${name}`);
    } catch (error) {
      testResults.push({
        test: name,
        passed: false,
        message: `ERROR: ${error instanceof Error ? error.message : String(error)}`
      });
      console.log(`❌ ${name} - ${error instanceof Error ? error.message : String(error)}`);
    }
  };
}

// ============================================================================
// Tests
// ============================================================================

async function runAllTests() {
  console.log('🧪 Phase 7: AI Explainer Integration Tests');
  console.log('═'.repeat(80));
  console.log();

// Test 1: High confidence (>= 90%) - No disclaimers
await test('High confidence (90%) should not trigger disclaimers', async () => {
  const finding = createTestFinding({
    confidence: 0.90,
    confidence_breakdown: {
      pattern: 0.90,
      cwe: 0.90,
      owasp: 0.90,
      cve: 0.90
    }
  });
  
  const explanation = await explainFindingWithAI(finding);
  
  return !explanation.confidence_disclaimer && !explanation.guardrail_warning;
})();

// Test 2: Moderate confidence (60-89%) - No disclaimers
await test('Moderate confidence (75%) should not trigger disclaimers', async () => {
  const finding = createTestFinding({
    confidence: 0.75,
    confidence_breakdown: {
      pattern: 0.75,
      cwe: 0.75,
      owasp: 0.75,
      cve: 0.75
    }
  });
  
  const explanation = await explainFindingWithAI(finding);
  
  return !explanation.confidence_disclaimer && !explanation.guardrail_warning;
})();

// Test 3: Below 60% - Confidence disclaimer required
await test('Confidence 55% should trigger disclaimer (< 60%)', async () => {
  const finding = createTestFinding({
    confidence: 0.55,
    confidence_breakdown: {
      pattern: 0.55,
      cwe: 0.55,
      owasp: 0.55,
      cve: 0.55
    }
  });
  
  const explanation = await explainFindingWithAI(finding);
  
  return !!explanation.confidence_disclaimer && !explanation.guardrail_warning;
})();

// Test 4: Below 40% - Guardrail warning required
await test('Confidence 35% should trigger guardrail (< 40%)', async () => {
  const finding = createTestFinding({
    confidence: 0.35,
    confidence_breakdown: {
      pattern: 0.35,
      cwe: 0.35,
      owasp: 0.35,
      cve: 0.35
    }
  });
  
  const explanation = await explainFindingWithAI(finding);
  
  return !!explanation.confidence_disclaimer && !!explanation.guardrail_warning;
})();

// Test 5: Guardrail message contains "heuristic"
await test('Guardrail warning should mention "heuristic"', async () => {
  const finding = createTestFinding({
    confidence: 0.30,
    confidence_breakdown: {
      pattern: 0.30,
      cwe: 0.30,
      owasp: 0.30,
      cve: 0.30
    }
  });
  
  const explanation = await explainFindingWithAI(finding);
  
  return !!explanation.guardrail_warning && 
         explanation.guardrail_warning.toLowerCase().includes('heuristic');
})();

// Test 6: Guardrail message contains "manual review"
await test('Guardrail warning should mention "manual review"', async () => {
  const finding = createTestFinding({
    confidence: 0.25,
    confidence_breakdown: {
      pattern: 0.25,
      cwe: 0.25,
      owasp: 0.25,
      cve: 0.25
    }
  });
  
  const explanation = await explainFindingWithAI(finding);
  
  return !!explanation.guardrail_warning && 
         explanation.guardrail_warning.toLowerCase().includes('manual review');
})();

// Test 7: Explanation structure validation
await test('Explanation should have all required fields', async () => {
  const finding = createTestFinding();
  const explanation = await explainFindingWithAI(finding);
  
  return !!explanation.developer_explanation &&
         !!explanation.blue_team_context &&
         !!explanation.remediation_steps &&
         !!explanation.code_example &&
         !!explanation.model_info &&
         explanation.remediation_steps.length >= 3 &&
         !!explanation.blue_team_context.impact &&
         !!explanation.blue_team_context.attacker_perspective &&
         Array.isArray(explanation.blue_team_context.detection_indicators);
})();

// Test 8: Remediation steps should be actionable
await test('Remediation steps should have action and rationale', async () => {
  const finding = createTestFinding();
  const explanation = await explainFindingWithAI(finding);
  
  return explanation.remediation_steps.every(step => 
    !!step.action && !!step.rationale && typeof step.step === 'number'
  );
})();

// Test 9: Code example should have before/after
await test('Code example should have before and after snippets', async () => {
  const finding = createTestFinding();
  const explanation = await explainFindingWithAI(finding);
  
  return !!explanation.code_example.before &&
         !!explanation.code_example.after &&
         !!explanation.code_example.changes_explained;
})();

// Test 10: Model info should be populated
await test('Model info should contain version and timestamp', async () => {
  const finding = createTestFinding();
  const explanation = await explainFindingWithAI(finding);
  
  return !!explanation.model_info.name &&
         !!explanation.model_info.version &&
         !!explanation.model_info.timestamp &&
         explanation.model_info.version === AI_EXPLANATION_PROMPT_V1.version;
})();

// Test 11: Formatting should work without errors
await test('formatAIExplanation should produce readable output', async () => {
  const finding = createTestFinding();
  const explanation = await explainFindingWithAI(finding);
  const formatted = formatAIExplanation(explanation);
  
  return formatted.includes('AI EXPLANATION ASSISTANT') &&
         formatted.includes('Developer Explanation') &&
         formatted.includes('Blue Team') &&
         formatted.includes('Remediation Steps') &&
         formatted.includes('Secure Code Example');
})();

// Test 12: Different CWE types
await test('Should handle SQL Injection (CWE-89)', async () => {
  const finding = createTestFinding({
    pattern: 'cursor\\.execute\\(.*\\+',
    snippet: 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
    cwe: {
      id: 'CWE-89',
      name: 'SQL Injection',
      severity: 'CRITICAL'
    },
    owasp: ['A03:2021 - Injection'],
    risk_score: 9.0,
    threat_context: {
      exploited_in_wild: true,
      attack_vector: 'SQL injection via string concatenation',
      impact: 'Database compromise, data theft',
      urgency: 'CRITICAL'
    },
    explanation: 'SQL injection via string concatenation'
  });
  
  const explanation = await explainFindingWithAI(finding);
  return !!explanation.developer_explanation;
})();

// Test 13: Different CWE types - Command Injection
await test('Should handle Command Injection (CWE-78)', async () => {
  const finding = createTestFinding({
    pattern: '\\.exec\\(',
    snippet: 'exec(`git pull origin ${branch}`)',
    cwe: {
      id: 'CWE-78',
      name: 'OS Command Injection',
      severity: 'CRITICAL'
    },
    owasp: ['A03:2021 - Injection'],
    risk_score: 9.5,
    threat_context: {
      exploited_in_wild: true,
      attack_vector: 'Command injection via template literal',
      impact: 'Remote code execution, system compromise',
      urgency: 'CRITICAL'
    },
    explanation: 'Command injection via exec()'
  });
  
  const explanation = await explainFindingWithAI(finding);
  return !!explanation.developer_explanation;
})();

// Test 14: Edge case - No code snippet
await test('Should handle findings without code snippet', async () => {
  const finding = createTestFinding({
    snippet: undefined as any
  });
  
  const explanation = await explainFindingWithAI(finding);
  return !!explanation.developer_explanation;
})();

// Test 15: Edge case - No CVE references
await test('Should handle findings without CVE references', async () => {
  const finding = createTestFinding({
    cvss_context: {
      top_cves: [],
      max_cvss: 0
    }
  });
  
  const explanation = await explainFindingWithAI(finding);
  return !!explanation.developer_explanation;
})();

// ============================================================================
// Test Summary
// ============================================================================

console.log('\n' + '═'.repeat(80));
console.log('📊 TEST RESULTS SUMMARY');
console.log('═'.repeat(80));

const passed = testResults.filter(r => r.passed).length;
const failed = testResults.filter(r => !r.passed).length;

testResults.forEach(result => {
  const icon = result.passed ? '✅' : '❌';
  console.log(`${icon} ${result.test}: ${result.message}`);
});

console.log('\n' + '─'.repeat(80));
console.log(`Total: ${testResults.length} tests | Passed: ${passed} | Failed: ${failed}`);
console.log('═'.repeat(80));

if (failed > 0) {
  console.log('\n❌ Some tests failed!');
  process.exit(1);
} else {
  console.log('\n✅ All tests passed!');
  console.log('\n📋 Key Guardrails Verified:');
  console.log('  • Confidence < 60% → Disclaimer shown');
  console.log('  • Confidence < 40% → Guardrail warning shown');
  console.log('  • All explanations have required structure');
  console.log('  • Handles multiple CWE types (XSS, SQLi, RCE)');
  console.log('  • Works with missing optional fields');
  console.log('  • Prompt template version tracked\n');
}
}

// Run all tests
runAllTests().catch(error => {
  console.error('❌ Test suite failed:', error);
  process.exit(1);
});
