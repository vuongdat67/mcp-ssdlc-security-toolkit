/**
 * Test Security Review Engine - Phase 6
 * Validates AI Security Review with Blue Team context
 */

import { SecurityKnowledgeBase } from '../src/index';
import { existsSync, unlinkSync } from 'fs';
import { join } from 'path';

const TEST_DB_PATH = join(__dirname, '../data/test-security-review.db');

// Test code samples with real vulnerabilities
const TEST_SAMPLES = {
  javascript_xss: `
function displayUserName(username) {
  // VULNERABLE: XSS via innerHTML
  document.getElementById('greeting').innerHTML = 'Hello ' + username;
  
  // VULNERABLE: document.write
  document.write('<p>Welcome ' + username + '</p>');
  
  // Safe alternative (commented out)
  // document.getElementById('greeting').textContent = 'Hello ' + username;
}

function sendResponse(res, data) {
  // VULNERABLE: Unencoded response
  res.send('<h1>' + data.title + '</h1>');
}
`,

  javascript_injection: `
function evaluateExpression(userExpression) {
  // CRITICAL: Code injection
  const result = eval(userExpression);
  return result;
}

function createDynamicFunction(userCode) {
  // CRITICAL: Function constructor with user input
  const fn = new Function('x', userCode);
  return fn(10);
}
`,

  python_injection: `
def execute_user_code(user_input):
    # CRITICAL: Arbitrary code execution
    exec(user_input)
    
def evaluate_expression(expression):
    # CRITICAL: Eval injection
    result = eval(expression)
    return result

def run_system_command(command):
    # CRITICAL: Command injection
    import os
    os.system(command)
`,

  python_sqli: `
def get_user_by_id(user_id):
    # VULNERABLE: SQL injection via string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def search_users(username):
    # VULNERABLE: SQL injection
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
`,

  safe_code: `
// This is safe code - should have no findings
function greetUser(username) {
  // Safe: textContent does not parse HTML
  document.getElementById('greeting').textContent = 'Hello ' + username;
}

function getData() {
  // Safe: JSON.parse with validation
  const data = JSON.parse(userInput);
  if (typeof data.name === 'string') {
    return data;
  }
}
`
};

async function testSecurityReview() {
  console.log('🔒 Testing Security Review Engine (Phase 6)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  // Clean up old test database
  if (existsSync(TEST_DB_PATH)) {
    unlinkSync(TEST_DB_PATH);
    console.log('🗑️  Removed old test database\n');
  }

  // Step 1: Initialize and seed KB
  console.log('1️⃣  Initializing Security Knowledge Base...');
  const kb = new SecurityKnowledgeBase(TEST_DB_PATH);
  await kb.initialize();
  console.log('✅ Knowledge Base initialized\n');

  console.log('2️⃣  Seeding database (this may take a moment)...');
  const seedResult = await kb.seed({
    cveLimit: 500,
    cveSeverityFilter: 'MEDIUM',
    verbose: false
  });
  console.log(`✅ Seeded: ${seedResult.cwes_inserted} CWEs, ${seedResult.cves_inserted} CVEs, ${seedResult.remediation_entries} remediation examples\n`);

  // Step 2: Test JavaScript XSS Detection
  console.log('3️⃣  Testing JavaScript XSS Detection...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  const xssResult = await kb.reviewCode('javascript', TEST_SAMPLES.javascript_xss);
  
  console.log(`📊 Summary: ${xssResult.findings.length} findings`);
  console.log(`   Critical: ${xssResult.summary.critical}, High: ${xssResult.summary.high}, Medium: ${xssResult.summary.medium}, Low: ${xssResult.summary.low}`);
  console.log(`   Total Risk Score: ${xssResult.summary.total_risk_score}/10`);
  console.log(`   Average Confidence: ${(xssResult.summary.average_confidence * 100).toFixed(0)}%\n`);

  if (xssResult.findings.length > 0) {
    const finding = xssResult.findings[0];
    console.log(`🔍 Sample Finding:`);
    console.log(`   Pattern: ${finding.pattern}`);
    console.log(`   Line: ${finding.line_number}`);
    console.log(`   CWE: ${finding.cwe.id} - ${finding.cwe.name}`);
    console.log(`   OWASP: ${finding.owasp.join(', ')}`);
    console.log(`   Risk Score: ${finding.risk_score}/10`);
    console.log(`   Confidence: ${(finding.confidence * 100).toFixed(0)}% (Pattern: ${(finding.confidence_breakdown.pattern * 100).toFixed(0)}%, CWE: ${(finding.confidence_breakdown.cwe * 100).toFixed(0)}%, OWASP: ${(finding.confidence_breakdown.owasp * 100).toFixed(0)}%, CVE: ${(finding.confidence_breakdown.cve * 100).toFixed(0)}%)`);
    console.log(`   Urgency: ${finding.threat_context.urgency}`);
    console.log(`   Exploited in Wild: ${finding.threat_context.exploited_in_wild ? '⚠️ YES (CISA KEV)' : 'No'}`);
    console.log(`   Top CVEs: ${finding.cvss_context.top_cves.length} (Max CVSS: ${finding.cvss_context.max_cvss})`);
    
    if (finding.remediation) {
      console.log(`\n   ✅ Remediation Available:`);
      console.log(`      ${finding.remediation.explanation.substring(0, 100)}...`);
    }
    
    if (finding.false_positive_notes) {
      console.log(`\n   ⚠️ False Positive Note: ${finding.false_positive_notes}`);
    }
  }
  console.log('');

  // Step 3: Test Code Injection Detection
  console.log('4️⃣  Testing Code Injection Detection...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  const injectionResult = await kb.reviewCode('javascript', TEST_SAMPLES.javascript_injection);
  
  console.log(`📊 Summary: ${injectionResult.findings.length} findings`);
  injectionResult.findings.forEach((f, i) => {
    console.log(`   ${i + 1}. ${f.pattern} (Line ${f.line_number}) - Risk: ${f.risk_score}/10, Urgency: ${f.threat_context.urgency}`);
  });
  console.log('');

  // Step 4: Test Python Vulnerabilities
  console.log('5️⃣  Testing Python Injection Detection...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  const pythonResult = await kb.reviewCode('python', TEST_SAMPLES.python_injection);
  
  console.log(`📊 Summary: ${pythonResult.findings.length} findings`);
  pythonResult.findings.forEach((f, i) => {
    console.log(`   ${i + 1}. ${f.pattern} (Line ${f.line_number}) - ${f.cwe.id}, Confidence: ${(f.confidence * 100).toFixed(0)}%`);
  });
  console.log('');

  // Step 5: Test SQL Injection
  console.log('6️⃣  Testing SQL Injection Detection...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  const sqliResult = await kb.reviewCode('python', TEST_SAMPLES.python_sqli);
  
  console.log(`📊 Summary: ${sqliResult.findings.length} findings`);
  if (sqliResult.findings.length > 0) {
    const sqli = sqliResult.findings[0];
    console.log(`\n🔍 SQL Injection Finding:`);
    console.log(`   CWE: ${sqli.cwe.id}`);
    console.log(`   Attack Vector: ${sqli.threat_context.attack_vector}`);
    console.log(`   Impact: ${sqli.threat_context.impact}`);
    
    if (sqli.remediation) {
      console.log(`\n   🛡️ Secure Alternative:`);
      console.log(`      ${sqli.remediation.secure_example.split('\n')[0]}...`);
    }
  }
  console.log('');

  // Step 6: Test Safe Code (Should have minimal/no findings)
  console.log('7️⃣  Testing Safe Code (False Positive Check)...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  const safeResult = await kb.reviewCode('javascript', TEST_SAMPLES.safe_code);
  
  console.log(`📊 Summary: ${safeResult.findings.length} findings`);
  if (safeResult.findings.length === 0) {
    console.log('✅ No vulnerabilities detected in safe code (correct!)');
  } else {
    console.log('⚠️ Findings in "safe" code - may be false positives:');
    safeResult.findings.forEach((f, i) => {
      console.log(`   ${i + 1}. ${f.pattern} - ${f.false_positive_notes || 'No FP note'}`);
    });
  }
  console.log('');

  // Step 7: Quality Assessment
  console.log('8️⃣  Security Review Engine Quality Assessment...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  const allResults = [xssResult, injectionResult, pythonResult, sqliResult];
  const totalFindings = allResults.reduce((sum, r) => sum + r.findings.length, 0);
  const criticalFindings = allResults.reduce((sum, r) => sum + r.summary.critical, 0);
  const kevFindings = allResults.flatMap(r => r.findings).filter(f => f.threat_context.exploited_in_wild).length;
  const withRemediation = allResults.flatMap(r => r.findings).filter(f => f.remediation).length;
  
  console.log(`✅ Total Findings: ${totalFindings}`);
  console.log(`✅ Critical Urgency: ${criticalFindings}`);
  console.log(`✅ Exploited in Wild (CISA KEV): ${kevFindings}`);
  console.log(`✅ With Remediation Guidance: ${withRemediation}/${totalFindings} (${((withRemediation/totalFindings)*100).toFixed(0)}%)`);
  console.log(`✅ False Positives on Safe Code: ${safeResult.findings.length}`);
  
  console.log('\n📊 Confidence Distribution:');
  const confidences = allResults.flatMap(r => r.findings).map(f => f.confidence);
  const avgConfidence = confidences.reduce((sum, c) => sum + c, 0) / confidences.length;
  const highConfidence = confidences.filter(c => c >= 0.7).length;
  const mediumConfidence = confidences.filter(c => c >= 0.5 && c < 0.7).length;
  const lowConfidence = confidences.filter(c => c < 0.5).length;
  
  console.log(`   Average: ${(avgConfidence * 100).toFixed(0)}%`);
  console.log(`   High (≥70%): ${highConfidence}/${totalFindings}`);
  console.log(`   Medium (50-70%): ${mediumConfidence}/${totalFindings}`);
  console.log(`   Low (<50%): ${lowConfidence}/${totalFindings}`);
  
  // Step 8: Explainability Check
  console.log('\n9️⃣  Explainability Assessment...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  const sampleFinding = xssResult.findings[0];
  if (sampleFinding) {
    console.log('✅ Finding includes:');
    console.log(`   - Why risky: ${sampleFinding.explanation.includes('Why This Is Risky') ? 'Yes' : 'No'}`);
    console.log(`   - CWE context: ${sampleFinding.explanation.includes('CWE Context') ? 'Yes' : 'No'}`);
    console.log(`   - Real-world evidence: ${sampleFinding.explanation.includes('Evidence') ? 'Yes' : 'No'}`);
    console.log(`   - Confidence breakdown: ${sampleFinding.confidence_breakdown ? 'Yes' : 'No'}`);
    console.log(`   - Blue Team context: ${sampleFinding.threat_context ? 'Yes' : 'No'}`);
    console.log(`   - Remediation: ${sampleFinding.remediation ? 'Yes' : 'No'}`);
  }
  
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('✅ Phase 6 Security Review Engine Test Complete!');
  console.log('\n📦 Test database saved at:', TEST_DB_PATH);
  console.log('📏 Database size:', (existsSync(TEST_DB_PATH) ? `${(require('fs').statSync(TEST_DB_PATH).size / 1024).toFixed(2)} KB` : 'N/A'));
}

// Run tests
testSecurityReview().catch(error => {
  console.error('❌ Test failed:', error);
  process.exit(1);
});
