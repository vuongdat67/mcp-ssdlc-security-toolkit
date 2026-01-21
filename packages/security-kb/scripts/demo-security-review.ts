/**
 * Demo: Security Review Engine with Full Output
 * Shows complete finding details including Blue Team context
 */

import { SecurityKnowledgeBase } from '../src/index';
import { join } from 'path';

const DEMO_DB_PATH = join(__dirname, '../data/demo-security-review.db');

// Sample vulnerable code
const VULNERABLE_CODE = `
// User authentication endpoint
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  // VULNERABLE: SQL Injection via string concatenation
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  db.query(query, (err, results) => {
    if (results.length > 0) {
      // VULNERABLE: XSS via unescaped HTML
      res.send('<h1>Welcome ' + username + '!</h1>');
      
      // VULNERABLE: Code injection
      eval('logEvent("User ' + username + ' logged in")');
    }
  });
});
`;

async function demoSecurityReview() {
  console.log('🔒 Security Review Engine Demo');
  console.log('═'.repeat(80));
  console.log('\n📝 Analyzing vulnerable login endpoint...\n');
  console.log('Code:');
  console.log('-'.repeat(80));
  console.log(VULNERABLE_CODE);
  console.log('-'.repeat(80));
  console.log('\n');

  // Initialize KB
  const kb = new SecurityKnowledgeBase(DEMO_DB_PATH);
  await kb.initialize();
  await kb.seed({ cveLimit: 500, verbose: false });

  // Review code
  const result = await kb.reviewCode('javascript', VULNERABLE_CODE);

  console.log('🔍 SECURITY REVIEW RESULTS');
  console.log('═'.repeat(80));
  console.log(`\n📊 Summary:`);
  console.log(`   Language: ${result.language}`);
  console.log(`   Total Lines: ${result.total_lines}`);
  console.log(`   Findings: ${result.findings.length}`);
  console.log(`   - CRITICAL: ${result.summary.critical}`);
  console.log(`   - HIGH: ${result.summary.high}`);
  console.log(`   - MEDIUM: ${result.summary.medium}`);
  console.log(`   - LOW: ${result.summary.low}`);
  console.log(`   Total Risk Score: ${result.summary.total_risk_score}/10`);
  console.log(`   Average Confidence: ${(result.summary.average_confidence * 100).toFixed(0)}%`);
  console.log(`   Scan Duration: ${result.scan_metadata.duration_ms}ms\n`);

  // Display each finding in detail
  result.findings.forEach((finding, index) => {
    console.log('━'.repeat(80));
    console.log(`\n🚨 FINDING #${index + 1}: ${finding.threat_context.urgency} URGENCY`);
    console.log('━'.repeat(80));
    
    console.log('\n📍 Location:');
    console.log(`   Pattern: ${finding.pattern}`);
    console.log(`   Line: ${finding.line_number}`);
    console.log(`   Code: ${finding.snippet}`);
    
    console.log('\n🐛 Vulnerability:');
    console.log(`   CWE: ${finding.cwe.id} - ${finding.cwe.name}`);
    console.log(`   Severity: ${finding.cwe.severity}`);
    console.log(`   OWASP: ${finding.owasp.join(', ')}`);
    console.log(`   Risk Score: ${finding.risk_score}/10`);
    
    console.log('\n🎯 Blue Team Context:');
    console.log(`   Exploited in Wild: ${finding.threat_context.exploited_in_wild ? '⚠️ YES (CISA KEV)' : 'No'}`);
    console.log(`   Attack Vector: ${finding.threat_context.attack_vector}`);
    console.log(`   Impact: ${finding.threat_context.impact}`);
    console.log(`   Urgency: ${finding.threat_context.urgency}`);
    
    console.log('\n📈 CVE Evidence:');
    console.log(`   Related CVEs: ${finding.cvss_context.top_cves.length}`);
    console.log(`   Max CVSS Score: ${finding.cvss_context.max_cvss}`);
    if (finding.cvss_context.top_cves.length > 0) {
      console.log('   Top CVEs:');
      finding.cvss_context.top_cves.slice(0, 3).forEach(cve => {
        console.log(`      - ${cve.id} (CVSS ${cve.cvss_score}): ${cve.description.substring(0, 80)}...`);
      });
    }
    
    console.log('\n🔍 Confidence Analysis:');
    console.log(`   Overall: ${(finding.confidence * 100).toFixed(0)}%`);
    console.log(`   Breakdown:`);
    console.log(`      - Pattern Detection: ${(finding.confidence_breakdown.pattern * 100).toFixed(0)}%`);
    console.log(`      - CWE Data Quality: ${(finding.confidence_breakdown.cwe * 100).toFixed(0)}%`);
    console.log(`      - OWASP Mapping: ${(finding.confidence_breakdown.owasp * 100).toFixed(0)}%`);
    console.log(`      - CVE Evidence: ${(finding.confidence_breakdown.cve * 100).toFixed(0)}%`);
    
    console.log('\n📖 Explanation:');
    const explanationLines = finding.explanation.split('\n');
    explanationLines.forEach(line => {
      if (line.trim()) {
        console.log(`   ${line}`);
      }
    });
    
    if (finding.remediation) {
      console.log('\n✅ Remediation:');
      console.log('   Insecure Pattern:');
      finding.remediation.insecure_example.split('\n').forEach(line => {
        console.log(`      ${line}`);
      });
      console.log('\n   Secure Alternative:');
      finding.remediation.secure_example.split('\n').forEach(line => {
        console.log(`      ${line}`);
      });
      console.log(`\n   Guidance: ${finding.remediation.explanation}`);
    }
    
    if (finding.false_positive_notes) {
      console.log(`\n⚠️ False Positive Note: ${finding.false_positive_notes}`);
    }
    
    console.log('');
  });

  console.log('═'.repeat(80));
  console.log('✅ Security Review Complete!');
  console.log('═'.repeat(80));
  console.log('\n💡 Next Steps:');
  console.log('   1. Prioritize CRITICAL and HIGH urgency findings');
  console.log('   2. Review findings with exploited_in_wild = true first');
  console.log('   3. Apply secure coding alternatives from remediation guidance');
  console.log('   4. Re-scan code after fixes to verify resolution\n');
}

demoSecurityReview().catch(error => {
  console.error('❌ Demo failed:', error);
  process.exit(1);
});
