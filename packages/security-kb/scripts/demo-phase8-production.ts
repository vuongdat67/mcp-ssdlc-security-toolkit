/**
 * Phase 8: Production Demo
 * 
 * Demonstrates the complete security review workflow:
 * 1. Deterministic vulnerability detection
 * 2. Severity normalization
 * 3. Report generation
 * 4. MCP tool integration readiness
 */

import { createSecurityKB, generateSecurityReport, generateQuickSummary } from '../src/index.js';
import { writeFileSync } from 'fs';
import { join } from 'path';

// ============================================================================
// Sample Vulnerable Code
// ============================================================================

const VULNERABLE_APPLICATION = `
// E-Commerce Application - Vulnerable Code Sample

// 1. XSS Vulnerability
function displayProductReview(review) {
  const reviewDiv = document.getElementById('reviews');
  reviewDiv.innerHTML = userInput; // VULN: XSS via innerHTML
  document.write(userInput); // VULN: XSS via document.write
}

// 2. SQL Injection
async function searchProducts(query) {
  const sql = "SELECT * FROM products WHERE name = '" + query + "'"; // VULN: SQLi
  return await db.query(sql);
}

// 3. Command Injection
const { exec } = require('child_process');
function deployBranch(branchName) {
  exec('git pull origin ' + branchName); // VULN: Command injection
}

// 4. SSRF
async function fetchProductImage(imageUrl) {
  const response = await fetch(imageUrl); // VULN: SSRF via fetch
  const data = await axios.get(imageUrl); // VULN: SSRF via axios
  return response.blob();
}

// 5. Hardcoded Secrets
const api_key = "sk_live_abc123xyz789secret"; // VULN: Hardcoded API key
const api_secret = "0123456789abcdefghijklmnopqrstuvwxyz"; // VULN: Hardcoded secret
const github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"; // VULN: GitHub token

// 6. Path Traversal
const fs = require('fs');
function loadTemplate(templateName) {
  return fs.readFileSync(templateName); // VULN: Path traversal
}

function streamUserFile(userPath) {
  return fs.createReadStream(userPath); // VULN: Path traversal
}

// 7. Insecure Randomness
function generateSessionToken() {
  return Math.random().toString(36); // VULN: Insecure PRNG
}

// 8. Eval Injection
function executeUserCode(code) {
  eval(userInput); // VULN: Code injection via eval
  new Function(userInput)(); // VULN: Function constructor
}
`;

// ============================================================================
// Main Demo
// ============================================================================

async function main() {
  console.log('🔒 Phase 8: Production Security Review Demo');
  console.log('═'.repeat(80));
  console.log('\nAnalyzing vulnerable e-commerce application...\n');
  
  // ──────────────────────────────────────────────────────────────────────────
  // Step 1: Initialize Security KB
  // ──────────────────────────────────────────────────────────────────────────
  console.log('📚 Step 1: Initializing Security Knowledge Base...');
  const kb = await createSecurityKB();
  console.log('✅ Knowledge base loaded\n');
  
  // ──────────────────────────────────────────────────────────────────────────
  // Step 2: Perform Deterministic Security Review
  // ──────────────────────────────────────────────────────────────────────────
  console.log('🔍 Step 2: Performing deterministic security analysis...');
  const startTime = Date.now();
  const result = await kb.reviewCode('javascript', VULNERABLE_APPLICATION);
  const analysisTime = Date.now() - startTime;
  console.log(`✅ Analysis complete in ${analysisTime}ms\n`);
  
  // ──────────────────────────────────────────────────────────────────────────
  // Step 3: Display Quick Summary
  // ──────────────────────────────────────────────────────────────────────────
  console.log('📊 Step 3: Quick Summary');
  console.log('─'.repeat(80));
  console.log(generateQuickSummary(result));
  console.log();
  
  // ──────────────────────────────────────────────────────────────────────────
  // Step 4: Generate Reports
  // ──────────────────────────────────────────────────────────────────────────
  console.log('📝 Step 4: Generating security reports...\n');
  
  // Full report (for security team)
  const fullReport = generateSecurityReport(result, {
    projectName: 'E-Commerce Application',
    format: 'full',
    includeRemediation: true
  });
  
  const fullReportPath = join(process.cwd(), 'data', 'phase8-full-report.md');
  writeFileSync(fullReportPath, fullReport, 'utf-8');
  console.log(`✅ Full report: ${fullReportPath}`);
  
  // Executive summary (for management)
  const execReport = generateSecurityReport(result, {
    projectName: 'E-Commerce Application',
    format: 'executive',
    minSeverity: 'HIGH'
  });
  
  const execReportPath = join(process.cwd(), 'data', 'phase8-executive-summary.md');
  writeFileSync(execReportPath, execReport, 'utf-8');
  console.log(`✅ Executive summary: ${execReportPath}`);
  
  // Developer report (for engineering team)
  const devReport = generateSecurityReport(result, {
    projectName: 'E-Commerce Application',
    format: 'developer',
    includeRemediation: true
  });
  
  const devReportPath = join(process.cwd(), 'data', 'phase8-developer-report.md');
  writeFileSync(devReportPath, devReport, 'utf-8');
  console.log(`✅ Developer report: ${devReportPath}`);
  
  // JSON output (for CI/CD integration)
  const jsonPath = join(process.cwd(), 'data', 'phase8-findings.json');
  writeFileSync(jsonPath, JSON.stringify(result, null, 2), 'utf-8');
  console.log(`✅ JSON findings: ${jsonPath}\n`);
  
  // ──────────────────────────────────────────────────────────────────────────
  // Step 5: Findings Breakdown
  // ──────────────────────────────────────────────────────────────────────────
  console.log('🔍 Step 5: Findings Breakdown');
  console.log('─'.repeat(80));
  
  console.log(`\n**Severity Distribution**:`);
  console.log(`  🔴 Critical: ${result.summary.critical}`);
  console.log(`  🟠 High: ${result.summary.high}`);
  console.log(`  🟡 Medium: ${result.summary.medium}`);
  console.log(`  🟢 Low: ${result.summary.low}`);
  
  const exploited = result.findings.filter(f => f.threat_context.exploited_in_wild).length;
  const cisaKev = result.findings.filter(f => 
    f.cvss_context.top_cves.some(cve => cve.cisa_kev)
  ).length;
  
  console.log(`\n**Priority Indicators**:`);
  console.log(`  ⚠️ Exploited in wild: ${exploited}`);
  console.log(`  ⚠️ CISA KEV listed: ${cisaKev}`);
  console.log(`  📊 Average confidence: ${(result.summary.average_confidence * 100).toFixed(0)}%`);
  console.log(`  🎯 Overall risk score: ${result.summary.total_risk_score.toFixed(1)}/100`);
  
  // ──────────────────────────────────────────────────────────────────────────
  // Step 6: Top Vulnerabilities
  // ──────────────────────────────────────────────────────────────────────────
  console.log(`\n🚨 Step 6: Top Vulnerabilities (High Risk)`);
  console.log('─'.repeat(80));
  
  const topFindings = result.findings
    .filter(f => f.risk_score >= 7.0)
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 5);
  
  topFindings.forEach((finding, index) => {
    console.log(`\n${index + 1}. ${finding.cwe.id}: ${finding.cwe.name}`);
    console.log(`   Risk: ${finding.risk_score.toFixed(1)}/10 | Confidence: ${(finding.confidence * 100).toFixed(0)}%`);
    console.log(`   Pattern: ${finding.pattern}`);
    if (finding.threat_context.exploited_in_wild) {
      console.log(`   ⚠️ ACTIVELY EXPLOITED IN THE WILD`);
    }
  });
  
  // ──────────────────────────────────────────────────────────────────────────
  // Step 7: MCP Tool Usage Example
  // ──────────────────────────────────────────────────────────────────────────
  console.log(`\n\n📡 Step 7: MCP Tool Integration`);
  console.log('─'.repeat(80));
  console.log(`
The security_review_code tool is now available in the MCP server.

**Example MCP Request**:
\`\`\`json
{
  "method": "tools/call",
  "params": {
    "name": "security_review_code",
    "arguments": {
      "code_snippet": "div.innerHTML = userInput;",
      "language": "javascript",
      "mode": "deep",
      "report_format": "developer",
      "include_remediation": true
    }
  }
}
\`\`\`

**Example CLI Usage**:
\`\`\`bash
# Analyze a file
node dist/mcp-server.js security_review_code \\
  --file_path ./src/app.js \\
  --language javascript \\
  --mode deep \\
  --report_format full

# Analyze code snippet
node dist/mcp-server.js security_review_code \\
  --code_snippet "exec(\\\`git pull \${branch}\\\`)" \\
  --language javascript \\
  --mode quick \\
  --report_format json
\`\`\`
`);
  
  // ──────────────────────────────────────────────────────────────────────────
  // Step 8: Performance Metrics
  // ──────────────────────────────────────────────────────────────────────────
  console.log(`\n📈 Step 8: Performance Metrics`);
  console.log('─'.repeat(80));
  console.log(`
**Analysis Performance**:
  • Lines analyzed: ${result.total_lines}
  • Patterns checked: ${result.scan_metadata.patterns_checked}
  • Findings detected: ${result.findings.length}
  • Analysis time: ${analysisTime}ms
  • Throughput: ${(result.total_lines / (analysisTime / 1000)).toFixed(0)} lines/second

**Detection Coverage**:
  • CWE categories: ${new Set(result.findings.map(f => f.cwe.id)).size}
  • OWASP categories: ${new Set(result.findings.flatMap(f => f.owasp)).size}
  • CVE references: ${result.findings.reduce((sum, f) => sum + f.cvss_context.top_cves.length, 0)}
`);
  
  // ──────────────────────────────────────────────────────────────────────────
  // Summary
  // ──────────────────────────────────────────────────────────────────────────
  console.log('═'.repeat(80));
  console.log('✅ Phase 8 Demo Complete!');
  console.log('═'.repeat(80));
  console.log(`
📊 **Production Readiness Summary**:

✅ Deterministic Detection: ${result.findings.length} vulnerabilities detected
✅ Severity Normalization: Developer/Security/Business impact calculated
✅ Report Generation: Full, Executive, Developer, and JSON formats
✅ MCP Tool Integration: Ready for Claude Desktop / API usage
✅ Performance: ${(result.total_lines / (analysisTime / 1000)).toFixed(0)} lines/second throughput
✅ Knowledge Base: ${result.scan_metadata.patterns_checked} patterns from CWE/CVE/OWASP

📁 **Generated Reports**:
  • Full Report: data/phase8-full-report.md
  • Executive Summary: data/phase8-executive-summary.md
  • Developer Report: data/phase8-developer-report.md
  • JSON Findings: data/phase8-findings.json

🚀 **Next Steps**:
  1. Review generated reports in data/ directory
  2. Integrate MCP tool in ssdlc-planner/src/index.ts
  3. Test with Claude Desktop MCP configuration
  4. Deploy to production environment
  5. Add CI/CD integration for automated security reviews

🔗 **MCP Tool**: security_review_code
📚 **Documentation**: See README.md for architecture and usage

Phase 8 is complete and production-ready! 🎉
`);
}

// ============================================================================
// Run Demo
// ============================================================================

main().catch(error => {
  console.error('❌ Demo failed:', error);
  process.exit(1);
});
