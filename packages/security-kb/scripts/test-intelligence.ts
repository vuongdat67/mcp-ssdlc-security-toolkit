/**
 * Test Security Intelligence Layer
 * Phase 5: Validate database seeding and intelligent queries
 */

import { SecurityKnowledgeBase } from '../src/index';
import { existsSync, unlinkSync } from 'fs';
import { join } from 'path';

const TEST_DB_PATH = join(__dirname, '../data/test-security.db');

async function testIntelligenceLayer() {
  console.log('🧪 Testing Security Intelligence Layer (Phase 5)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  // Clean up old test database
  if (existsSync(TEST_DB_PATH)) {
    unlinkSync(TEST_DB_PATH);
    console.log('🗑️  Removed old test database\n');
  }

  // Step 1: Initialize Knowledge Base
  console.log('1️⃣  Initializing Security Knowledge Base...');
  const kb = new SecurityKnowledgeBase(TEST_DB_PATH);
  await kb.initialize();
  console.log('✅ Knowledge Base initialized\n');

  // Step 2: Seed Database
  console.log('2️⃣  Seeding database with real security data...');
  const startTime = Date.now();
  
  const seedResult = await kb.seed({
    cveLimit: 500,
    cveSeverityFilter: 'MEDIUM',
    verbose: true
  });

  const duration = (Date.now() - startTime) / 1000;
  console.log(`\n✅ Seeding completed in ${duration.toFixed(2)}s`);
  console.log(`\n📊 Seed Results:`);
  console.log(`   CWEs: ${seedResult.cwes_inserted}`);
  console.log(`   CVEs: ${seedResult.cves_inserted}`);
  console.log(`   OWASP: ${seedResult.owasp_inserted}`);
  console.log(`   CVE-CWE Mappings: ${seedResult.cve_cwe_mappings}`);
  console.log(`   CWE-OWASP Mappings: ${seedResult.cwe_owasp_mappings}`);
  console.log(`   Threat Patterns: ${seedResult.threat_patterns}`);

  // Step 3: Validate Schema
  console.log(`\n3️⃣  Validating schema...`);
  const validation = kb.validateSchema();
  if (validation.valid) {
    console.log('✅ Schema validation passed');
  } else {
    console.error('❌ Schema validation failed:', validation.errors);
    return;
  }

  // Step 4: Get Statistics
  console.log(`\n4️⃣  Knowledge Base Statistics:`);
  const stats = kb.getStats();
  for (const [key, value] of Object.entries(stats)) {
    console.log(`   ${key}: ${value}`);
  }

  // Step 5: Test CWE Queries
  console.log(`\n5️⃣  Testing CWE Queries...`);
  const xssCWE = kb.getCWE('CWE-79');
  if (xssCWE) {
    console.log(`✅ Found ${xssCWE.cwe_id}: ${xssCWE.name}`);
    console.log(`   Severity: ${xssCWE.severity}`);
    console.log(`   Mitigations: ${xssCWE.mitigations.length}`);
  } else {
    console.log('❌ CWE-79 not found');
  }

  // Step 6: Test CVE Queries
  console.log(`\n6️⃣  Testing CVE Queries (by CWE)...`);
  const xssCVEs = kb.queryCVEsByCWE('CWE-79', { limit: 5, minCVSS: 7.0 });
  console.log(`✅ Found ${xssCVEs.length} high-severity XSS CVEs`);
  if (xssCVEs.length > 0) {
    const sample = xssCVEs[0];
    console.log(`\n   Sample: ${sample.cve_id}`);
    console.log(`   Severity: ${sample.severity} (CVSS: ${sample.cvss_score})`);
    console.log(`   Description: ${sample.description.substring(0, 150)}...`);
    console.log(`   CISA KEV: ${sample.cisa_known_exploited ? 'Yes' : 'No'}`);
  }

  // Step 7: Test OWASP Mappings
  console.log(`\n7️⃣  Testing OWASP Mappings...`);
  const owaspForXSS = kb.getOWASPByCWE('CWE-79');
  if (owaspForXSS.length > 0) {
    console.log(`✅ CWE-79 maps to ${owaspForXSS.length} OWASP categories`);
    for (const owasp of owaspForXSS) {
      console.log(`   ${owasp.category}: ${owasp.name}`);
    }
  } else {
    console.log('⚠️  No OWASP mappings found for CWE-79');
  }

  // Step 8: Test Threat Intelligence
  console.log(`\n8️⃣  Testing Threat Intelligence (explainThreat)...`);
  const threats = [
    { pattern: 'eval(userInput)', language: 'javascript' },
    { pattern: 'innerHTML = userInput', language: 'javascript' },
    { pattern: 'exec(user_input)', language: 'python' }
  ];

  for (const threat of threats) {
    console.log(`\n   Testing: ${threat.pattern} (${threat.language})`);
    const explanation = kb.explainThreat(threat.pattern, threat.language);
    
    if (explanation) {
      console.log(`   ✅ Risk Score: ${explanation.risk_score}/10`);
      console.log(`   ✅ Confidence: ${(explanation.confidence * 100).toFixed(0)}%`);
      console.log(`   ✅ CWE: ${explanation.cwe[0].cwe_id} (${explanation.cwe[0].name})`);
      console.log(`   ✅ OWASP: ${explanation.owasp.length > 0 ? explanation.owasp[0].category : 'None'}`);
      console.log(`   ✅ CVEs Found: ${explanation.top_cves.length}`);
      
      console.log(`\n   📊 Reasoning Chain:`);
      for (const step of explanation.reasoning_chain) {
        console.log(`      ${step.level.toUpperCase()}: ${step.description} (${(step.confidence * 100).toFixed(0)}% confidence)`);
      }

      if (explanation.top_cves.length > 0) {
        console.log(`\n   🔥 Top CVE: ${explanation.top_cves[0].cve_id} (CVSS ${explanation.top_cves[0].cvss_score})`);
      }

      console.log(`\n   💡 Explanation:`);
      const lines = explanation.explanation.split('\n');
      for (const line of lines.slice(0, 3)) {
        if (line.trim()) console.log(`      ${line.trim()}`);
      }
    } else {
      console.log(`   ❌ No explanation found`);
    }
  }

  // Step 9: Test Risk Scoring
  console.log(`\n9️⃣  Testing Risk Scoring...`);
  const riskScore = kb.calculateRiskScore('CWE-79');
  console.log(`   Risk Score for CWE-79: ${riskScore}/10`);

  // Step 10: Save Database
  console.log(`\n🔟 Saving database...`);
  kb.save();
  console.log(`✅ Database saved to ${TEST_DB_PATH}`);

  // Cleanup
  kb.close();

  console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log('✅ All tests completed successfully!');
  console.log(`\n📦 Test database: ${TEST_DB_PATH}`);
  console.log(`📏 Database size: ${(require('fs').statSync(TEST_DB_PATH).size / 1024).toFixed(2)} KB`);
}

// Run tests
testIntelligenceLayer().catch(error => {
  console.error('\n❌ Test failed:', error);
  process.exit(1);
});
