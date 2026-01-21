/**
 * Test Real Data Parsers - Phase 4
 * 
 * Validates CWE, CVE, and OWASP parsers with sample data
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { parseCWEXML } from '../src/parsers/cwe-parser';
import { parseCVEJSONSimple } from '../src/parsers/cve-parser-simple';
import { parseOWASPTop10 } from '../src/parsers/owasp-parser';

const CWE_XML_PATH = join(__dirname, '../../../data/cwec/cwec_v4.19.xml');
const CVE_JSON_PATH = join(__dirname, '../../../data/nist/nvdcve-2.0-modified.json');
const OWASP_DOCS_PATH = join(__dirname, '../../../data/top10_owasp');

console.log('🧪 MCP SSDLC Security Toolkit - Parser Tests (Phase 4)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

async function runTests() {

// Test CWE Parser
console.log('\n1️⃣  Testing CWE Parser...');
if (!existsSync(CWE_XML_PATH)) {
  console.error(`   ❌ CWE XML not found: ${CWE_XML_PATH}`);
} else {
  try {
    const cwes = parseCWEXML(CWE_XML_PATH);
    console.log(`   ✅ Parsed ${cwes.length} CWE entries`);
    
    // Show sample
    if (cwes.length > 0) {
      const sample = cwes.find(c => c.cwe_id === 'CWE-1004') || cwes[0];
      console.log(`\n   Sample: ${sample.cwe_id}`);
      console.log(`   Name: ${sample.name}`);
      console.log(`   Severity: ${sample.severity}`);
      console.log(`   Description: ${sample.description.substring(0, 100)}...`);
      console.log(`   Mitigations: ${sample.mitigations?.length || 0}`);
      console.log(`   Related CWEs: ${sample.related_cwes?.length || 0}`);
    }
  } catch (error) {
    console.error(`   ❌ Parsing failed:`, error);
  }
}

// Test CVE Parser (OPTIMIZED - Memory Efficient)
console.log('\n2️⃣  Testing CVE Parser (Optimized)...');
if (!existsSync(CVE_JSON_PATH)) {
  console.error(`   ❌ CVE JSON not found: ${CVE_JSON_PATH}`);
} else {
  try {
    console.log(`   📄 Parsing with optimized parser (limit: 500 entries)...`);
    
    const startTime = Date.now();
    
    const cves = await parseCVEJSONSimple(CVE_JSON_PATH, {
      limit: 500, // Parse only first 500 for testing
      minSeverity: 'MEDIUM', // Only MEDIUM+ severity
      onProgress: (count) => {
        if (count % 1000 === 0) {
          console.log(`   ⏳ Processed ${count} CVEs...`);
        }
      }
    });
    
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(`   ✅ Parsed ${cves.length} CVEs in ${duration}s`);
    
    // Show sample
    if (cves.length > 0) {
      const sample = cves[0];
      console.log(`\n   Sample: ${sample.cve_id}`);
      console.log(`   Severity: ${sample.severity} (CVSS: ${sample.cvss_score})`);
      console.log(`   Description: ${sample.description.substring(0, 100)}...`);
      console.log(`   CWEs: ${sample.cwe_ids?.join(', ') || 'None'}`);
      console.log(`   CISA KEV: ${sample.cisa_known_exploited ? 'Yes' : 'No'}`);
      console.log(`   Technologies: ${sample.affected_technologies?.join(', ') || 'None'}`);
    }
    
    // Statistics
    const critical = cves.filter(c => c.severity === 'CRITICAL').length;
    const high = cves.filter(c => c.severity === 'HIGH').length;
    const medium = cves.filter(c => c.severity === 'MEDIUM').length;
    const cisa = cves.filter(c => c.cisa_known_exploited).length;
    
    console.log(`\n   Distribution:`);
    console.log(`     CRITICAL: ${critical}`);
    console.log(`     HIGH: ${high}`);
    console.log(`     MEDIUM: ${medium}`);
    console.log(`     CISA Known Exploited: ${cisa}`);
  } catch (error) {
    console.error(`   ❌ Parsing failed:`, error);
  }
}

// Test OWASP Parser
console.log('\n3️⃣  Testing OWASP Top 10 2025 Parser...');
if (!existsSync(OWASP_DOCS_PATH)) {
  console.error(`   ❌ OWASP docs not found: ${OWASP_DOCS_PATH}`);
} else {
  try {
    const entries = parseOWASPTop10(OWASP_DOCS_PATH);
    console.log(`   ✅ Parsed ${entries.length} OWASP Top 10 2025 entries`);
    
    // Show samples
    if (entries.length > 0) {
      entries.slice(0, 3).forEach(entry => {
        console.log(`\n   ${entry.category}: ${entry.name}`);
        console.log(`   Description: ${entry.description.substring(0, 100)}...`);
        console.log(`   Related CWEs: ${entry.related_cwes?.length || 0}`);
        console.log(`   Prevention strategies: ${entry.prevention_strategies?.length || 0}`);
      });
    }
  } catch (error) {
    console.error(`   ❌ Parsing failed:`, error);
  }
}

}

runTests().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('✅ Parser tests completed');
