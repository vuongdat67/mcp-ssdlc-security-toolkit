/**
 * Seed Database with Real Security Data
 * Phase 5: Populate SQLite with CWE, CVE, OWASP data from Phase 4 parsers
 */

import { Database } from 'sql.js';
import { join } from 'path';
import { parseCWEXML } from './parsers/cwe-parser.js';
import { parseCVEJSONSimple } from './parsers/cve-parser-simple.js';
import { parseOWASPTop10 } from './parsers/owasp-parser.js';
import { initializeSchema } from './schema.js';
import { initializeRemediationSchema, seedRemediationData } from './remediation-schema.js';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { existsSync } from 'fs';
import { 
  normalizeForSQLite, 
  normalizeJSONField, 
  canonicalizeCWEId, 
  canonicalizeCVEId 
} from './utils/normalize.js';

// ESM equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Get the workspace root - handle both tsx (development) and built code
const getWorkspaceRoot = () => {
  // Try multiple possible paths
  const candidates = [
    join(process.cwd(), '../../'),  // When running from packages/security-kb
    join(process.cwd(), '../../../'), // When running from packages/security-kb/scripts
    join(__dirname, '../../../../'),  // When running from built dist/
  ];
  
  // Return the first path that contains the 'raw' directory
  for (const candidate of candidates) {
    const rawPath = join(candidate, 'raw');
    if (existsSync(rawPath)) {
      return candidate;
    }
  }
  
  // Fallback to current working directory
  return process.cwd();
};

// Raw data paths (relative to project root)
const WORKSPACE_ROOT = getWorkspaceRoot();
const RAW_DATA_ROOT = join(WORKSPACE_ROOT, 'raw');
const CWE_XML_PATH = join(RAW_DATA_ROOT, 'cwe_xml_zip/lastest/cwec_latest.xml/cwec_v4.19.xml');
const CVE_JSON_PATH = join(RAW_DATA_ROOT, 'nist_vuln_data-feeds/nvdcve-2.0-modified.json/nvdcve-2.0-modified.json');
const OWASP_DOCS_PATH = join(RAW_DATA_ROOT, 'Top10/2025/docs/en');

export interface SeedOptions {
  cveLimit?: number;
  cveSeverityFilter?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  verbose?: boolean;
}

export interface SeedResult {
  cwes_inserted: number;
  cves_inserted: number;
  owasp_inserted: number;
  cve_cwe_mappings: number;
  cwe_owasp_mappings: number;
  threat_patterns: number;
  remediation_entries: number;
  duration_ms: number;
}

/**
 * Seed the database with real security data.
 */
export async function seedDatabase(db: Database, options: SeedOptions = {}): Promise<SeedResult> {
  const startTime = Date.now();
  const {
    cveLimit = 1000,
    cveSeverityFilter = 'MEDIUM',
    verbose = false
  } = options;

  const log = (msg: string) => {
    if (verbose) console.log(`[Seed] ${msg}`);
  };

  // Step 1: Initialize schema
  log('Initializing schema...');
  initializeSchema(db, { enableIndexes: true });
  initializeRemediationSchema(db);
  log('Schema initialized');

  // Step 2: Seed CWEs
  log(`Parsing CWE XML from ${CWE_XML_PATH}...`);
  const cwes = parseCWEXML(CWE_XML_PATH);
  log(`Parsed ${cwes.length} CWEs`);

  const cweStmt = db.prepare(`
    INSERT INTO cwes (cwe_id, name, description, extended_description, severity, likelihood, mitigation_json, related_cwes_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  let cwesInserted = 0;
  for (const cwe of cwes) {
    try {
      // CRITICAL: Normalize all fields to prevent [object Object] binding errors
      // Extended_description and likelihood can be nested objects from XML parsing
      const normalizedCweId = canonicalizeCWEId(cwe.cwe_id) || cwe.cwe_id;
      const normalizedExtendedDesc = normalizeForSQLite(cwe.extended_description);
      const normalizedLikelihood = normalizeForSQLite(cwe.likelihood_of_exploit) || 'Medium';
      
      cweStmt.bind([
        normalizedCweId,
        cwe.name,
        cwe.description,
        normalizedExtendedDesc,
        cwe.severity || 'Medium',
        normalizedLikelihood,
        normalizeJSONField(cwe.mitigations),
        normalizeJSONField(cwe.related_cwes)
      ]);
      cweStmt.step();
      cweStmt.reset();
      cwesInserted++;
    } catch (error) {
      if (verbose) console.error(`Error inserting CWE ${cwe.cwe_id}:`, error);
    }
  }
  cweStmt.free();
  log(`Inserted ${cwesInserted} CWEs`);

  // Step 3: Seed CVEs
  log(`Parsing CVE JSON from ${CVE_JSON_PATH}...`);
  const cves = await parseCVEJSONSimple(CVE_JSON_PATH, {
    limit: cveLimit,
    minSeverity: cveSeverityFilter,
    onProgress: verbose ? (count) => {
      if (count % 500 === 0) log(`Processed ${count} CVEs...`);
    } : undefined
  });
  log(`Parsed ${cves.length} CVEs`);

  const cveStmt = db.prepare(`
    INSERT INTO cves (cve_id, description, severity, cvss_score, cvss_vector, published_date, last_modified, affected_technologies_json, references_json, cisa_known_exploited)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  let cvesInserted = 0;
  const cveCWEPairs: Array<{ cve_id: string; cwe_id: string }> = [];

  for (const cve of cves) {
    try {
      // Canonicalize CVE ID to ensure consistency
      const normalizedCveId = canonicalizeCVEId(cve.cve_id) || cve.cve_id;
      
      cveStmt.bind([
        normalizedCveId,
        cve.description,
        cve.severity,
        cve.cvss_score,
        cve.cvss_vector || null,
        cve.published_date,
        cve.last_modified,
        normalizeJSONField(cve.affected_technologies),
        normalizeJSONField(cve.references),
        cve.cisa_known_exploited ? 1 : 0
      ]);
      cveStmt.step();
      cveStmt.reset();
      cvesInserted++;

      // Collect CVE-CWE mappings with canonicalized IDs
      if (cve.cwe_ids && cve.cwe_ids.length > 0) {
        for (const cweId of cve.cwe_ids) {
          const normalizedCweId = canonicalizeCWEId(cweId);
          if (normalizedCweId) {
            cveCWEPairs.push({ cve_id: normalizedCveId, cwe_id: normalizedCweId });
          }
        }
      }
    } catch (error) {
      if (verbose) console.error(`Error inserting CVE ${cve.cve_id}:`, error);
    }
  }
  cveStmt.free();
  log(`Inserted ${cvesInserted} CVEs`);

  // Step 4: Insert CVE-CWE mappings
  log(`Inserting CVE-CWE mappings...`);
  const cveCWEStmt = db.prepare(`
    INSERT OR IGNORE INTO cve_cwe_mapping (cve_id, cwe_id, confidence)
    VALUES (?, ?, 1.0)
  `);

  let cveCWEMappings = 0;
  for (const pair of cveCWEPairs) {
    try {
      cveCWEStmt.bind([pair.cve_id, pair.cwe_id]);
      cveCWEStmt.step();
      cveCWEStmt.reset();
      cveCWEMappings++;
    } catch {
      // Ignore duplicates or invalid CWE references
    }
  }
  cveCWEStmt.free();
  log(`Inserted ${cveCWEMappings} CVE-CWE mappings`);

  // Step 5: Seed OWASP Top 10
  log(`Parsing OWASP Top 10 from ${OWASP_DOCS_PATH}...`);
  const owaspCategories = parseOWASPTop10(OWASP_DOCS_PATH);
  log(`Parsed ${owaspCategories.length} OWASP categories`);

  const owaspStmt = db.prepare(`
    INSERT INTO owasp_top10 (category, name, description, related_cwes_json, prevention_strategies_json, year)
    VALUES (?, ?, ?, ?, ?, 2025)
  `);

  let owaspInserted = 0;
  const cwOWASPPairs: Array<{ cwe_id: string; owasp_category: string }> = [];

  for (const owasp of owaspCategories) {
    try {
      owaspStmt.bind([
        owasp.category,
        owasp.name,
        owasp.description,
        normalizeJSONField(owasp.related_cwes),
        normalizeJSONField(owasp.prevention_strategies)
      ]);
      owaspStmt.step();
      owaspStmt.reset();
      owaspInserted++;

      // Collect CWE-OWASP mappings with canonicalized CWE IDs
      if (owasp.related_cwes && owasp.related_cwes.length > 0) {
        for (const cweId of owasp.related_cwes) {
          const normalizedCweId = canonicalizeCWEId(cweId);
          if (normalizedCweId) {
            cwOWASPPairs.push({ cwe_id: normalizedCweId, owasp_category: owasp.category });
          }
        }
      }
    } catch (error) {
      if (verbose) console.error(`Error inserting OWASP ${owasp.category}:`, error);
    }
  }
  owaspStmt.free();
  log(`Inserted ${owaspInserted} OWASP categories`);

  // Step 6: Insert CWE-OWASP mappings
  log(`Inserting CWE-OWASP mappings...`);
  const cweOWASPStmt = db.prepare(`
    INSERT OR IGNORE INTO cwe_owasp_mapping (cwe_id, owasp_category, confidence, source)
    VALUES (?, ?, 1.0, 'owasp_doc')
  `);

  let cweOWASPMappings = 0;
  for (const pair of cwOWASPPairs) {
    try {
      cweOWASPStmt.bind([pair.cwe_id, pair.owasp_category]);
      cweOWASPStmt.step();
      cweOWASPStmt.reset();
      cweOWASPMappings++;
    } catch {
      // Ignore duplicates or invalid CWE references
    }
  }
  cweOWASPStmt.free();
  log(`Inserted ${cweOWASPMappings} CWE-OWASP mappings`);

  // Step 7: Seed threat patterns (hardcoded security patterns)
  log(`Inserting threat patterns...`);
  const threatPatterns = getThreatPatterns();
  const patternStmt = db.prepare(`
    INSERT INTO threat_patterns (pattern, language, category, cwe_id, risk_score, confidence, explanation)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  let patternsInserted = 0;
  for (const pattern of threatPatterns) {
    try {
      patternStmt.bind([
        pattern.pattern,
        pattern.language,
        pattern.category,
        pattern.cwe_id,
        pattern.risk_score,
        pattern.confidence,
        pattern.explanation
      ]);
      patternStmt.step();
      patternStmt.reset();
      patternsInserted++;
    } catch (error) {
      if (verbose) console.error(`Error inserting pattern ${pattern.pattern}:`, error);
    }
  }
  patternStmt.free();
  log(`Inserted ${patternsInserted} threat patterns`);

  // Step 8: Seed remediation data
  log('Inserting remediation examples...');
  const remediationInserted = seedRemediationData(db);
  log(`Inserted ${remediationInserted} remediation entries`);

  const duration = Date.now() - startTime;
  log(`Seeding completed in ${duration}ms`);

  return {
    cwes_inserted: cwesInserted,
    cves_inserted: cvesInserted,
    owasp_inserted: owaspInserted,
    cve_cwe_mappings: cveCWEMappings,
    cwe_owasp_mappings: cweOWASPMappings,
    threat_patterns: patternsInserted,
    remediation_entries: remediationInserted,
    duration_ms: duration
  };
}

/**
 * Hardcoded threat patterns for common security issues.
 * 
 * Phase 6.2 Coverage Strategy:
 * - Code Injection: eval, exec, Function constructor
 * - XSS: innerHTML, document.write, unescaped templates
 * - SQL Injection: String concatenation, template literals, dynamic queries
 * - Command Injection: os.system, subprocess, child_process.exec
 * - Path Traversal: File operations without validation
 * - SSRF: Unvalidated HTTP requests (fetch, axios, requests)
 * - Hardcoded Secrets: API keys, tokens, passwords in source
 * - Deserialization: pickle, yaml.unsafe_load
 * 
 * Each pattern includes:
 * - Regex pattern for matching
 * - CWE mapping (canonical CWE-XXX format)
 * - Risk score (0-10, based on exploitability + impact)
 * - Confidence (0-1, based on detection accuracy)
 * - Explanation for security review outputs
 */
function getThreatPatterns() {
  return [
    // ========== JavaScript Code Injection Patterns ==========
    {
      pattern: 'eval\\(',
      language: 'javascript',
      category: 'injection',
      cwe_id: 'CWE-95',
      risk_score: 9.5,
      confidence: 0.95,
      explanation: 'Using eval() allows arbitrary code execution. Attackers can execute malicious JavaScript code in the application context. Use safer alternatives like JSON.parse().'
    },
    {
      pattern: 'new Function\\(',
      language: 'javascript',
      category: 'injection',
      cwe_id: 'CWE-95',
      risk_score: 9.0,
      confidence: 0.95,
      explanation: 'Creating functions from strings is equivalent to eval() and allows arbitrary code execution. Avoid dynamic code generation.'
    },

    // ========== JavaScript XSS Patterns ==========
    {
      pattern: '\\.innerHTML\\s*=',
      language: 'javascript',
      category: 'xss',
      cwe_id: 'CWE-79',
      risk_score: 8.0,
      confidence: 0.90,
      explanation: 'Setting innerHTML with unsanitized data enables Cross-Site Scripting (XSS) attacks. Use textContent for plain text or sanitize with DOMPurify.'
    },
    {
      pattern: 'document\\.write\\(',
      language: 'javascript',
      category: 'xss',
      cwe_id: 'CWE-79',
      risk_score: 7.5,
      confidence: 0.95,
      explanation: 'Using document.write() can lead to XSS vulnerabilities and is deprecated in modern applications. Use safer DOM manipulation methods.'
    },
    {
      pattern: '\\.html\\(',
      language: 'javascript',
      category: 'xss',
      cwe_id: 'CWE-79',
      risk_score: 8.0,
      confidence: 0.85,
      explanation: 'jQuery .html() method creates XSS vulnerabilities when used with unvalidated data. Use .text() for plain text or sanitize HTML.'
    },
    {
      pattern: 'res\\.send\\(\\s*[\'"]?<',
      language: 'javascript',
      category: 'xss',
      cwe_id: 'CWE-79',
      risk_score: 7.0,
      confidence: 0.80,
      explanation: 'Sending HTML directly in responses without encoding enables XSS. Use templating engines with auto-escaping or res.json().'
    },

    // ========== Python Injection Patterns ==========
    {
      pattern: 'exec\\(',
      language: 'python',
      category: 'injection',
      cwe_id: 'CWE-95',
      risk_score: 9.5,
      confidence: 0.95,
      explanation: 'Using exec() enables arbitrary Python code execution, giving attackers full control. Never use with untrusted input.'
    },
    {
      pattern: 'eval\\(',
      language: 'python',
      category: 'injection',
      cwe_id: 'CWE-95',
      risk_score: 9.5,
      confidence: 0.95,
      explanation: 'Using eval() allows arbitrary Python expression evaluation. Use ast.literal_eval() for safe parsing of literals.'
    },

    // ========== Python Command Injection Patterns ==========
    {
      pattern: 'os\\.system\\(',
      language: 'python',
      category: 'command-injection',
      cwe_id: 'CWE-78',
      risk_score: 9.0,
      confidence: 0.95,
      explanation: 'os.system() executes shell commands and is vulnerable to command injection. Use subprocess with shell=False.'
    },
    {
      pattern: 'subprocess.*shell\\s*=\\s*True',
      language: 'python',
      category: 'command-injection',
      cwe_id: 'CWE-78',
      risk_score: 9.0,
      confidence: 0.95,
      explanation: 'Using subprocess with shell=True enables command injection. Always use shell=False with argument lists.'
    },

    // ========== SQL Injection Patterns ==========
    // Python SQL Injection
    {
      pattern: 'f["\'].*SELECT.*FROM',
      language: 'python',
      category: 'sql-injection',
      cwe_id: 'CWE-89',
      risk_score: 8.5,
      confidence: 0.90,
      explanation: 'Using f-strings in SQL queries enables SQL injection. F-strings interpolate variables directly, bypassing parameterization. Use cursor.execute() with ? or %s placeholders.'
    },
    {
      pattern: 'cursor\\.execute\\(.*\\+',
      language: 'python',
      category: 'sql-injection',
      cwe_id: 'CWE-89',
      risk_score: 8.5,
      confidence: 0.90,
      explanation: 'Building SQL queries with string concatenation (+) allows SQL injection. Use parameterized queries with ? or %s placeholders.'
    },
    {
      pattern: '["\'].*SELECT.*["\']\\s*\\+',
      language: 'python',
      category: 'sql-injection',
      cwe_id: 'CWE-89',
      risk_score: 8.5,
      confidence: 0.90,
      explanation: 'String concatenation in SQL queries enables SQL injection. Use parameterized queries with proper placeholders.'
    },
    {
      pattern: '["\'].*SELECT.*WHERE.*["\']\\s*%',
      language: 'python',
      category: 'sql-injection',
      cwe_id: 'CWE-89',
      risk_score: 8.5,
      confidence: 0.85,
      explanation: 'Using string formatting (%) in SQL queries enables SQL injection. Use parameterized queries with proper placeholders.'
    },
    // JavaScript SQL Injection
    {
      pattern: '"SELECT.*WHERE.*"\\s*\\+',
      language: 'javascript',
      category: 'sql-injection',
      cwe_id: 'CWE-89',
      risk_score: 8.5,
      confidence: 0.85,
      explanation: 'String concatenation in SQL queries enables SQL injection attacks. Use parameterized queries or ORM query builders.'
    },
    {
      pattern: '`SELECT.*WHERE.*\\$\\{',
      language: 'javascript',
      category: 'sql-injection',
      cwe_id: 'CWE-89',
      risk_score: 8.5,
      confidence: 0.85,
      explanation: 'Template literals in SQL queries enable SQL injection. Use parameterized queries with libraries like pg or mysql2.'
    },
    {
      pattern: 'db\\.query\\([^)]*\\+',
      language: 'javascript',
      category: 'sql-injection',
      cwe_id: 'CWE-89',
      risk_score: 8.5,
      confidence: 0.85,
      explanation: 'Concatenating user input in database queries enables SQL injection. Use parameterized queries.'
    },
    {
      pattern: 'connection\\.execute\\([^)]*\\+',
      language: 'javascript',
      category: 'sql-injection',
      cwe_id: 'CWE-89',
      risk_score: 8.5,
      confidence: 0.85,
      explanation: 'Building SQL with string concatenation allows injection. Use placeholders: connection.execute(query, [param1, param2]).'
    },

    // ========== Command Injection Patterns ==========
    {
      pattern: '\\.exec\\(',
      language: 'javascript',
      category: 'command-injection',
      cwe_id: 'CWE-78',
      risk_score: 9.0,
      confidence: 0.85,
      explanation: 'exec() runs commands through shell, enabling command injection. Use execFile() or spawn() with argument arrays instead.'
    },
    {
      pattern: 'shell\\s*:\\s*true',
      language: 'javascript',
      category: 'command-injection',
      cwe_id: 'CWE-78',
      risk_score: 9.0,
      confidence: 0.90,
      explanation: 'Using spawn() with shell:true enables command injection. Always use shell:false with argument arrays.'
    },
    {
      pattern: 'subprocess\\.Popen\\([^,]*,\\s*shell\\s*=\\s*True',
      language: 'python',
      category: 'command-injection',
      cwe_id: 'CWE-78',
      risk_score: 9.0,
      confidence: 0.90,
      explanation: 'subprocess.Popen with shell=True enables command injection. Use shell=False with argument lists.'
    },
    {
      pattern: 'subprocess\\.run\\([^,]*,\\s*shell\\s*=\\s*True',
      language: 'python',
      category: 'command-injection',
      cwe_id: 'CWE-78',
      risk_score: 9.0,
      confidence: 0.90,
      explanation: 'subprocess.run with shell=True enables command injection. Use shell=False with list arguments.'
    },
    {
      pattern: 'os\\.popen\\(',
      language: 'python',
      category: 'command-injection',
      cwe_id: 'CWE-78',
      risk_score: 8.5,
      confidence: 0.90,
      explanation: 'os.popen() executes commands through shell. Use subprocess.run() with shell=False.'
    },

    // ========== Path Traversal Patterns ==========
    {
      pattern: 'fs\\.readFile\\(',
      language: 'javascript',
      category: 'path-traversal',
      cwe_id: 'CWE-22',
      risk_score: 7.0,
      confidence: 0.75,
      explanation: 'Reading files without path validation can enable directory traversal (../) attacks. Validate paths against allowlists and use path.resolve().'
    },
    {
      pattern: 'fs\\.readFileSync\\(',
      language: 'javascript',
      category: 'path-traversal',
      cwe_id: 'CWE-22',
      risk_score: 7.0,
      confidence: 0.75,
      explanation: 'Synchronous file reads without validation allow path traversal. Validate paths and use path.resolve() to prevent ../ attacks.'
    },
    {
      pattern: 'fs\\.createReadStream\\(',
      language: 'javascript',
      category: 'path-traversal',
      cwe_id: 'CWE-22',
      risk_score: 7.0,
      confidence: 0.75,
      explanation: 'Creating read streams without path validation enables directory traversal. Validate paths against safe base directories.'
    },
    {
      pattern: 'open\\(',
      language: 'python',
      category: 'path-traversal',
      cwe_id: 'CWE-22',
      risk_score: 6.5,
      confidence: 0.70,
      explanation: 'Opening files without validation may allow path traversal. Use pathlib.Path.resolve() and validate against safe base directories.'
    },
    {
      pattern: 'Path\\([^)]*\\)\\.read_text\\(',
      language: 'python',
      category: 'path-traversal',
      cwe_id: 'CWE-22',
      risk_score: 6.5,
      confidence: 0.70,
      explanation: 'Reading file contents without path validation allows traversal. Resolve paths and validate they remain in expected directories.'
    },

    // ========== SSRF Patterns ==========
    {
      pattern: 'fetch\\(',
      language: 'javascript',
      category: 'ssrf',
      cwe_id: 'CWE-918',
      risk_score: 8.0,
      confidence: 0.80,
      explanation: 'Using fetch() with unvalidated URLs enables SSRF attacks. Validate URLs against allowlists, block private IPs and cloud metadata endpoints.'
    },
    {
      pattern: 'axios\\.get\\(',
      language: 'javascript',
      category: 'ssrf',
      cwe_id: 'CWE-918',
      risk_score: 8.0,
      confidence: 0.80,
      explanation: 'axios.get() with user-controlled URLs enables SSRF. Validate URLs, block internal networks (127.0.0.1, 169.254.169.254).'
    },
    {
      pattern: 'axios\\.post\\(',
      language: 'javascript',
      category: 'ssrf',
      cwe_id: 'CWE-918',
      risk_score: 8.0,
      confidence: 0.80,
      explanation: 'axios.post() with unvalidated URLs enables SSRF. Implement URL allowlists and block access to internal resources.'
    },
    {
      pattern: 'http\\.get\\(',
      language: 'javascript',
      category: 'ssrf',
      cwe_id: 'CWE-918',
      risk_score: 8.0,
      confidence: 0.80,
      explanation: 'Node.js http.get() with user input enables SSRF. Validate destination URLs and block private network ranges.'
    },
    {
      pattern: 'https\\.get\\(',
      language: 'javascript',
      category: 'ssrf',
      cwe_id: 'CWE-918',
      risk_score: 8.0,
      confidence: 0.80,
      explanation: 'https.get() with user-controlled URLs enables SSRF. Validate URLs and prevent access to cloud metadata services.'
    },
    {
      pattern: 'requests\\.get\\(',
      language: 'python',
      category: 'ssrf',
      cwe_id: 'CWE-918',
      risk_score: 8.0,
      confidence: 0.80,
      explanation: 'requests.get() with unvalidated URLs enables SSRF. Validate URLs, use allowlists, block internal IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).'
    },
    {
      pattern: 'requests\\.post\\(',
      language: 'python',
      category: 'ssrf',
      cwe_id: 'CWE-918',
      risk_score: 8.0,
      confidence: 0.80,
      explanation: 'requests.post() with user input enables SSRF. Implement URL validation and prevent access to cloud metadata endpoints.'
    },
    {
      pattern: 'urllib\\.request\\.urlopen\\(',
      language: 'python',
      category: 'ssrf',
      cwe_id: 'CWE-918',
      risk_score: 8.0,
      confidence: 0.80,
      explanation: 'urllib.request.urlopen() with unvalidated URLs enables SSRF. Validate destination URLs against allowlists.'
    },
    {
      pattern: 'httpx\\.get\\(',
      language: 'python',
      category: 'ssrf',
      cwe_id: 'CWE-918',
      risk_score: 8.0,
      confidence: 0.80,
      explanation: 'httpx.get() with user-controlled URLs enables SSRF. Validate URLs and block private network access.'
    },

    // ========== Hardcoded Secrets Patterns ==========
    {
      pattern: 'api[_-]?key\\s*=\\s*[\'"][a-zA-Z0-9]{20,}[\'"]',
      language: 'any',
      category: 'hardcoded-secrets',
      cwe_id: 'CWE-798',
      risk_score: 8.5,
      confidence: 0.85,
      explanation: 'Hardcoded API keys in source code are security risks. Use environment variables or secret management systems (AWS Secrets Manager, Azure Key Vault).'
    },
    {
      pattern: 'api[_-]?secret\\s*=\\s*[\'"][a-zA-Z0-9]{20,}[\'"]',
      language: 'any',
      category: 'hardcoded-secrets',
      cwe_id: 'CWE-798',
      risk_score: 8.5,
      confidence: 0.85,
      explanation: 'Hardcoded API secrets expose credentials in version control. Store secrets in environment variables or dedicated vaults.'
    },
    {
      pattern: 'password\\s*=\\s*[\'"][^\'"]{6,}[\'"]',
      language: 'any',
      category: 'hardcoded-secrets',
      cwe_id: 'CWE-798',
      risk_score: 8.0,
      confidence: 0.75,
      explanation: 'Hardcoded passwords in source code are easily discovered. Use environment variables and secure configuration management.'
    },
    {
      pattern: 'token\\s*=\\s*[\'"][a-zA-Z0-9_-]{20,}[\'"]',
      language: 'any',
      category: 'hardcoded-secrets',
      cwe_id: 'CWE-798',
      risk_score: 8.0,
      confidence: 0.75,
      explanation: 'Hardcoded tokens in code expose authentication credentials. Use secret management systems and environment variables.'
    },
    {
      pattern: 'private[_-]?key\\s*=\\s*[\'"]',
      language: 'any',
      category: 'hardcoded-secrets',
      cwe_id: 'CWE-798',
      risk_score: 9.0,
      confidence: 0.90,
      explanation: 'Hardcoded private keys compromise cryptographic security. Store keys in secure vaults, never commit to version control.'
    },
    {
      pattern: 'secret[_-]?key\\s*=\\s*[\'"][a-zA-Z0-9]{16,}[\'"]',
      language: 'any',
      category: 'hardcoded-secrets',
      cwe_id: 'CWE-798',
      risk_score: 8.5,
      confidence: 0.85,
      explanation: 'Hardcoded secret keys in source expose cryptographic material. Use environment variables and secret rotation policies.'
    },
    {
      pattern: 'aws[_-]?access[_-]?key[_-]?id\\s*=\\s*[\'"]AKIA[a-zA-Z0-9]{16}[\'"]',
      language: 'any',
      category: 'hardcoded-secrets',
      cwe_id: 'CWE-798',
      risk_score: 9.0,
      confidence: 0.95,
      explanation: 'Hardcoded AWS access keys provide full AWS account access. Use IAM roles, EC2 instance profiles, or AWS Secrets Manager.'
    },
    {
      pattern: 'github[_-]?token\\s*=\\s*[\'"]gh[ps]_[a-zA-Z0-9]{36,}[\'"]',
      language: 'any',
      category: 'hardcoded-secrets',
      cwe_id: 'CWE-798',
      risk_score: 8.5,
      confidence: 0.95,
      explanation: 'Hardcoded GitHub tokens expose repository access. Use GitHub Actions secrets or environment variables, rotate tokens immediately.'
    },

    // ========== Deserialization Patterns ==========
    {
      pattern: 'pickle\\.loads\\(',
      language: 'python',
      category: 'deserialization',
      cwe_id: 'CWE-502',
      risk_score: 9.0,
      confidence: 0.95,
      explanation: 'Deserializing untrusted data with pickle allows arbitrary code execution. Use JSON for untrusted data.'
    },
    {
      pattern: 'pickle\\.load\\(',
      language: 'python',
      category: 'deserialization',
      cwe_id: 'CWE-502',
      risk_score: 9.0,
      confidence: 0.95,
      explanation: 'Loading pickled data from untrusted sources allows code execution. Never unpickle untrusted data.'
    },
    {
      pattern: 'yaml\\.unsafe_load\\(',
      language: 'python',
      category: 'deserialization',
      cwe_id: 'CWE-502',
      risk_score: 8.5,
      confidence: 0.95,
      explanation: 'yaml.unsafe_load() can execute arbitrary code. Use yaml.safe_load() for untrusted YAML.'
    }
  ];
}
