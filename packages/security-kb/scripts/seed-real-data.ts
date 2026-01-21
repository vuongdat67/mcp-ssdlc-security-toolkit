/**
 * Enhanced Seed Script - Phase 4
 * 
 * Populates SQLite database with real vulnerability data:
 * - MITRE CWE v4.19 (16MB XML catalog)
 * - NIST NVD CVE 2.0 (2,959 vulnerabilities)
 * - OWASP Top 10 2025 (10 categories)
 */

import Database from 'better-sqlite3';
import { join } from 'path';
import { existsSync, readFileSync } from 'fs';
import { parseCWEXML } from '../src/parsers/cwe-parser';
import { parseCVEJSON } from '../src/parsers/cve-parser';
import { parseOWASPTop10 } from '../src/parsers/owasp-parser';

const DB_PATH = join(__dirname, '../data/security-kb.db');
const CWE_XML_PATH = join(__dirname, '../../../data/cwec/cwec_v4.19.xml');
const CVE_JSON_PATH = join(__dirname, '../../../data/nist/nvdcve-2.0-modified.json');
const OWASP_DOCS_PATH = join(__dirname, '../../../data/top10_owasp');

interface SeedOptions {
  maxCWEs?: number;
  maxCVEs?: number;
  includeOWASP?: boolean;
  dropExisting?: boolean;
}

function createTables(db: Database.Database) {
  console.log('\n📋 Creating database schema...');

  // CWE Table (enhanced)
  db.exec(`
    CREATE TABLE IF NOT EXISTS cwe (
      cwe_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      extended_description TEXT,
      severity TEXT,
      likelihood_of_exploit TEXT,
      abstraction TEXT,
      status TEXT,
      related_cwes TEXT,
      applicable_platforms TEXT,
      common_consequences TEXT,
      mitigations TEXT,
      detection_methods TEXT,
      observed_examples TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // CVE Table (enhanced)
  db.exec(`
    CREATE TABLE IF NOT EXISTS cve (
      cve_id TEXT PRIMARY KEY,
      description TEXT NOT NULL,
      severity TEXT NOT NULL,
      cvss_score REAL,
      cvss_vector TEXT,
      published_date TEXT,
      last_modified TEXT,
      cwe_ids TEXT,
      affected_technologies TEXT,
      references TEXT,
      cisa_known_exploited INTEGER DEFAULT 0,
      vuln_status TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // OWASP Top 10 Table (enhanced)
  db.exec(`
    CREATE TABLE IF NOT EXISTS owasp_top10 (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      year INTEGER NOT NULL,
      risk_factors TEXT,
      example_attack_scenarios TEXT,
      prevention_strategies TEXT,
      related_cwes TEXT,
      references TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(category, year)
    )
  `);

  // Create indexes for performance
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_cwe_severity ON cwe(severity);
    CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve(severity);
    CREATE INDEX IF NOT EXISTS idx_cve_cisa ON cve(cisa_known_exploited);
    CREATE INDEX IF NOT EXISTS idx_owasp_year ON owasp_top10(year);
  `);

  console.log('✅ Schema created successfully');
}

function seedCWEs(db: Database.Database, maxEntries?: number) {
  console.log('\n🔍 Seeding CWE data...');

  if (!existsSync(CWE_XML_PATH)) {
    console.error(`❌ CWE XML not found: ${CWE_XML_PATH}`);
    return;
  }

  console.log(`   Reading: ${CWE_XML_PATH}`);
  const xmlContent = readFileSync(CWE_XML_PATH, 'utf-8');
  
  console.log(`   Parsing CWE XML (${(xmlContent.length / 1024 / 1024).toFixed(2)} MB)...`);
  const cwes = parseCWEXML(xmlContent);

  const entriesToInsert = maxEntries ? cwes.slice(0, maxEntries) : cwes;

  const insertStmt = db.prepare(`
    INSERT OR REPLACE INTO cwe (
      cwe_id, name, description, extended_description, severity,
      likelihood_of_exploit, abstraction, status, related_cwes,
      applicable_platforms, common_consequences, mitigations,
      detection_methods, observed_examples
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertMany = db.transaction((entries: any[]) => {
    for (const cwe of entries) {
      insertStmt.run(
        cwe.cwe_id,
        cwe.name,
        cwe.description,
        cwe.extended_description || null,
        cwe.severity,
        cwe.likelihood_of_exploit || null,
        cwe.abstraction || null,
        cwe.status || null,
        cwe.related_cwes ? JSON.stringify(cwe.related_cwes) : null,
        cwe.applicable_platforms ? JSON.stringify(cwe.applicable_platforms) : null,
        cwe.common_consequences ? JSON.stringify(cwe.common_consequences) : null,
        cwe.mitigations ? JSON.stringify(cwe.mitigations) : null,
        cwe.detection_methods ? JSON.stringify(cwe.detection_methods) : null,
        cwe.observed_examples ? JSON.stringify(cwe.observed_examples) : null
      );
    }
  });

  console.log(`   Inserting ${entriesToInsert.length} CWE entries...`);
  insertMany(entriesToInsert);
  console.log(`✅ Seeded ${entriesToInsert.length} CWEs`);
}

function seedCVEs(db: Database.Database, maxEntries?: number) {
  console.log('\n🔍 Seeding CVE data...');

  if (!existsSync(CVE_JSON_PATH)) {
    console.error(`❌ CVE JSON not found: ${CVE_JSON_PATH}`);
    return;
  }

  console.log(`   Reading: ${CVE_JSON_PATH}`);
  const jsonContent = readFileSync(CVE_JSON_PATH, 'utf-8');
  
  console.log(`   Parsing CVE JSON (${(jsonContent.length / 1024 / 1024).toFixed(2)} MB)...`);
  const cves = parseCVEJSON(jsonContent);

  const entriesToInsert = maxEntries ? cves.slice(0, maxEntries) : cves;

  const insertStmt = db.prepare(`
    INSERT OR REPLACE INTO cve (
      cve_id, description, severity, cvss_score, cvss_vector,
      published_date, last_modified, cwe_ids, affected_technologies,
      references, cisa_known_exploited, vuln_status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertMany = db.transaction((entries: any[]) => {
    for (const cve of entries) {
      insertStmt.run(
        cve.cve_id,
        cve.description,
        cve.severity,
        cve.cvss_score || null,
        cve.cvss_vector || null,
        cve.published_date || null,
        cve.last_modified || null,
        cve.cwe_ids ? JSON.stringify(cve.cwe_ids) : null,
        cve.affected_technologies ? JSON.stringify(cve.affected_technologies) : null,
        cve.references ? JSON.stringify(cve.references) : null,
        cve.cisa_known_exploited ? 1 : 0,
        cve.vuln_status || null
      );
    }
  });

  console.log(`   Inserting ${entriesToInsert.length} CVE entries...`);
  insertMany(entriesToInsert);
  console.log(`✅ Seeded ${entriesToInsert.length} CVEs`);
}

function seedOWASP(db: Database.Database) {
  console.log('\n🔍 Seeding OWASP Top 10 2025...');

  if (!existsSync(OWASP_DOCS_PATH)) {
    console.error(`❌ OWASP docs not found: ${OWASP_DOCS_PATH}`);
    return;
  }

  console.log(`   Reading: ${OWASP_DOCS_PATH}`);
  const entries = parseOWASPTop10(OWASP_DOCS_PATH);

  const insertStmt = db.prepare(`
    INSERT OR REPLACE INTO owasp_top10 (
      category, name, description, year, risk_factors,
      example_attack_scenarios, prevention_strategies, related_cwes, references
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertMany = db.transaction((owaspEntries: any[]) => {
    for (const owasp of owaspEntries) {
      insertStmt.run(
        owasp.category,
        owasp.name,
        owasp.description,
        owasp.year,
        owasp.risk_factors ? JSON.stringify(owasp.risk_factors) : null,
        owasp.example_attack_scenarios ? JSON.stringify(owasp.example_attack_scenarios) : null,
        owasp.prevention_strategies ? JSON.stringify(owasp.prevention_strategies) : null,
        owasp.related_cwes ? JSON.stringify(owasp.related_cwes) : null,
        owasp.references ? JSON.stringify(owasp.references) : null
      );
    }
  });

  console.log(`   Inserting ${entries.length} OWASP entries...`);
  insertMany(entries);
  console.log(`✅ Seeded ${entries.length} OWASP Top 10 2025 entries`);
}

function printStats(db: Database.Database) {
  console.log('\n📊 Database Statistics:');
  
  const cweCount = db.prepare('SELECT COUNT(*) as count FROM cwe').get() as { count: number };
  const cveCount = db.prepare('SELECT COUNT(*) as count FROM cve').get() as { count: number };
  const owaspCount = db.prepare('SELECT COUNT(*) as count FROM owasp_top10').get() as { count: number };
  
  console.log(`   CWEs: ${cweCount.count}`);
  console.log(`   CVEs: ${cveCount.count}`);
  console.log(`   OWASP Top 10: ${owaspCount.count}`);
  
  // Show severity distribution
  const cveSeverity = db.prepare('SELECT severity, COUNT(*) as count FROM cve GROUP BY severity').all() as Array<{ severity: string; count: number }>;
  console.log('\n   CVE Severity Distribution:');
  cveSeverity.forEach(s => console.log(`     ${s.severity}: ${s.count}`));
  
  // Show CISA exploited count
  const cisaCount = db.prepare('SELECT COUNT(*) as count FROM cve WHERE cisa_known_exploited = 1').get() as { count: number };
  console.log(`\n   CISA Known Exploited: ${cisaCount.count}`);
}

export function seedDatabase(options: SeedOptions = {}) {
  console.log('🌱 MCP SSDLC Security Toolkit - Database Seeding (Phase 4)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL'); // Performance optimization

  try {
    if (options.dropExisting) {
      console.log('\n🗑️  Dropping existing tables...');
      db.exec('DROP TABLE IF EXISTS cwe');
      db.exec('DROP TABLE IF EXISTS cve');
      db.exec('DROP TABLE IF EXISTS owasp_top10');
    }

    createTables(db);

    const startTime = Date.now();

    seedCWEs(db, options.maxCWEs);
    seedCVEs(db, options.maxCVEs);
    
    if (options.includeOWASP !== false) {
      seedOWASP(db);
    }

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    
    printStats(db);

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`✅ Database seeding completed in ${duration}s`);
    console.log(`📁 Database: ${DB_PATH}`);

  } catch (error) {
    console.error('\n❌ Seeding failed:', error);
    throw error;
  } finally {
    db.close();
  }
}

// CLI execution
if (require.main === module) {
  const args = process.argv.slice(2);
  
  const options: SeedOptions = {
    maxCWEs: args.includes('--max-cwes') ? parseInt(args[args.indexOf('--max-cwes') + 1]) : undefined,
    maxCVEs: args.includes('--max-cves') ? parseInt(args[args.indexOf('--max-cves') + 1]) : undefined,
    includeOWASP: !args.includes('--no-owasp'),
    dropExisting: args.includes('--drop')
  };

  console.log('Options:', JSON.stringify(options, null, 2));
  seedDatabase(options);
}
