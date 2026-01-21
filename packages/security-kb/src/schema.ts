/**
 * Security Knowledge Base - Enhanced SQLite Schema
 * Phase 5: Intelligence Layer with CWE/OWASP/CVE relationships
 */

import { Database } from 'sql.js';

export interface SchemaOptions {
  enableIndexes?: boolean;
}

/**
 * Initialize the enhanced security knowledge base schema.
 * Includes CWE, CVE, OWASP tables with relationship mappings.
 */
export function initializeSchema(db: Database, options: SchemaOptions = { enableIndexes: true }): void {
  // Drop existing tables for clean migration
  db.exec(`
    DROP TABLE IF EXISTS cve_cwe_mapping;
    DROP TABLE IF EXISTS cwe_owasp_mapping;
    DROP TABLE IF EXISTS threat_patterns;
    DROP TABLE IF EXISTS cves;
    DROP TABLE IF EXISTS cwes;
    DROP TABLE IF EXISTS owasp_top10;
  `);

  // Core Tables
  db.exec(`
    -- CWE (Common Weakness Enumeration) Table
    CREATE TABLE IF NOT EXISTS cwes (
      cwe_id TEXT PRIMARY KEY,              -- e.g., 'CWE-79'
      name TEXT NOT NULL,                    -- e.g., 'Cross-site Scripting (XSS)'
      description TEXT NOT NULL,
      extended_description TEXT,
      severity TEXT,                         -- High, Medium, Low
      likelihood TEXT,                       -- High, Medium, Low
      mitigation_json TEXT,                  -- JSON array of mitigations
      related_cwes_json TEXT,                -- JSON array of related CWE IDs
      created_at INTEGER DEFAULT (strftime('%s', 'now'))
    );

    -- CVE (Common Vulnerabilities and Exposures) Table
    CREATE TABLE IF NOT EXISTS cves (
      cve_id TEXT PRIMARY KEY,              -- e.g., 'CVE-2023-12345'
      description TEXT NOT NULL,
      severity TEXT NOT NULL,                -- CRITICAL, HIGH, MEDIUM, LOW, NONE
      cvss_score REAL NOT NULL,              -- 0.0 - 10.0
      cvss_vector TEXT,                      -- CVSS vector string
      published_date TEXT NOT NULL,
      last_modified TEXT NOT NULL,
      affected_technologies_json TEXT,       -- JSON array of technologies
      references_json TEXT,                  -- JSON array of reference URLs
      cisa_known_exploited INTEGER DEFAULT 0, -- 0 or 1 (boolean)
      created_at INTEGER DEFAULT (strftime('%s', 'now'))
    );

    -- OWASP Top 10 Table
    CREATE TABLE IF NOT EXISTS owasp_top10 (
      category TEXT PRIMARY KEY,             -- e.g., 'A01'
      name TEXT NOT NULL,                    -- e.g., 'Broken Access Control'
      description TEXT NOT NULL,
      related_cwes_json TEXT,                -- JSON array of CWE IDs
      prevention_strategies_json TEXT,       -- JSON array of prevention steps
      year INTEGER DEFAULT 2025,
      created_at INTEGER DEFAULT (strftime('%s', 'now'))
    );

    -- CVE ↔ CWE Mapping Table
    CREATE TABLE IF NOT EXISTS cve_cwe_mapping (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id TEXT NOT NULL,
      cwe_id TEXT NOT NULL,
      confidence REAL DEFAULT 1.0,           -- 0.0 - 1.0 (mapping confidence)
      FOREIGN KEY (cve_id) REFERENCES cves(cve_id),
      FOREIGN KEY (cwe_id) REFERENCES cwes(cwe_id),
      UNIQUE(cve_id, cwe_id)
    );

    -- CWE ↔ OWASP Mapping Table
    CREATE TABLE IF NOT EXISTS cwe_owasp_mapping (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cwe_id TEXT NOT NULL,
      owasp_category TEXT NOT NULL,
      confidence REAL DEFAULT 1.0,           -- 0.0 - 1.0 (mapping confidence)
      source TEXT DEFAULT 'owasp_doc',       -- owasp_doc, inferred, manual
      FOREIGN KEY (cwe_id) REFERENCES cwes(cwe_id),
      FOREIGN KEY (owasp_category) REFERENCES owasp_top10(category),
      UNIQUE(cwe_id, owasp_category)
    );

    -- Threat Pattern Intelligence Table (Pattern → CWE)
    CREATE TABLE IF NOT EXISTS threat_patterns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pattern TEXT NOT NULL,                 -- e.g., 'eval(userInput)'
      language TEXT NOT NULL,                -- javascript, python, java, etc.
      category TEXT NOT NULL,                -- injection, xss, sqli, etc.
      cwe_id TEXT NOT NULL,
      risk_score REAL NOT NULL,              -- 0.0 - 10.0
      confidence REAL DEFAULT 1.0,
      explanation TEXT NOT NULL,
      FOREIGN KEY (cwe_id) REFERENCES cwes(cwe_id)
    );
  `);

  // Create Indexes (if enabled)
  if (options.enableIndexes) {
    db.exec(`
      -- Performance Indexes
      CREATE INDEX IF NOT EXISTS idx_cve_severity ON cves(severity);
      CREATE INDEX IF NOT EXISTS idx_cve_cvss_score ON cves(cvss_score DESC);
      CREATE INDEX IF NOT EXISTS idx_cve_cisa_kev ON cves(cisa_known_exploited);
      CREATE INDEX IF NOT EXISTS idx_cwe_severity ON cwes(severity);
      
      -- Mapping Indexes
      CREATE INDEX IF NOT EXISTS idx_cve_cwe_cve ON cve_cwe_mapping(cve_id);
      CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe ON cve_cwe_mapping(cwe_id);
      CREATE INDEX IF NOT EXISTS idx_cwe_owasp_cwe ON cwe_owasp_mapping(cwe_id);
      CREATE INDEX IF NOT EXISTS idx_cwe_owasp_owasp ON cwe_owasp_mapping(owasp_category);
      
      -- Threat Pattern Indexes
      CREATE INDEX IF NOT EXISTS idx_threat_pattern ON threat_patterns(pattern);
      CREATE INDEX IF NOT EXISTS idx_threat_language ON threat_patterns(language);
      CREATE INDEX IF NOT EXISTS idx_threat_category ON threat_patterns(category);
      CREATE INDEX IF NOT EXISTS idx_threat_cwe ON threat_patterns(cwe_id);
    `);
  }
}

/**
 * Validate schema integrity.
 */
export function validateSchema(db: Database): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  try {
    // Check required tables exist
    const tables = ['cwes', 'cves', 'owasp_top10', 'cve_cwe_mapping', 'cwe_owasp_mapping', 'threat_patterns'];
    const stmt = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?");
    
    for (const table of tables) {
      stmt.bind([table]);
      if (!stmt.step()) {
        errors.push(`Missing table: ${table}`);
      }
      stmt.reset();
    }
    stmt.free();

    // Check row counts
    const counts = db.exec('SELECT COUNT(*) as cwes FROM cwes')[0];
    if (counts && counts.values[0][0] === 0) {
      errors.push('CWE table is empty');
    }

  } catch (error) {
    errors.push(`Schema validation error: ${error}`);
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Get schema statistics.
 */
export function getSchemaStats(db: Database): Record<string, number> {
  const stats: Record<string, number> = {};

  const tables = ['cwes', 'cves', 'owasp_top10', 'cve_cwe_mapping', 'cwe_owasp_mapping', 'threat_patterns'];
  
  for (const table of tables) {
    try {
      const result = db.exec(`SELECT COUNT(*) as count FROM ${table}`);
      stats[table] = result[0]?.values[0][0] as number || 0;
    } catch {
      stats[table] = 0;
    }
  }

  return stats;
}
