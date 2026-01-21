/**
 * Security Knowledge Base
 * Phase 5: Enhanced intelligence layer with CWE/OWASP/CVE relationships
 */

import initSqlJs, { Database } from "sql.js";
import { readFileSync, existsSync, writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { initializeSchema, validateSchema, getSchemaStats } from "./schema";
import { SecurityIntelligence, ThreatExplanation, QueryOptions } from "./intelligence";
import { seedDatabase, SeedOptions, SeedResult } from "./seed";
import { SecurityReviewEngine, SecurityReviewResult } from "./security-review";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Re-export types
export * from "./intelligence";
export * from "./schema";
export * from "./seed";
export * from "./security-review";
export * from "./remediation-schema";
export * from "./ai-explainer";
export * from "./severity-normalizer";
export * from "./report-generator";

// Legacy types for backward compatibility
export interface CVEEntry {
  cve_id: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cvss_score: number;
  published_date: string;
  affected_technology: string;
  mitigation: string;
}

export interface CWEEntry {
  cwe_id: string;
  name: string;
  description: string;
  consequences: string;
  mitigation: string;
  examples: string;
}

export interface OWASPEntry {
  rank: number;
  category: string;
  description: string;
  examples: string[];
  mitigations: string[];
  cwe_mappings: string[];
}

export class SecurityKnowledgeBase {
  private db: Database | null = null;
  private dbPath: string;
  private initialized: boolean = false;
  private intelligence: SecurityIntelligence | null = null;
  private reviewEngine: SecurityReviewEngine | null = null;

  constructor(dbPath?: string) {
    this.dbPath = dbPath || join(__dirname, "../data/security.db");
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;

    const SQL = await initSqlJs();
    
    if (existsSync(this.dbPath)) {
      const buffer = readFileSync(this.dbPath);
      this.db = new SQL.Database(buffer);
      console.log(`[SecurityKB] Loaded existing database from ${this.dbPath}`);
    } else {
      this.db = new SQL.Database();
      mkdirSync(dirname(this.dbPath), { recursive: true });
      console.log(`[SecurityKB] Created new database at ${this.dbPath}`);
      
      // Initialize schema for new database
      initializeSchema(this.db, { enableIndexes: true });
    }
    
    this.intelligence = new SecurityIntelligence(this.db);
    this.reviewEngine = new SecurityReviewEngine(this.db);
    this.initialized = true;
  }

  private ensureInitialized(): Database {
    if (!this.db) {
      throw new Error("SecurityKnowledgeBase not initialized. Call initialize() first.");
    }
    return this.db;
  }

  /**
   * Seed the database with real security data.
   */
  async seed(options?: SeedOptions): Promise<SeedResult> {
    const db = this.ensureInitialized();
    return await seedDatabase(db, options);
  }

  /**
   * Save the database to disk.
   */
  save(): void {
    const db = this.ensureInitialized();
    const data = db.export();
    writeFileSync(this.dbPath, data);
    console.log(`[SecurityKB] Database saved to ${this.dbPath}`);
  }

  /**
   * Validate schema integrity.
   */
  validateSchema(): { valid: boolean; errors: string[] } {
    const db = this.ensureInitialized();
    return validateSchema(db);
  }

  /**
   * Get database statistics.
   */
  getStats(): Record<string, number> {
    const db = this.ensureInitialized();
    if (this.intelligence) {
      return this.intelligence.getStatistics();
    }
    return getSchemaStats(db);
  }

  // -------------------------------------------------------------------------
  // Intelligence Layer API
  // -------------------------------------------------------------------------

  /**
   * Explain a threat pattern with full reasoning chain.
   */
  explainThreat(pattern: string, language: string): ThreatExplanation | null {
    if (!this.intelligence) {
      throw new Error("Intelligence layer not initialized");
    }
    return this.intelligence.explainThreat(pattern, language);
  }

  /**
   * Get CWE details.
   */
  getCWE(cweId: string) {
    if (!this.intelligence) {
      throw new Error("Intelligence layer not initialized");
    }
    return this.intelligence.getCWE(cweId);
  }

  /**
   * Query CVEs by CWE.
   */
  queryCVEsByCWE(cweId: string, options?: QueryOptions) {
    if (!this.intelligence) {
      throw new Error("Intelligence layer not initialized");
    }
    return this.intelligence.queryCVEsByCWE(cweId, options);
  }

  /**
   * Get OWASP category by CWE.
   */
  getOWASPByCWE(cweId: string) {
    if (!this.intelligence) {
      throw new Error("Intelligence layer not initialized");
    }
    return this.intelligence.getOWASPByCWE(cweId);
  }

  /**
   * Calculate risk score for a CWE.
   */
  calculateRiskScore(cweId: string): number {
    if (!this.intelligence) {
      throw new Error("Intelligence layer not initialized");
    }
    return this.intelligence.calculateRiskScore(cweId);
  }

  /**
   * Review code for security vulnerabilities.
   * Phase 6A: AI Security Review Engine
   * 
   * This is a deterministic scanner that:
   * - Matches patterns against threat_patterns KB
   * - Provides CWE/OWASP/CVE evidence
   * - Includes Blue Team context (CISA KEV, urgency)
   * - Offers remediation guidance
   * - Explains confidence scoring
   * 
   * Does NOT use LLM reasoning or invent vulnerabilities.
   */
  async reviewCode(language: string, code: string): Promise<SecurityReviewResult> {
    if (!this.reviewEngine) {
      throw new Error("Review engine not initialized");
    }
    return this.reviewEngine.reviewCode(language, code);
  }

  // -------------------------------------------------------------------------
  // Legacy Methods (for backward compatibility)
  // -------------------------------------------------------------------------

  queryCVEs(technology: string, limit: number = 10): CVEEntry[] {
    const db = this.ensureInitialized();
    // Legacy method - kept for compatibility
    const stmt = db.prepare("SELECT * FROM cves WHERE affected_technologies_json LIKE ? ORDER BY cvss_score DESC LIMIT ?");
    stmt.bind([`%${technology}%`, limit]);
    
    const results: CVEEntry[] = [];
    while (stmt.step()) {
      const row = stmt.getAsObject() as any;
      results.push({
        cve_id: row.cve_id,
        description: row.description,
        severity: row.severity,
        cvss_score: row.cvss_score,
        published_date: row.published_date,
        affected_technology: technology,
        mitigation: ''
      });
    }
    stmt.free();
    return results;
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
      this.intelligence = null;
      this.initialized = false;
    }
  }
}

export async function createSecurityKB(dbPath?: string): Promise<SecurityKnowledgeBase> {
  const kb = new SecurityKnowledgeBase(dbPath);
  await kb.initialize();
  return kb;
}
