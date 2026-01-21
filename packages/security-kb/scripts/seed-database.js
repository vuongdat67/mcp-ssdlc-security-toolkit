#!/usr/bin/env node

/**
 * Seed script to populate the security knowledge base
 */

import initSqlJs from "sql.js";
import { writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const dbPath = join(__dirname, "../data/security.db");

// Ensure data directory exists
mkdirSync(dirname(dbPath), { recursive: true });

console.log("🌱 Seeding security knowledge base...\n");

const SQL = await initSqlJs();
const db = new SQL.Database();

console.log("Creating tables...");
db.exec(`
  CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL NOT NULL,
    published_date TEXT NOT NULL,
    affected_technology TEXT NOT NULL,
    mitigation TEXT
  );

  CREATE TABLE IF NOT EXISTS cwes (
    cwe_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    consequences TEXT,
    mitigation TEXT,
    examples TEXT
  );

  CREATE TABLE IF NOT EXISTS owasp_top10 (
    rank INTEGER PRIMARY KEY,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    examples TEXT NOT NULL,
    mitigations TEXT NOT NULL,
    cwe_mappings TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS secure_patterns (
    id TEXT PRIMARY KEY,
    language TEXT NOT NULL,
    category TEXT NOT NULL,
    pattern_name TEXT NOT NULL,
    description TEXT NOT NULL,
    code_example TEXT NOT NULL,
    security_notes TEXT NOT NULL
  );
`);

// Seed OWASP Top 10 (2021)
console.log("Seeding OWASP Top 10...");
const owaspData = [
  {
    rank: 1,
    category: "A01:2021-Broken Access Control",
    description: "Failures related to enforcing access control and authorization",
    examples: JSON.stringify(["IDOR", "Elevation of privilege", "Metadata manipulation", "Force browsing"]),
    mitigations: JSON.stringify([
      "Deny by default access",
      "Implement access control checks on every request",
      "Log access control failures",
      "Rate limit API and controller access"
    ]),
    cwe_mappings: JSON.stringify(["CWE-200", "CWE-201", "CWE-352"])
  },
  {
    rank: 2,
    category: "A02:2021-Cryptographic Failures",
    description: "Failures related to cryptography which often leads to sensitive data exposure",
    examples: JSON.stringify(["Weak encryption", "Hardcoded keys", "Insecure protocols", "Missing encryption"]),
    mitigations: JSON.stringify([
      "Classify data and apply appropriate encryption",
      "Use strong encryption algorithms (AES-256, RSA-2048+)",
      "Encrypt data in transit (TLS 1.2+)",
      "Store passwords with strong adaptive hashing (bcrypt, argon2)"
    ]),
    cwe_mappings: JSON.stringify(["CWE-259", "CWE-327", "CWE-331"])
  },
  {
    rank: 3,
    category: "A03:2021-Injection",
    description: "Injection flaws such as SQL, NoSQL, OS, and LDAP injection",
    examples: JSON.stringify(["SQL injection", "NoSQL injection", "OS command injection", "LDAP injection"]),
    mitigations: JSON.stringify([
      "Use parameterized queries",
      "Validate and sanitize all inputs",
      "Use ORM frameworks",
      "Escape special characters"
    ]),
    cwe_mappings: JSON.stringify(["CWE-79", "CWE-89", "CWE-73"])
  },
  {
    rank: 7,
    category: "A07:2021-Identification and Authentication Failures",
    description: "Failures related to user identity, authentication, and session management",
    examples: JSON.stringify(["Credential stuffing", "Brute force", "Weak passwords", "Session fixation"]),
    mitigations: JSON.stringify([
      "Implement multi-factor authentication",
      "Do not ship with default credentials",
      "Implement weak password checks",
      "Rate limit authentication attempts"
    ]),
    cwe_mappings: JSON.stringify(["CWE-297", "CWE-287", "CWE-384"])
  }
];

owaspData.forEach(entry => {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO owasp_top10 (rank, category, description, examples, mitigations, cwe_mappings)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  stmt.run([entry.rank, entry.category, entry.description, entry.examples, entry.mitigations, entry.cwe_mappings]);
  stmt.free();
});

console.log(`✓ Seeded ${owaspData.length} OWASP entries`);

// Seed sample CVEs
console.log("Seeding CVE data...");
const cveData = [
  {
    cve_id: "CVE-2023-XXXX",
    description: "JWT algorithm confusion vulnerability allowing authentication bypass",
    severity: "HIGH",
    cvss_score: 8.1,
    published_date: "2023-06-15",
    affected_technology: "JWT",
    mitigation: "Validate algorithm field, use RS256 instead of HS256, verify signature properly"
  },
  {
    cve_id: "CVE-2023-YYYY",
    description: "SQL injection in user authentication endpoint",
    severity: "CRITICAL",
    cvss_score: 9.8,
    published_date: "2023-08-22",
    affected_technology: "PostgreSQL",
    mitigation: "Use parameterized queries, implement input validation, apply principle of least privilege"
  },
  {
    cve_id: "CVE-2023-ZZZZ",
    description: "Server-Side Request Forgery (SSRF) in file upload functionality",
    severity: "HIGH",
    cvss_score: 7.5,
    published_date: "2023-09-10",
    affected_technology: "File Upload",
    mitigation: "Validate URLs, whitelist allowed domains, use network segmentation"
  }
];

cveData.forEach(entry => {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO cves (cve_id, description, severity, cvss_score, published_date, affected_technology, mitigation)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run([entry.cve_id, entry.description, entry.severity, entry.cvss_score, entry.published_date, entry.affected_technology, entry.mitigation]);
  stmt.free();
});

console.log(`✓ Seeded ${cveData.length} CVE entries`);

// Seed CWE data
console.log("Seeding CWE data...");
const cweData = [
  {
    cwe_id: "CWE-287",
    name: "Improper Authentication",
    description: "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct",
    consequences: "Authentication bypass, unauthorized access",
    mitigation: "Use strong authentication mechanisms, implement MFA, validate credentials properly",
    examples: "Missing authentication checks, weak password requirements"
  },
  {
    cwe_id: "CWE-89",
    name: "SQL Injection",
    description: "The software constructs SQL statements from user input without proper neutralization",
    consequences: "Data breach, data manipulation, authentication bypass",
    mitigation: "Use parameterized queries, ORM frameworks, input validation",
    examples: "Unescaped user input in SQL queries"
  },
  {
    cwe_id: "CWE-79",
    name: "Cross-site Scripting (XSS)",
    description: "The software does not neutralize or incorrectly neutralizes user input before placement in output",
    consequences: "Session hijacking, credential theft, malicious content injection",
    mitigation: "Encode output, use Content Security Policy, validate and sanitize input",
    examples: "Reflected XSS, stored XSS, DOM-based XSS"
  }
];

cweData.forEach(entry => {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO cwes (cwe_id, name, description, consequences, mitigation, examples)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  stmt.run([entry.cwe_id, entry.name, entry.description, entry.consequences, entry.mitigation, entry.examples]);
  stmt.free();
});

console.log(`✓ Seeded ${cweData.length} CWE entries`);

// Seed secure coding patterns
console.log("Seeding secure patterns...");
const patternsData = [
  {
    id: "python-auth-001",
    language: "python",
    category: "authentication",
    pattern_name: "Secure Password Hashing",
    description: "Use bcrypt for secure password storage",
    code_example: `import bcrypt

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(
        password.encode('utf-8'),
        hashed.encode('utf-8')
    )`,
    security_notes: JSON.stringify([
      "Use bcrypt with minimum 12 rounds",
      "Never store passwords in plain text",
      "Use constant-time comparison to prevent timing attacks",
      "Consider using argon2 for even stronger security"
    ])
  },
  {
    id: "javascript-injection-001",
    language: "javascript",
    category: "input-validation",
    pattern_name: "SQL Injection Prevention",
    description: "Use parameterized queries to prevent SQL injection",
    code_example: `// Good: Parameterized query
const getUserById = async (db, userId) => {
  const query = 'SELECT * FROM users WHERE id = $1';
  const result = await db.query(query, [userId]);
  return result.rows[0];
};

// Bad: String concatenation
// const query = 'SELECT * FROM users WHERE id = ' + userId;`,
    security_notes: JSON.stringify([
      "Always use parameterized queries",
      "Never concatenate user input into SQL",
      "Use ORM frameworks (Sequelize, TypeORM)",
      "Apply principle of least privilege for DB users"
    ])
  },
  {
    id: "python-crypto-001",
    language: "python",
    category: "cryptography",
    pattern_name: "AES Encryption",
    description: "Secure AES-256-GCM encryption implementation",
    code_example: `from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import os

def encrypt_data(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt data using AES-256-GCM"""
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    aesgcm = AESGCM(key)  # key must be 32 bytes for AES-256
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def decrypt_data(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt data using AES-256-GCM"""
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext`,
    security_notes: JSON.stringify([
      "Use AES-256 with GCM mode for authenticated encryption",
      "Generate random nonce for each encryption",
      "Never reuse nonce with same key",
      "Store nonce alongside ciphertext",
      "Use key derivation function (PBKDF2/Argon2) for password-based keys"
    ])
  }
];

patternsData.forEach(entry => {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO secure_patterns (id, language, category, pattern_name, description, code_example, security_notes)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run([entry.id, entry.language, entry.category, entry.pattern_name, entry.description, entry.code_example, entry.security_notes]);
  stmt.free();
});

console.log(`✓ Seeded ${patternsData.length} secure patterns`);

// Save database to file
const data = db.export();
writeFileSync(dbPath, Buffer.from(data));

db.close();

console.log("\n✨ Database seeded successfully!");
console.log(`📍 Location: ${dbPath}`);
