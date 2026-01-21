/**
 * Domain Configuration Loader
 * 
 * Loads security domain definitions from JSON, YAML, and Markdown files.
 * Supports custom domains for specialized security contexts.
 */

import { readFileSync, readdirSync, existsSync } from 'fs';
import { join, extname, basename } from 'path';
import { z } from 'zod';

// ============================================================================
// Types
// ============================================================================

export interface ThreatPattern {
  regex: string;
  language: string;
  confidence: number;
  riskScore: number;
}

export interface Mitigation {
  phase: 'Architecture' | 'Design' | 'Implementation' | 'Testing' | 'Deployment';
  description: string;
  codeExample?: {
    language: string;
    insecure: string;
    secure: string;
  };
}

export interface Threat {
  id: string;
  name: string;
  description: string;
  cweIds: string[];
  owaspCategories: string[];
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  likelihood: 'HIGH' | 'MEDIUM' | 'LOW';
  patterns: ThreatPattern[];
  mitigations: Mitigation[];
}

export interface ThreatCategory {
  id: string;
  name: string;
  description: string;
  strideCategory: 'Spoofing' | 'Tampering' | 'Repudiation' | 'InformationDisclosure' | 'DenialOfService' | 'ElevationOfPrivilege';
  threats: Threat[];
}

export interface SecurityControl {
  id: string;
  name: string;
  description: string;
  category: 'Preventive' | 'Detective' | 'Corrective' | 'Compensating';
  implementation: string;
}

export interface TestGuideline {
  category: string;
  testCases: string[];
  tools: string[];
}

export interface SecurityDomain {
  id: string;
  name: string;
  version: string;
  description: string;
  tags: string[];
  languages: string[];
  frameworks: string[];
  complianceStandards: string[];
  threatCategories: ThreatCategory[];
  securityControls: SecurityControl[];
  testingGuidelines: TestGuideline[];
}

// ============================================================================
// Schema Validation
// ============================================================================

const ThreatPatternSchema = z.object({
  regex: z.string(),
  language: z.string(),
  confidence: z.number().min(0).max(100),
  riskScore: z.number().min(0).max(10),
});

// ThreatSchema for future use in strict validation
const _ThreatSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().optional().default(''),
  cweIds: z.array(z.string()).optional().default([]),
  owaspCategories: z.array(z.string()).optional().default([]),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).optional().default('MEDIUM'),
  likelihood: z.enum(['HIGH', 'MEDIUM', 'LOW']).optional().default('MEDIUM'),
  patterns: z.array(ThreatPatternSchema).optional().default([]),
  mitigations: z.array(z.any()).optional().default([]),
});

// Export for external use
export { _ThreatSchema as ThreatSchema };

const SecurityDomainSchema = z.object({
  id: z.string(),
  name: z.string(),
  version: z.string(),
  description: z.string().optional().default(''),
  tags: z.array(z.string()).optional().default([]),
  languages: z.array(z.string()).optional().default([]),
  frameworks: z.array(z.string()).optional().default([]),
  complianceStandards: z.array(z.string()).optional().default([]),
  threatCategories: z.array(z.any()).optional().default([]),
  securityControls: z.array(z.any()).optional().default([]),
  testingGuidelines: z.array(z.any()).optional().default([]),
});

// ============================================================================
// Parsers
// ============================================================================

/**
 * Parse JSON domain file
 */
function parseJSON(content: string): unknown {
  return JSON.parse(content);
}

/**
 * Parse YAML domain file
 * Simple YAML parser for common cases (no external dependency)
 */
function parseYAML(content: string): unknown {
  // Simple YAML to JSON conversion for basic structures
  // For production, use js-yaml library
  const lines = content.split('\n');
  const result: Record<string, unknown> = {};
  let currentArrayKey = '';
  let currentArray: unknown[] = [];
  let inArray = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Handle key-value pairs
    const kvMatch = trimmed.match(/^(\w+):\s*(.*)$/);
    if (kvMatch) {
      const [, key, value] = kvMatch;
      if (value && !value.startsWith('|')) {
        // Simple value
        let parsed: unknown = value;
        if (value === 'true') parsed = true;
        else if (value === 'false') parsed = false;
        else if (/^\d+$/.test(value)) parsed = parseInt(value, 10);
        else if (/^\d+\.\d+$/.test(value)) parsed = parseFloat(value);
        else if (value.startsWith('"') && value.endsWith('"')) parsed = value.slice(1, -1);
        else if (value.startsWith("'") && value.endsWith("'")) parsed = value.slice(1, -1);
        result[key] = parsed;
        inArray = false;
      } else {
        currentArrayKey = key;
        result[key] = [];
        inArray = true;
        currentArray = result[key] as unknown[];
      }
    } else if (trimmed.startsWith('- ') && inArray) {
      currentArray.push(trimmed.slice(2));
    }
  }

  // Use currentArrayKey to avoid unused warning
  if (currentArrayKey && result[currentArrayKey]) {
    // Array was populated
  }

  return result;
}

/**
 * Parse Markdown domain file
 * Extracts structured data from markdown format
 */
function parseMarkdown(content: string): unknown {
  const result: Record<string, unknown> = {
    id: '',
    name: '',
    version: '1.0.0',
    description: '',
    tags: [],
    languages: [],
    frameworks: [],
    complianceStandards: [],
    threatCategories: [],
    securityControls: [],
    testingGuidelines: [],
  };

  // Extract ID from header or metadata
  const idMatch = content.match(/\*\*ID:\*\*\s*(\S+)/);
  if (idMatch) result.id = idMatch[1];

  // Extract title
  const titleMatch = content.match(/^#\s+(.+)/m);
  if (titleMatch) result.name = titleMatch[1].replace(/Security Domain$/, '').trim();

  // Extract version
  const versionMatch = content.match(/\*\*Version:\*\*\s*(\S+)/);
  if (versionMatch) result.version = versionMatch[1];

  // Extract description from Overview section
  const overviewMatch = content.match(/## Overview\s*\n\n([\s\S]*?)(?=\n##|\n\*\*|$)/);
  if (overviewMatch) result.description = overviewMatch[1].trim();

  // Extract metadata table
  const metadataSection = content.match(/## Metadata[\s\S]*?\|[\s\S]*?\|([\s\S]*?)(?=\n---|\n##|$)/);
  if (metadataSection) {
    const langMatch = metadataSection[1].match(/Languages[^|]*\|\s*([^|]+)/i);
    if (langMatch) {
      result.languages = langMatch[1].split(',').map(s => s.trim()).filter(Boolean);
    }
  }

  return result;
}

// ============================================================================
// Domain Loader
// ============================================================================

export class DomainLoader {
  private domainsPath: string;
  private domains: Map<string, SecurityDomain> = new Map();

  constructor(domainsPath: string) {
    this.domainsPath = domainsPath;
  }

  /**
   * Load all domains from the configured directory
   */
  async loadAll(): Promise<void> {
    if (!existsSync(this.domainsPath)) {
      console.warn(`[DomainLoader] Domains path not found: ${this.domainsPath}`);
      return;
    }

    const files = readdirSync(this.domainsPath);
    
    for (const file of files) {
      const ext = extname(file).toLowerCase();
      if (['.json', '.yaml', '.yml', '.md'].includes(ext)) {
        try {
          const domain = await this.loadFile(join(this.domainsPath, file));
          if (domain) {
            this.domains.set(domain.id, domain);
            // Domain loaded successfully
          }
        } catch (error) {
          console.error(`[DomainLoader] Failed to load ${file}:`, error);
        }
      }
    }

    // Domains loading complete
  }

  /**
   * Load a single domain file
   */
  async loadFile(filePath: string): Promise<SecurityDomain | null> {
    const content = readFileSync(filePath, 'utf-8');
    const ext = extname(filePath).toLowerCase();
    const fileName = basename(filePath, ext);

    let rawData: unknown;

    switch (ext) {
      case '.json':
        rawData = parseJSON(content);
        break;
      case '.yaml':
      case '.yml':
        rawData = parseYAML(content);
        break;
      case '.md':
        rawData = parseMarkdown(content);
        break;
      default:
        throw new Error(`Unsupported file extension: ${ext}`);
    }

    // Validate and normalize
    const validated = SecurityDomainSchema.parse(rawData);
    
    // Use filename as ID if not provided
    if (!validated.id) {
      validated.id = fileName;
    }

    return validated as SecurityDomain;
  }

  /**
   * Get a domain by ID
   */
  getDomain(id: string): SecurityDomain | undefined {
    return this.domains.get(id);
  }

  /**
   * Get all loaded domains
   */
  getAllDomains(): SecurityDomain[] {
    return Array.from(this.domains.values());
  }

  /**
   * Get domains by language
   */
  getDomainsByLanguage(language: string): SecurityDomain[] {
    const normalized = language.toLowerCase();
    return this.getAllDomains().filter(d => 
      d.languages.some(l => l.toLowerCase() === normalized)
    );
  }

  /**
   * Get all threat patterns from a domain
   */
  getThreatPatterns(domainId: string, language?: string): ThreatPattern[] {
    const domain = this.getDomain(domainId);
    if (!domain) return [];

    const patterns: ThreatPattern[] = [];

    for (const category of domain.threatCategories) {
      for (const threat of category.threats) {
        for (const pattern of threat.patterns) {
          if (!language || pattern.language === language || pattern.language === 'any') {
            patterns.push(pattern);
          }
        }
      }
    }

    return patterns;
  }

  /**
   * Get statistics about loaded domains
   */
  getStats(): Record<string, number> {
    const stats: Record<string, number> = {
      totalDomains: this.domains.size,
      totalCategories: 0,
      totalThreats: 0,
      totalPatterns: 0,
      totalControls: 0,
    };

    for (const domain of this.domains.values()) {
      stats.totalCategories += domain.threatCategories.length;
      stats.totalControls += domain.securityControls.length;
      
      for (const category of domain.threatCategories) {
        stats.totalThreats += category.threats.length;
        for (const threat of category.threats) {
          stats.totalPatterns += threat.patterns.length;
        }
      }
    }

    return stats;
  }
}

// ============================================================================
// Singleton instance
// ============================================================================

let domainLoaderInstance: DomainLoader | null = null;

export function getDomainLoader(domainsPath?: string): DomainLoader {
  if (!domainLoaderInstance) {
    const path = domainsPath || join(process.cwd(), 'config', 'domains');
    domainLoaderInstance = new DomainLoader(path);
  }
  return domainLoaderInstance;
}

export async function initializeDomains(domainsPath?: string): Promise<DomainLoader> {
  const loader = getDomainLoader(domainsPath);
  await loader.loadAll();
  return loader;
}
