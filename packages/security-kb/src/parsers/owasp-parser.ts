/**
 * OWASP Top 10 2025 Parser
 * 
 * Parses OWASP Top 10 2025 markdown documentation
 * and normalizes it for SQLite storage.
 */

import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

export interface OWASPEntry {
  category: string; // A01, A02, etc.
  name: string;
  description: string;
  year: number;
  risk_factors?: {
    exploitability?: string;
    prevalence?: string;
    detectability?: string;
    technical_impact?: string;
  };
  example_attack_scenarios?: string[];
  prevention_strategies?: string[];
  related_cwes?: string[];
  references?: string[];
}

export function parseOWASPTop10(docsPath: string): OWASPEntry[] {
  console.log(`📖 Parsing OWASP Top 10 2025 from: ${docsPath}`);

  const entries: OWASPEntry[] = [];
  const files = readdirSync(docsPath).filter(f => f.match(/^A\d{2}_2025-.*\.md$/));

  for (const file of files) {
    try {
      const filePath = join(docsPath, file);
      const content = readFileSync(filePath, 'utf-8');

      // Extract category (A01, A02, etc.)
      const categoryMatch = file.match(/^(A\d{2})_2025/);
      if (!categoryMatch) continue;

      const category = categoryMatch[1];

      // Extract name from filename
      const nameMatch = file.match(/^A\d{2}_2025-(.+)\.md$/);
      const name = nameMatch ? nameMatch[1].replace(/_/g, ' ') : 'Unknown';

      // Extract description from markdown
      const description = extractDescription(content);

      // Extract CWEs
      const relatedCWEs = extractCWEs(content);

      // Extract prevention strategies
      const prevention = extractPrevention(content);

      // Extract example scenarios
      const examples = extractExampleScenarios(content);

      // Extract references
      const references = extractReferences(content);

      const entry: OWASPEntry = {
        category,
        name,
        description,
        year: 2025,
        related_cwes: relatedCWEs,
        prevention_strategies: prevention,
        example_attack_scenarios: examples,
        references
      };

      entries.push(entry);
    } catch (error) {
      console.error(`⚠️  Failed to parse ${file}:`, error);
    }
  }

  console.log(`✅ Parsed ${entries.length} OWASP Top 10 2025 entries`);
  return entries;
}

function extractDescription(content: string): string {
  // Extract first paragraph after title
  const lines = content.split('\n');
  let description = '';
  let inDescription = false;

  for (const line of lines) {
    // Skip title
    if (line.startsWith('# ')) continue;

    // Skip metadata
    if (line.trim().startsWith('**') || line.trim().startsWith('*')) {
      if (!inDescription) continue;
    }

    // First non-empty, non-title line starts description
    if (line.trim() && !inDescription) {
      inDescription = true;
    }

    if (inDescription) {
      description += line + ' ';
      
      // Stop at next heading or after ~300 chars
      if (line.startsWith('##') || description.length > 500) {
        break;
      }
    }
  }

  return description.trim().substring(0, 500) || 'No description available';
}

function extractCWEs(content: string): string[] | undefined {
  // Look for CWE references in markdown
  const cweRegex = /CWE-(\d+)/g;
  const matches = [...content.matchAll(cweRegex)];
  
  if (matches.length === 0) return undefined;

  const cwes = new Set(matches.map(m => `CWE-${m[1]}`));
  return Array.from(cwes).slice(0, 20); // Limit to 20
}

function extractPrevention(content: string): string[] | undefined {
  // Look for "How to Prevent" or "Prevention" section
  const preventionSection = extractSection(content, /##\s*(How to Prevent|Prevention)/i);
  if (!preventionSection) return undefined;

  // Extract bullet points
  const bullets = preventionSection
    .split('\n')
    .filter(line => line.trim().startsWith('-') || line.trim().startsWith('*'))
    .map(line => line.replace(/^[-*]\s*/, '').trim())
    .filter(line => line.length > 10)
    .slice(0, 10); // Limit to 10

  return bullets.length > 0 ? bullets : undefined;
}

function extractExampleScenarios(content: string): string[] | undefined {
  // Look for "Example Attack Scenarios" section
  const scenariosSection = extractSection(content, /##\s*Example Attack Scenarios/i);
  if (!scenariosSection) return undefined;

  // Extract scenario blocks (usually starts with "Scenario #")
  const scenarios: string[] = [];
  const lines = scenariosSection.split('\n');
  let currentScenario = '';

  for (const line of lines) {
    if (line.match(/Scenario\s*#?\d+/i)) {
      if (currentScenario) {
        scenarios.push(currentScenario.trim());
      }
      currentScenario = line.replace(/Scenario\s*#?\d+:?\s*/i, '');
    } else if (currentScenario && line.trim()) {
      currentScenario += ' ' + line.trim();
    }
  }

  if (currentScenario) {
    scenarios.push(currentScenario.trim());
  }

  return scenarios.length > 0 ? scenarios.slice(0, 5) : undefined;
}

function extractReferences(content: string): string[] | undefined {
  // Look for "References" section
  const referencesSection = extractSection(content, /##\s*References/i);
  if (!referencesSection) return undefined;

  // Extract URLs
  const urlRegex = /https?:\/\/[^\s\)]+/g;
  const matches = [...referencesSection.matchAll(urlRegex)];
  
  if (matches.length === 0) return undefined;

  const urls = new Set(matches.map(m => m[0]));
  return Array.from(urls).slice(0, 10); // Limit to 10
}

function extractSection(content: string, sectionRegex: RegExp): string | null {
  const lines = content.split('\n');
  let inSection = false;
  let sectionContent = '';

  for (const line of lines) {
    if (sectionRegex.test(line)) {
      inSection = true;
      continue;
    }

    if (inSection) {
      // Stop at next section (## heading)
      if (line.match(/^##\s+/)) {
        break;
      }
      sectionContent += line + '\n';
    }
  }

  return sectionContent.trim() || null;
}

// Export function for direct usage
export function parseOWASPTop10File(relativePath: string = '../../../data/top10_owasp'): OWASPEntry[] {
  const absolutePath = join(__dirname, relativePath);
  return parseOWASPTop10(absolutePath);
}
