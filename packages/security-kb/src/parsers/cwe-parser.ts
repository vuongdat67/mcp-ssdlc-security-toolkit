/**
 * CWE XML Parser
 * 
 * Parses CWE (Common Weakness Enumeration) XML data from MITRE
 * and normalizes it for SQLite storage.
 */

import { XMLParser } from 'fast-xml-parser';
import { readFileSync } from 'fs';
import { join } from 'path';

export interface CWEEntry {
  cwe_id: string;
  name: string;
  description: string;
  extended_description?: string;
  likelihood_of_exploit?: string;
  severity?: string;
  abstraction?: string;
  status?: string;
  related_cwes?: string[]; // Parent/child relationships
  applicable_platforms?: string[];
  common_consequences?: Array<{
    scope: string;
    impact: string;
    note?: string;
  }>;
  mitigations?: Array<{
    phase: string;
    description: string;
    effectiveness?: string;
  }>;
  detection_methods?: Array<{
    method: string;
    description?: string;
    effectiveness?: string;
  }>;
  observed_examples?: Array<{
    reference: string;
    description: string;
    link?: string;
  }>;
}

export function parseCWEXML(xmlPath: string): CWEEntry[] {
  console.log(`📖 Parsing CWE XML from: ${xmlPath}`);

  const xmlContent = readFileSync(xmlPath, 'utf-8');

  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    textNodeName: '#text',
    parseAttributeValue: true,
    trimValues: true,
    ignoreDeclaration: true,
    ignorePiTags: true
  });

  const result = parser.parse(xmlContent);
  const weaknesses = result.Weakness_Catalog?.Weaknesses?.Weakness;

  if (!weaknesses) {
    throw new Error('No weaknesses found in XML');
  }

  const weaknessArray = Array.isArray(weaknesses) ? weaknesses : [weaknesses];
  const entries: CWEEntry[] = [];

  for (const weakness of weaknessArray) {
    try {
      const entry: CWEEntry = {
        cwe_id: `CWE-${weakness['@_ID']}`,
        name: weakness['@_Name'] || '',
        description: weakness.Description || '',
        extended_description: weakness.Extended_Description || undefined,
        likelihood_of_exploit: weakness.Likelihood_Of_Exploit || undefined,
        severity: inferSeverity(weakness),
        abstraction: weakness['@_Abstraction'] || undefined,
        status: weakness['@_Status'] || undefined,
        related_cwes: extractRelatedCWEs(weakness.Related_Weaknesses),
        applicable_platforms: extractApplicablePlatforms(weakness.Applicable_Platforms),
        common_consequences: extractConsequences(weakness.Common_Consequences),
        mitigations: extractMitigations(weakness.Potential_Mitigations),
        detection_methods: extractDetectionMethods(weakness.Detection_Methods),
        observed_examples: extractObservedExamples(weakness.Observed_Examples)
      };

      entries.push(entry);
    } catch (error) {
      console.error(`⚠️  Failed to parse CWE-${weakness['@_ID']}:`, error);
    }
  }

  console.log(`✅ Parsed ${entries.length} CWE entries`);
  return entries;
}

function inferSeverity(weakness: any): string {
  // Infer severity from likelihood and consequences
  const likelihood = weakness.Likelihood_Of_Exploit?.toLowerCase();
  const consequences = weakness.Common_Consequences?.Consequence;

  if (!consequences) return 'Unknown';

  const consequenceArray = Array.isArray(consequences) ? consequences : [consequences];
  const hasHighImpact = consequenceArray.some((c: any) => 
    c.Impact && (
      c.Impact.includes('Execute Unauthorized Code') ||
      c.Impact.includes('Gain Privileges') ||
      c.Impact.includes('Bypass Protection Mechanism')
    )
  );

  if (likelihood === 'high' || hasHighImpact) return 'High';
  if (likelihood === 'medium') return 'Medium';
  if (likelihood === 'low') return 'Low';

  return 'Medium'; // Default
}

function extractRelatedCWEs(relatedWeaknesses: any): string[] | undefined {
  if (!relatedWeaknesses?.Related_Weakness) return undefined;

  const related = Array.isArray(relatedWeaknesses.Related_Weakness)
    ? relatedWeaknesses.Related_Weakness
    : [relatedWeaknesses.Related_Weakness];

  return related
    .map((r: any) => `CWE-${r['@_CWE_ID']}`)
    .filter(Boolean);
}

function extractApplicablePlatforms(platforms: any): string[] | undefined {
  if (!platforms) return undefined;

  const result: string[] = [];

  // Languages
  if (platforms.Language) {
    const langs = Array.isArray(platforms.Language) ? platforms.Language : [platforms.Language];
    result.push(...langs.map((l: any) => l['@_Name'] || l['@_Class']));
  }

  // Technologies
  if (platforms.Technology) {
    const techs = Array.isArray(platforms.Technology) ? platforms.Technology : [platforms.Technology];
    result.push(...techs.map((t: any) => t['@_Name'] || t['@_Class']));
  }

  return result.length > 0 ? result.filter(Boolean) : undefined;
}

function extractConsequences(consequences: any): CWEEntry['common_consequences'] | undefined {
  if (!consequences?.Consequence) return undefined;

  const conseqArray = Array.isArray(consequences.Consequence)
    ? consequences.Consequence
    : [consequences.Consequence];

  return conseqArray.map((c: any) => ({
    scope: c.Scope || 'Unknown',
    impact: c.Impact || 'Unknown',
    note: c.Note || undefined
  }));
}

function extractMitigations(mitigations: any): CWEEntry['mitigations'] | undefined {
  if (!mitigations?.Mitigation) return undefined;

  const mitigationArray = Array.isArray(mitigations.Mitigation)
    ? mitigations.Mitigation
    : [mitigations.Mitigation];

  return mitigationArray.map((m: any) => ({
    phase: m.Phase || 'Unknown',
    description: m.Description || '',
    effectiveness: m.Effectiveness || undefined
  }));
}

function extractDetectionMethods(methods: any): CWEEntry['detection_methods'] | undefined {
  if (!methods?.Detection_Method) return undefined;

  const methodArray = Array.isArray(methods.Detection_Method)
    ? methods.Detection_Method
    : [methods.Detection_Method];

  return methodArray.map((m: any) => ({
    method: m.Method || 'Unknown',
    description: m.Description || undefined,
    effectiveness: m.Effectiveness || undefined
  }));
}

function extractObservedExamples(examples: any): CWEEntry['observed_examples'] | undefined {
  if (!examples?.Observed_Example) return undefined;

  const exampleArray = Array.isArray(examples.Observed_Example)
    ? examples.Observed_Example
    : [examples.Observed_Example];

  return exampleArray.map((e: any) => ({
    reference: e.Reference || '',
    description: e.Description || '',
    link: e.Link || undefined
  })).slice(0, 5); // Limit to 5 examples
}

// Export function for direct usage
export function parseCWEFile(relativePath: string = '../../../data/cwec/cwec_v4.19.xml'): CWEEntry[] {
  const absolutePath = join(__dirname, relativePath);
  return parseCWEXML(absolutePath);
}
