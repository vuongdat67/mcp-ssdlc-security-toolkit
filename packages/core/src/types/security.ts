/**
 * Security-related types and constants
 */

import { z } from "zod";

/**
 * OWASP Top 10 2021 categories
 */
export enum OWASPCategory {
  A01_BrokenAccessControl = "A01:2021",
  A02_CryptographicFailures = "A02:2021",
  A03_Injection = "A03:2021",
  A04_InsecureDesign = "A04:2021",
  A05_SecurityMisconfiguration = "A05:2021",
  A06_VulnerableComponents = "A06:2021",
  A07_IdentificationFailures = "A07:2021",
  A08_DataIntegrityFailures = "A08:2021",
  A09_SecurityLoggingFailures = "A09:2021",
  A10_ServerSideRequestForgery = "A10:2021",
}

/**
 * CVE (Common Vulnerabilities and Exposures) entry
 */
export const CVESchema = z.object({
  cve_id: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
  description: z.string(),
  cvss_score: z.number().min(0).max(10),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]),
  published_date: z.string(),
  technology: z.string(),
  exploitability: z.enum(["PROVEN", "PROOF_OF_CONCEPT", "FUNCTIONAL", "UNPROVEN"]).optional(),
  references: z.array(z.string()).optional(),
});

export type CVE = z.infer<typeof CVESchema>;

/**
 * CWE (Common Weakness Enumeration) entry
 */
export const CWESchema = z.object({
  cwe_id: z.string().regex(/^CWE-\d+$/),
  name: z.string(),
  description: z.string(),
  extended_description: z.string().optional(),
  mitigation: z.string(),
  examples: z.array(z.string()).optional(),
});

export type CWE = z.infer<typeof CWESchema>;

/**
 * Secure coding pattern
 */
export const SecurePatternSchema = z.object({
  id: z.string(),
  name: z.string(),
  language: z.string(),
  category: z.enum([
    "authentication",
    "authorization",
    "cryptography",
    "input_validation",
    "output_encoding",
    "session_management",
    "file_handling",
    "database",
  ]),
  description: z.string(),
  code_template: z.string(),
  security_notes: z.array(z.string()),
  owasp_mapping: z.nativeEnum(OWASPCategory).optional(),
  related_cwe: z.array(z.string()).optional(),
});

export type SecurePattern = z.infer<typeof SecurePatternSchema>;

/**
 * Compliance standards
 */
export enum ComplianceStandard {
  PCI_DSS = "PCI-DSS",
  GDPR = "GDPR",
  ISO27001 = "ISO27001",
  HIPAA = "HIPAA",
  SOC2 = "SOC2",
}

/**
 * Security requirement
 */
export const SecurityRequirementSchema = z.object({
  id: z.string(),
  category: z.string(),
  requirement: z.string(),
  rationale: z.string(),
  compliance_mapping: z.array(z.nativeEnum(ComplianceStandard)).optional(),
  implementation_guidance: z.string(),
  verification_method: z.string(),
});

export type SecurityRequirement = z.infer<typeof SecurityRequirementSchema>;
