/**
 * Template-related types
 */

import { z } from "zod";

/**
 * Template metadata
 */
export const TemplateMetadataSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  category: z.enum([
    "requirements",
    "architecture",
    "security",
    "pseudocode",
    "testing",
    "planning",
  ]),
  author: z.string().optional(),
  version: z.string(),
  variables: z.array(z.string()),
  examples: z.array(z.string()).optional(),
});

export type TemplateMetadata = z.infer<typeof TemplateMetadataSchema>;

/**
 * Template rendering options
 */
export interface TemplateOptions {
  format?: "markdown" | "json" | "yaml";
  helpers?: Record<string, (...args: unknown[]) => unknown>;
  partials?: Record<string, string>;
}
