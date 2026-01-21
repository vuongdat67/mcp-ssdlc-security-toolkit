/**
 * Template rendering engine using Handlebars
 */

import Handlebars from "handlebars";
import { readFile } from "@mcp-ssdlc/core";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Cache compiled templates
const templateCache = new Map<string, HandlebarsTemplateDelegate>();

/**
 * Register Handlebars helpers
 */
function registerHelpers(): void {
  // Format date helper
  Handlebars.registerHelper("formatDate", (date: Date) => {
    return date.toISOString().split("T")[0];
  });

  // Uppercase helper
  Handlebars.registerHelper("uppercase", (str: string) => {
    return str.toUpperCase();
  });

  // Join array helper
  Handlebars.registerHelper("join", (arr: string[], separator: string) => {
    return arr.join(separator || ", ");
  });

  // Conditional helper for priority colors
  Handlebars.registerHelper("priorityBadge", (priority: string) => {
    const badges: Record<string, string> = {
      P0: "🔴 Critical",
      P1: "🟠 High",
      P2: "🟡 Medium",
      P3: "🟢 Low",
    };
    return badges[priority] || priority;
  });
}

// Register helpers on module load
registerHelpers();

/**
 * Get template path from template name
 */
function getTemplatePath(templateName: string): string {
  // Templates are in packages/ssdlc-planner/templates/
  const templatesDir = path.join(__dirname, "../../templates");
  return path.join(templatesDir, templateName);
}

/**
 * Render a Handlebars template
 */
export async function renderTemplate(
  templateName: string,
  data: object
): Promise<string> {
  // Check cache first
  let template = templateCache.get(templateName);

  if (!template) {
    // Load template file
    const templatePath = getTemplatePath(templateName);
    const result = await readFile(templatePath);

    if (!result.ok) {
      // Template doesn't exist, create a simple fallback
      return createFallbackOutput(data);
    }

    // Compile template
    template = Handlebars.compile(result.value);
    templateCache.set(templateName, template);
  }

  // Render template with data
  return template(data);
}

/**
 * Create fallback JSON output when template is missing
 */
function createFallbackOutput(data: object): string {
  return "```json\n" + JSON.stringify(data, null, 2) + "\n```";
}

/**
 * Clear template cache (useful for development)
 */
export function clearTemplateCache(): void {
  templateCache.clear();
}
