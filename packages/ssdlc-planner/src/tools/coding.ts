/**
 * Coding Support Tools
 * 
 * Tools to assist developers with secure coding practices.
 */

import { createLogger } from "@mcp-ssdlc/core";
import { ToolMap } from "../types.js";
import { generateSecureCode } from "./coding/generate-secure-code.js";
import { reviewFile } from "./coding/review-file.js";
import { suggestFix } from "./coding/suggest-fix.js";

const logger = createLogger("Coding-Tools");

export function registerCodingTools(tools: ToolMap): void {
  // Generate secure code from requirements
  tools.set("generate_secure_code", async (input: unknown) => {
    logger.info("Generating secure code implementation");
    return generateSecureCode(input as any);
  });

  // Review an entire file
  tools.set("review_file", async (input: unknown) => {
    logger.info("Reviewing file for security issues");
    return reviewFile(input as any);
  });

  // Suggest fix for a vulnerability
  tools.set("suggest_fix", async (input: unknown) => {
    logger.info("Generating fix suggestion");
    return suggestFix(input as any);
  });

  logger.info("Registered 3 Coding Support tools");
}
