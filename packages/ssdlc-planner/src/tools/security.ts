/**
 * Security Engineer Tools
 * 
 * Tools for threat modeling and security review.
 */

import { createLogger } from "@mcp-ssdlc/core";
import { securityReviewCode } from "./security/review-code.js";
import { securityReviewCodeTool } from "./security/security-review-tool.js";
import { threatModelArchitecture } from "./security/threat-model.js";

const logger = createLogger("Security-Tools");

export function registerSecurityTools(tools: Map<string, CallableFunction>): void {
  // Phase 10: STRIDE Threat Modeling (SSDLC Planning)
  tools.set("security_threat_model", async (input: unknown) => {
    logger.info("Performing STRIDE threat modeling");
    return threatModelArchitecture(input as any);
  });

  // Phase 8: Security Code Review (Production-grade SAST)
  tools.set("security_review_code", async (input: unknown) => {
    logger.info("Reviewing code with security-kb intelligence");
    return securityReviewCodeTool.handler(input as any);
  });

  logger.info("Registered 2 Security Engineer tools");
}
