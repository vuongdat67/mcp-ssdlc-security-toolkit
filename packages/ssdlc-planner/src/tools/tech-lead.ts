/**
 * Tech Lead Tools
 * 
 * Tools for architecture design and pseudocode generation.
 */

import { createLogger } from "@mcp-ssdlc/core";
import { designSystemArchitecture } from "./tech-lead/design-architecture.js";

const logger = createLogger("TechLead-Tools");

export function registerTechLeadTools(tools: Map<string, CallableFunction>): void {
  // Phase 9: System architecture design
  tools.set("techlead_design_architecture", async (input: unknown) => {
    logger.info("Tech Lead: Designing system architecture");
    return designSystemArchitecture(input as any);
  });

  logger.info("Registered Tech Lead tools (Phase 9)");
}

