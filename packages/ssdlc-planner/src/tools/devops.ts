/**
 * DevOps Engineer Tools
 * 
 * Tools for CI/CD design and infrastructure planning.
 */

import { createLogger } from "@mcp-ssdlc/core";
import { ToolMap } from "../types.js";
import { devopsDesignCICD } from "./devops/design-cicd.js";

const logger = createLogger("DevOps-Tools");

export function registerDevOpsTools(tools: ToolMap): void {
  tools.set("devops_design_cicd", devopsDesignCICD);

  logger.info("Registered 1 DevOps Engineer tool");
}

