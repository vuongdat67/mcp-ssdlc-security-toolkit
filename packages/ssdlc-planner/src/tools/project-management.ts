/**
 * Project Manager Tools
 * 
 * Tools for sprint planning and project management.
 */

import { createLogger } from "@mcp-ssdlc/core";
import { ToolMap } from "../types.js";
import { pmCreateSprintPlan } from "./pm/create-sprint-plan.js";

const logger = createLogger("PM-Tools");

export function registerProjectManagementTools(tools: ToolMap): void {
  tools.set("pm_create_sprint_plan", pmCreateSprintPlan);

  logger.info("Registered 1 Project Manager tool");
}

