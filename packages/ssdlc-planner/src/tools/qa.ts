/**
 * QA Engineer Tools
 * 
 * Tools for test strategy and test case generation.
 */

import { createLogger } from "@mcp-ssdlc/core";
import { ToolMap } from "../types.js";
import { designTestStrategy } from "./qa/design-test-strategy.js";

const logger = createLogger("QA-Tools");

export function registerQATools(tools: ToolMap): void {
  // Phase 11: Security test strategy
  tools.set("qa_design_test_strategy", async (input: unknown) => {
    logger.info("QA: Designing security test strategy");
    return designTestStrategy(input as any);
  });

  logger.info("Registered QA tools (Phase 11)");
}
