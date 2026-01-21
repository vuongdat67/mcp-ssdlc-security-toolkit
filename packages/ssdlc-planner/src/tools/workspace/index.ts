/**
 * Workspace Diagnostic Tools Registration
 * 
 * Registers workspace analysis and environment diagnostic tools
 * for intelligent path resolution and build system detection.
 */

import { createLogger } from "@mcp-ssdlc/core";
import {
  workspaceSnapshot,
  environmentDiagnostics,
  validatePath,
  runDiagnosticPlaybook,
  WorkspaceSnapshotInputSchema,
  EnvironmentDiagnosticsInputSchema,
  ValidatePathInputSchema,
  RunDiagnosticPlaybookInputSchema,
} from "./workspace-diagnostics.js";

const logger = createLogger("workspace-diagnostics");

type CallableFunction = (input: unknown) => Promise<unknown>;

/**
 * Register all workspace diagnostic tools
 */
export function registerWorkspaceDiagnosticTools(tools: Map<string, CallableFunction>): void {
  // Workspace Snapshot Tool
  tools.set("workspace_snapshot", async (input: unknown) => {
    logger.info("Creating workspace snapshot...");
    
    try {
      const validatedInput = WorkspaceSnapshotInputSchema.parse(input || {});
      const result = await workspaceSnapshot(validatedInput);
      
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            snapshot: {
              root: result.root,
              os: result.os,
              timestamp: result.timestamp,
              stats: result.stats,
              buildSystem: result.buildSystem,
              environment: result.environment,
              structure: result.structure.slice(0, 50), // Limit for response size
            },
            message: `Workspace snapshot created: ${result.stats.totalFiles} files, ${result.stats.totalDirs} directories`,
          }, null, 2),
        }],
      };
    } catch (error) {
      logger.error("Workspace snapshot failed", error);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : String(error),
          }, null, 2),
        }],
      };
    }
  });

  // Environment Diagnostics Tool
  tools.set("environment_diagnostics", async (input: unknown) => {
    logger.info("Running environment diagnostics...");
    
    try {
      const validatedInput = EnvironmentDiagnosticsInputSchema.parse(input || {});
      const results = await environmentDiagnostics(validatedInput);
      
      const summary = {
        ok: results.filter(r => r.status === 'ok').length,
        warnings: results.filter(r => r.status === 'warning').length,
        errors: results.filter(r => r.status === 'error').length,
      };
      
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            summary,
            diagnostics: results,
            message: `Diagnostics complete: ${summary.ok} OK, ${summary.warnings} warnings, ${summary.errors} errors`,
          }, null, 2),
        }],
      };
    } catch (error) {
      logger.error("Environment diagnostics failed", error);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : String(error),
          }, null, 2),
        }],
      };
    }
  });

  // Validate Path Tool
  tools.set("validate_path", async (input: unknown) => {
    logger.info("Validating path...");
    
    try {
      const validatedInput = ValidatePathInputSchema.parse(input);
      const result = await validatePath(validatedInput);
      
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            validation: result,
            message: result.exists 
              ? `Path exists: ${result.type} at ${result.absolutePath}`
              : `Path not found: ${result.absolutePath}${result.suggestions?.length ? ` (${result.suggestions.length} suggestions)` : ''}`,
          }, null, 2),
        }],
      };
    } catch (error) {
      logger.error("Path validation failed", error);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : String(error),
          }, null, 2),
        }],
      };
    }
  });

  // Run Diagnostic Playbook Tool
  tools.set("run_diagnostic_playbook", async (input: unknown) => {
    logger.info("Running diagnostic playbook...");
    
    try {
      const validatedInput = RunDiagnosticPlaybookInputSchema.parse(input);
      const result = await runDiagnosticPlaybook(validatedInput);
      
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            playbook: result.playbook,
            results: result.results,
            suggestedCommands: result.commands,
            message: `Playbook '${result.playbook}' completed with ${result.results.length} checks`,
          }, null, 2),
        }],
      };
    } catch (error) {
      logger.error("Diagnostic playbook failed", error);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : String(error),
          }, null, 2),
        }],
      };
    }
  });

  logger.info("Registered 4 workspace diagnostic tools");
}

export default registerWorkspaceDiagnosticTools;
