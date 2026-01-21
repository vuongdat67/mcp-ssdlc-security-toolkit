/**
 * Shared types for MCP SSDLC Planner
 */

/**
 * Tool handler function type
 */
export type ToolHandler = (input: unknown) => Promise<unknown>;

/**
 * Tool registration map type
 */
export type ToolMap = Map<string, ToolHandler>;
