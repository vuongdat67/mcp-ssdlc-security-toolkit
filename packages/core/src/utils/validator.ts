/**
 * Validation utilities using Zod
 */

import { z, ZodError } from "zod";
import { Result } from "../types/common.js";

/**
 * Validate data against a Zod schema
 */
export function validate<T>(
  schema: z.ZodSchema<T>,
  data: unknown
): Result<T, ZodError> {
  try {
    const validated = schema.parse(data);
    return { ok: true, value: validated };
  } catch (error) {
    if (error instanceof ZodError) {
      return { ok: false, error };
    }
    throw error;
  }
}

/**
 * Validate data and throw on error
 */
export function validateOrThrow<T>(
  schema: z.ZodSchema<T>,
  data: unknown
): T {
  return schema.parse(data);
}

/**
 * Format Zod validation errors for user display
 */
export function formatValidationErrors(error: ZodError): string {
  return error.errors
    .map((err) => {
      const path = err.path.join(".");
      return `  - ${path}: ${err.message}`;
    })
    .join("\n");
}

/**
 * Sanitize file path to prevent path traversal attacks
 */
export function sanitizeFilePath(path: string): Result<string, Error> {
  // Check for path traversal patterns
  if (path.includes("..") || path.includes("~")) {
    return {
      ok: false,
      error: new Error("Path traversal detected in file path"),
    };
  }

  // Check for absolute paths (should use relative paths within project)
  if (path.startsWith("/") || /^[A-Za-z]:/.test(path)) {
    return {
      ok: false,
      error: new Error("Absolute paths not allowed"),
    };
  }

  return { ok: true, value: path };
}

/**
 * Validate project name (alphanumeric, hyphens, underscores only)
 */
export function validateProjectName(name: string): Result<string, Error> {
  const regex = /^[a-zA-Z0-9_-]+$/;
  if (!regex.test(name)) {
    return {
      ok: false,
      error: new Error(
        "Project name must contain only alphanumeric characters, hyphens, and underscores"
      ),
    };
  }

  if (name.length < 3 || name.length > 100) {
    return {
      ok: false,
      error: new Error("Project name must be between 3 and 100 characters"),
    };
  }

  return { ok: true, value: name };
}
