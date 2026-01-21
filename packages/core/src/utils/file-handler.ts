/**
 * File handling utilities
 */

import fs from "fs/promises";
import path from "path";
import { Result } from "../types/common.js";

/**
 * Read file content safely
 */
export async function readFile(filePath: string): Promise<Result<string, Error>> {
  try {
    const content = await fs.readFile(filePath, "utf-8");
    return { ok: true, value: content };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error : new Error(String(error)),
    };
  }
}

/**
 * Write file content safely
 */
export async function writeFile(
  filePath: string,
  content: string
): Promise<Result<void, Error>> {
  try {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content, "utf-8");
    return { ok: true, value: undefined };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error : new Error(String(error)),
    };
  }
}

/**
 * Check if file exists
 */
export async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Ensure directory exists
 */
export async function ensureDir(dirPath: string): Promise<Result<void, Error>> {
  try {
    await fs.mkdir(dirPath, { recursive: true });
    return { ok: true, value: undefined };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error : new Error(String(error)),
    };
  }
}
