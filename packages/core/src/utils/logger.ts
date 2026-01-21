/**
 * Logging utility with colored output
 */

import chalk from "chalk";

export enum LogLevel {
  DEBUG = "DEBUG",
  INFO = "INFO",
  WARN = "WARN",
  ERROR = "ERROR",
}

export class Logger {
  private context: string;

  constructor(context: string) {
    this.context = context;
  }

  private formatMessage(level: LogLevel, message: string, data?: unknown): string {
    const timestamp = new Date().toISOString();
    const prefix = `[${timestamp}] [${level}] [${this.context}]`;
    
    let output = `${prefix} ${message}`;
    if (data !== undefined) {
      output += `\n${JSON.stringify(data, null, 2)}`;
    }
    
    return output;
  }

  debug(message: string, data?: unknown): void {
    const formatted = this.formatMessage(LogLevel.DEBUG, message, data);
    // MCP stdio: ALL logs MUST go to stderr
    process.stderr.write(chalk.gray(formatted) + '\n');
  }

  info(message: string, data?: unknown): void {
    const formatted = this.formatMessage(LogLevel.INFO, message, data);
    // MCP stdio: ALL logs MUST go to stderr
    process.stderr.write(chalk.blue(formatted) + '\n');
  }

  warn(message: string, data?: unknown): void {
    const formatted = this.formatMessage(LogLevel.WARN, message, data);
    // MCP stdio: ALL logs MUST go to stderr
    process.stderr.write(chalk.yellow(formatted) + '\n');
  }

  error(message: string, error?: unknown): void {
    const formatted = this.formatMessage(LogLevel.ERROR, message, error);
    // MCP stdio: ALL logs MUST go to stderr
    process.stderr.write(chalk.red(formatted) + '\n');
  }

  success(message: string, data?: unknown): void {
    const timestamp = new Date().toISOString();
    const prefix = `[${timestamp}] [SUCCESS] [${this.context}]`;
    let output = `${prefix} ${message}`;
    if (data !== undefined) {
      output += `\n${JSON.stringify(data, null, 2)}`;
    }
    // MCP stdio: ALL logs MUST go to stderr
    process.stderr.write(chalk.green(output) + '\n');
  }
}

/**
 * Create a logger instance for a specific context
 */
export function createLogger(context: string): Logger {
  return new Logger(context);
}
