/**
 * Workspace Diagnostic Tools
 * 
 * Provides intelligent workspace analysis and environment diagnostics
 * to help AI agents understand project structure, detect issues, and
 * provide accurate path/environment debugging.
 * 
 * Features:
 * - Workspace snapshot with .gitignore awareness
 * - Environment diagnostics (Node, pnpm, OS)
 * - Path validation and resolution
 * - Build system detection
 * - Diagnostic command playbooks
 */

import { z } from 'zod';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';

// ============================================================================
// Types
// ============================================================================

export interface WorkspaceSnapshot {
  root: string;
  os: 'windows' | 'linux' | 'darwin';
  timestamp: string;
  structure: FileNode[];
  stats: {
    totalFiles: number;
    totalDirs: number;
    ignoredPatterns: string[];
  };
  buildSystem?: BuildSystemInfo;
  environment: EnvironmentInfo;
}

export interface FileNode {
  name: string;
  type: 'file' | 'directory';
  path: string;
  size?: number;
  children?: FileNode[];
}

export interface BuildSystemInfo {
  type: 'node' | 'cmake' | 'cargo' | 'python' | 'dotnet' | 'unknown';
  configFiles: string[];
  packageManager?: string;
  buildCommands?: string[];
}

export interface EnvironmentInfo {
  nodeVersion?: string;
  npmVersion?: string;
  pnpmVersion?: string;
  pythonVersion?: string;
  gitVersion?: string;
  shell: string;
  path: string[];
  cwd: string;
}

export interface DiagnosticResult {
  category: string;
  status: 'ok' | 'warning' | 'error';
  message: string;
  details?: Record<string, unknown>;
  suggestion?: string;
}

export interface PathValidation {
  path: string;
  exists: boolean;
  type: 'file' | 'directory' | 'none';
  absolutePath: string;
  relativePath: string;
  accessible: boolean;
  suggestions?: string[];
}

// ============================================================================
// Input Schemas
// ============================================================================

export const WorkspaceSnapshotInputSchema = z.object({
  rootPath: z.string().optional().describe('Root path to analyze (defaults to cwd)'),
  maxDepth: z.number().optional().default(5).describe('Maximum directory depth'),
  includeHidden: z.boolean().optional().default(false).describe('Include hidden files'),
  respectGitignore: z.boolean().optional().default(true).describe('Respect .gitignore rules'),
});

export const EnvironmentDiagnosticsInputSchema = z.object({
  categories: z.array(z.enum(['node', 'python', 'git', 'build', 'path', 'all']))
    .optional()
    .default(['all'])
    .describe('Categories to diagnose'),
});

export const ValidatePathInputSchema = z.object({
  targetPath: z.string().describe('Path to validate'),
  basePath: z.string().optional().describe('Base path for relative resolution'),
  findSimilar: z.boolean().optional().default(true).describe('Find similar paths if not found'),
});

export const RunDiagnosticPlaybookInputSchema = z.object({
  playbook: z.enum(['node-setup', 'build-check', 'path-debug', 'env-verify'])
    .describe('Diagnostic playbook to run'),
  workspacePath: z.string().optional().describe('Workspace path'),
});

// ============================================================================
// Utility Functions
// ============================================================================

function getOS(): 'windows' | 'linux' | 'darwin' {
  const platform = os.platform();
  if (platform === 'win32') return 'windows';
  if (platform === 'darwin') return 'darwin';
  return 'linux';
}

function parseGitignore(gitignorePath: string): string[] {
  if (!fs.existsSync(gitignorePath)) return [];
  
  const content = fs.readFileSync(gitignorePath, 'utf-8');
  return content
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
}

function shouldIgnore(filePath: string, patterns: string[]): boolean {
  const fileName = path.basename(filePath);
  
  for (const pattern of patterns) {
    // Simple pattern matching
    if (pattern === fileName) return true;
    if (pattern.endsWith('/') && fileName === pattern.slice(0, -1)) return true;
    if (pattern.startsWith('*') && fileName.endsWith(pattern.slice(1))) return true;
    if (pattern.endsWith('*') && fileName.startsWith(pattern.slice(0, -1))) return true;
    if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      if (regex.test(fileName)) return true;
    }
  }
  
  return false;
}

// Inline exec helpers with hardcoded commands - Semgrep safe (no function parameters)
function getNodeVersion(): string | null {
  try { return execSync('node --version', { encoding: 'utf-8', timeout: 5000 }).trim(); } catch { return null; }
}
function getNpmVersion(): string | null {
  try { return execSync('npm --version', { encoding: 'utf-8', timeout: 5000 }).trim(); } catch { return null; }
}
function getPnpmVersion(): string | null {
  try { return execSync('pnpm --version', { encoding: 'utf-8', timeout: 5000 }).trim(); } catch { return null; }
}
function getPythonVersion(): string | null {
  try { return execSync('python --version', { encoding: 'utf-8', timeout: 5000 }).trim(); } catch { return null; }
}
function getPython3Version(): string | null {
  try { return execSync('python3 --version', { encoding: 'utf-8', timeout: 5000 }).trim(); } catch { return null; }
}
function getGitVersion(): string | null {
  try { return execSync('git --version', { encoding: 'utf-8', timeout: 5000 }).trim(); } catch { return null; }
}
function getGitUserName(): string | null {
  try { return execSync('git config user.name', { encoding: 'utf-8', timeout: 5000 }).trim(); } catch { return null; }
}
function getGitUserEmail(): string | null {
  try { return execSync('git config user.email', { encoding: 'utf-8', timeout: 5000 }).trim(); } catch { return null; }
}
function getCorepackVersion(): string | null {
  try { return execSync('corepack --version', { encoding: 'utf-8', timeout: 5000 }).trim(); } catch { return null; }
}

function findSimilarPaths(targetPath: string, basePath: string): string[] {
  const suggestions: string[] = [];
  const targetName = path.basename(targetPath);
  const targetDir = path.dirname(targetPath);
  
  // Check if directory exists
  const searchDir = path.isAbsolute(targetDir) ? targetDir : path.join(basePath, targetDir);
  
  if (fs.existsSync(searchDir)) {
    try {
      const files = fs.readdirSync(searchDir);
      const similar = files.filter(f => {
        const lowerF = f.toLowerCase();
        const lowerTarget = targetName.toLowerCase();
        return lowerF.includes(lowerTarget) || lowerTarget.includes(lowerF) ||
               levenshteinDistance(lowerF, lowerTarget) <= 3;
      });
      suggestions.push(...similar.map(f => path.join(searchDir, f)));
    } catch {
      // Directory not accessible
    }
  }
  
  return suggestions.slice(0, 5);
}

function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  
  return matrix[b.length][a.length];
}

// ============================================================================
// Tool Handlers
// ============================================================================

export async function workspaceSnapshot(
  input: z.infer<typeof WorkspaceSnapshotInputSchema>
): Promise<WorkspaceSnapshot> {
  const rootPath = input.rootPath || process.cwd();
  const maxDepth = input.maxDepth || 5;
  const respectGitignore = input.respectGitignore !== false;
  const includeHidden = input.includeHidden || false;
  
  // Parse gitignore
  const gitignorePath = path.join(rootPath, '.gitignore');
  const ignorePatterns = respectGitignore ? parseGitignore(gitignorePath) : [];
  
  // Default ignores
  const defaultIgnores = ['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv'];
  const allIgnores = [...new Set([...ignorePatterns, ...defaultIgnores])];
  
  let totalFiles = 0;
  let totalDirs = 0;
  
  function scanDirectory(dirPath: string, depth: number): FileNode[] {
    if (depth > maxDepth) return [];
    
    const nodes: FileNode[] = [];
    
    try {
      const entries = fs.readdirSync(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        // Skip hidden files unless requested
        if (!includeHidden && entry.name.startsWith('.')) continue;
        
        // Check ignore patterns
        if (shouldIgnore(entry.name, allIgnores)) continue;
        
        const fullPath = path.join(dirPath, entry.name);
        const relativePath = path.relative(rootPath, fullPath);
        
        if (entry.isDirectory()) {
          totalDirs++;
          nodes.push({
            name: entry.name,
            type: 'directory',
            path: relativePath,
            children: scanDirectory(fullPath, depth + 1),
          });
        } else if (entry.isFile()) {
          totalFiles++;
          try {
            const stats = fs.statSync(fullPath);
            nodes.push({
              name: entry.name,
              type: 'file',
              path: relativePath,
              size: stats.size,
            });
          } catch {
            nodes.push({
              name: entry.name,
              type: 'file',
              path: relativePath,
            });
          }
        }
      }
    } catch (error) {
      // Directory not accessible
    }
    
    return nodes.sort((a, b) => {
      if (a.type !== b.type) return a.type === 'directory' ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
  }
  
  // Detect build system
  function detectBuildSystem(): BuildSystemInfo {
    const configFiles: string[] = [];
    
    if (fs.existsSync(path.join(rootPath, 'package.json'))) {
      configFiles.push('package.json');
      const pkgJson = JSON.parse(fs.readFileSync(path.join(rootPath, 'package.json'), 'utf-8'));
      const pm = fs.existsSync(path.join(rootPath, 'pnpm-lock.yaml')) ? 'pnpm' :
                 fs.existsSync(path.join(rootPath, 'yarn.lock')) ? 'yarn' : 'npm';
      return {
        type: 'node',
        configFiles,
        packageManager: pm,
        buildCommands: Object.keys(pkgJson.scripts || {}),
      };
    }
    
    if (fs.existsSync(path.join(rootPath, 'CMakeLists.txt'))) {
      configFiles.push('CMakeLists.txt');
      return { type: 'cmake', configFiles };
    }
    
    if (fs.existsSync(path.join(rootPath, 'Cargo.toml'))) {
      configFiles.push('Cargo.toml');
      return { type: 'cargo', configFiles };
    }
    
    if (fs.existsSync(path.join(rootPath, 'pyproject.toml')) || 
        fs.existsSync(path.join(rootPath, 'setup.py'))) {
      if (fs.existsSync(path.join(rootPath, 'pyproject.toml'))) configFiles.push('pyproject.toml');
      if (fs.existsSync(path.join(rootPath, 'setup.py'))) configFiles.push('setup.py');
      return { type: 'python', configFiles };
    }
    
    const csprojFiles = fs.readdirSync(rootPath).filter(f => f.endsWith('.csproj'));
    if (csprojFiles.length > 0) {
      return { type: 'dotnet', configFiles: csprojFiles };
    }
    
    return { type: 'unknown', configFiles: [] };
  }
  
  // Get environment info
  function getEnvironmentInfo(): EnvironmentInfo {
    const osType = getOS();
    
    return {
      nodeVersion: getNodeVersion() || undefined,
      npmVersion: getNpmVersion() || undefined,
      pnpmVersion: getPnpmVersion() || undefined,
      pythonVersion: getPythonVersion() || getPython3Version() || undefined,
      gitVersion: getGitVersion() || undefined,
      shell: process.env.SHELL || process.env.COMSPEC || 'unknown',
      path: (process.env.PATH || '').split(osType === 'windows' ? ';' : ':').slice(0, 10),
      cwd: process.cwd(),
    };
  }
  
  const structure = scanDirectory(rootPath, 0);
  
  return {
    root: rootPath,
    os: getOS(),
    timestamp: new Date().toISOString(),
    structure,
    stats: {
      totalFiles,
      totalDirs,
      ignoredPatterns: allIgnores,
    },
    buildSystem: detectBuildSystem(),
    environment: getEnvironmentInfo(),
  };
}

export async function environmentDiagnostics(
  input: z.infer<typeof EnvironmentDiagnosticsInputSchema>
): Promise<DiagnosticResult[]> {
  const categories = input.categories.includes('all') 
    ? ['node', 'python', 'git', 'build', 'path'] 
    : input.categories;
  
  const results: DiagnosticResult[] = [];
  const osType = getOS();
  
  // Node diagnostics
  if (categories.includes('node')) {
    const nodeVersion = getNodeVersion();
    if (nodeVersion) {
      const major = parseInt(nodeVersion.replace('v', '').split('.')[0]);
      results.push({
        category: 'node',
        status: major >= 20 ? 'ok' : major >= 18 ? 'warning' : 'error',
        message: `Node.js ${nodeVersion} detected`,
        details: { version: nodeVersion, major },
        suggestion: major < 20 ? 'Consider upgrading to Node.js 20 LTS or later' : undefined,
      });
    } else {
      results.push({
        category: 'node',
        status: 'error',
        message: 'Node.js not found in PATH',
        suggestion: 'Install Node.js from https://nodejs.org/',
      });
    }
    
    // Check pnpm
    const pnpmVersion = getPnpmVersion();
    if (pnpmVersion) {
      results.push({
        category: 'node',
        status: 'ok',
        message: `pnpm ${pnpmVersion} detected`,
      });
    }
  }
  
  // Git diagnostics
  if (categories.includes('git')) {
    const gitVersion = getGitVersion();
    if (gitVersion) {
      results.push({
        category: 'git',
        status: 'ok',
        message: gitVersion,
      });
      
      // Check git config
      const userName = getGitUserName();
      const userEmail = getGitUserEmail();
      
      if (!userName || !userEmail) {
        results.push({
          category: 'git',
          status: 'warning',
          message: 'Git user not configured',
          suggestion: 'Run: git config --global user.name "Your Name" && git config --global user.email "your@email.com"',
        });
      }
    } else {
      results.push({
        category: 'git',
        status: 'error',
        message: 'Git not found in PATH',
        suggestion: 'Install Git from https://git-scm.com/',
      });
    }
  }
  
  // Python diagnostics
  if (categories.includes('python')) {
    const pythonVersion = getPythonVersion() || getPython3Version();
    if (pythonVersion) {
      results.push({
        category: 'python',
        status: 'ok',
        message: pythonVersion,
      });
    }
  }
  
  // PATH diagnostics
  if (categories.includes('path')) {
    const pathVar = process.env.PATH || '';
    const separator = osType === 'windows' ? ';' : ':';
    const pathEntries = pathVar.split(separator);
    
    // Check for common issues
    const duplicates = pathEntries.filter((item, index) => pathEntries.indexOf(item) !== index);
    if (duplicates.length > 0) {
      results.push({
        category: 'path',
        status: 'warning',
        message: `${duplicates.length} duplicate entries in PATH`,
        details: { duplicates: [...new Set(duplicates)] },
      });
    }
    
    // Check for non-existent paths
    const nonExistent = pathEntries.filter(p => p && !fs.existsSync(p)).slice(0, 5);
    if (nonExistent.length > 0) {
      results.push({
        category: 'path',
        status: 'warning',
        message: `${nonExistent.length} non-existent directories in PATH`,
        details: { paths: nonExistent },
      });
    }
    
    results.push({
      category: 'path',
      status: 'ok',
      message: `PATH contains ${pathEntries.length} entries`,
      details: { count: pathEntries.length },
    });
  }
  
  // Build diagnostics
  if (categories.includes('build')) {
    const cwd = process.cwd();
    
    // Check package.json
    if (fs.existsSync(path.join(cwd, 'package.json'))) {
      results.push({
        category: 'build',
        status: 'ok',
        message: 'package.json found',
      });
      
      // Check node_modules
      if (!fs.existsSync(path.join(cwd, 'node_modules'))) {
        results.push({
          category: 'build',
          status: 'warning',
          message: 'node_modules not found',
          suggestion: 'Run: pnpm install',
        });
      }
      
      // Check lock file
      const hasLock = fs.existsSync(path.join(cwd, 'pnpm-lock.yaml')) ||
                      fs.existsSync(path.join(cwd, 'package-lock.json')) ||
                      fs.existsSync(path.join(cwd, 'yarn.lock'));
      if (!hasLock) {
        results.push({
          category: 'build',
          status: 'warning',
          message: 'No lock file found',
          suggestion: 'Run package manager install to generate lock file',
        });
      }
    }
  }
  
  return results;
}

export async function validatePath(
  input: z.infer<typeof ValidatePathInputSchema>
): Promise<PathValidation> {
  const basePath = input.basePath || process.cwd();
  const targetPath = input.targetPath;
  
  // Resolve absolute path
  const absolutePath = path.isAbsolute(targetPath) 
    ? targetPath 
    : path.resolve(basePath, targetPath);
  
  const relativePath = path.relative(basePath, absolutePath);
  
  let exists = false;
  let type: 'file' | 'directory' | 'none' = 'none';
  let accessible = false;
  
  try {
    const stats = fs.statSync(absolutePath);
    exists = true;
    type = stats.isDirectory() ? 'directory' : 'file';
    accessible = true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      exists = false;
    } else if ((error as NodeJS.ErrnoException).code === 'EACCES') {
      exists = true;
      accessible = false;
    }
  }
  
  const result: PathValidation = {
    path: targetPath,
    exists,
    type,
    absolutePath,
    relativePath,
    accessible,
  };
  
  // Find similar paths if requested and path doesn't exist
  if (!exists && input.findSimilar) {
    result.suggestions = findSimilarPaths(targetPath, basePath);
  }
  
  return result;
}

export async function runDiagnosticPlaybook(
  input: z.infer<typeof RunDiagnosticPlaybookInputSchema>
): Promise<{ playbook: string; results: DiagnosticResult[]; commands: string[] }> {
  const osType = getOS();
  const results: DiagnosticResult[] = [];
  const commands: string[] = [];
  const workspacePath = input.workspacePath || process.cwd();
  
  switch (input.playbook) {
    case 'node-setup':
      // Node.js setup verification
      commands.push(
        'node --version',
        'npm --version',
        'pnpm --version',
        osType === 'windows' ? 'where node' : 'which node',
      );
      
      const nodeV = getNodeVersion();
      results.push({
        category: 'node-setup',
        status: nodeV ? 'ok' : 'error',
        message: nodeV ? `Node.js: ${nodeV}` : 'Node.js not found',
        suggestion: nodeV ? undefined : 'Install from https://nodejs.org/',
      });
      
      // Check corepack
      const corepack = getCorepackVersion();
      if (!corepack) {
        results.push({
          category: 'node-setup',
          status: 'warning',
          message: 'Corepack not enabled',
          suggestion: 'Run: corepack enable',
        });
        commands.push('corepack enable');
      }
      break;
      
    case 'build-check':
      commands.push(
        'pnpm install --frozen-lockfile',
        'pnpm build',
        'pnpm test',
      );
      
      // Check if build outputs exist
      const distExists = fs.existsSync(path.join(workspacePath, 'dist')) ||
                         fs.existsSync(path.join(workspacePath, 'build'));
      results.push({
        category: 'build-check',
        status: distExists ? 'ok' : 'warning',
        message: distExists ? 'Build output directory exists' : 'No build output found',
        suggestion: distExists ? undefined : 'Run: pnpm build',
      });
      break;
      
    case 'path-debug':
      const pathVar = process.env.PATH || '';
      const separator = osType === 'windows' ? ';' : ':';
      
      if (osType === 'windows') {
        commands.push(
          '$env:PATH -split ";" | ForEach-Object { if (Test-Path $_) { $_ } else { "[MISSING] $_" } }',
          'Get-Command node -ErrorAction SilentlyContinue | Select-Object Source',
        );
      } else {
        commands.push(
          'echo $PATH | tr ":" "\\n" | while read p; do [ -d "$p" ] && echo "$p" || echo "[MISSING] $p"; done',
          'which node npm pnpm 2>/dev/null',
        );
      }
      
      results.push({
        category: 'path-debug',
        status: 'ok',
        message: `PATH has ${pathVar.split(separator).length} entries`,
        details: { 
          first5: pathVar.split(separator).slice(0, 5),
        },
      });
      break;
      
    case 'env-verify':
      commands.push(
        osType === 'windows' ? 'Get-ChildItem Env:' : 'env',
        'git config --list --show-origin',
      );
      
      const requiredEnvVars = ['PATH', 'HOME', 'USER'];
      if (osType === 'windows') requiredEnvVars.push('USERPROFILE', 'APPDATA');
      
      for (const envVar of requiredEnvVars) {
        const value = process.env[envVar];
        results.push({
          category: 'env-verify',
          status: value ? 'ok' : 'warning',
          message: value ? `${envVar} is set` : `${envVar} is not set`,
        });
      }
      break;
  }
  
  return {
    playbook: input.playbook,
    results,
    commands,
  };
}

// ============================================================================
// Tool Definitions for MCP Registration
// ============================================================================

export const workspaceDiagnosticTools = [
  {
    name: 'workspace_snapshot',
    description: 'Creates a complete snapshot of workspace structure, build system, and environment. Respects .gitignore and provides context for AI to understand the project.',
    inputSchema: WorkspaceSnapshotInputSchema,
    handler: workspaceSnapshot,
  },
  {
    name: 'environment_diagnostics', 
    description: 'Runs diagnostics on development environment: Node.js, Git, Python, PATH, and build setup. Returns issues with suggestions.',
    inputSchema: EnvironmentDiagnosticsInputSchema,
    handler: environmentDiagnostics,
  },
  {
    name: 'validate_path',
    description: 'Validates a file or directory path. Checks existence, accessibility, and suggests similar paths if not found.',
    inputSchema: ValidatePathInputSchema,
    handler: validatePath,
  },
  {
    name: 'run_diagnostic_playbook',
    description: 'Runs a predefined diagnostic playbook for common scenarios: node-setup, build-check, path-debug, env-verify.',
    inputSchema: RunDiagnosticPlaybookInputSchema,
    handler: runDiagnosticPlaybook,
  },
];

export default workspaceDiagnosticTools;
